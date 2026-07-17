#!/usr/bin/env python3
"""Combined DORA Article 24 assessment report generator.

Merges a ZAP JSON scan report with a filled-in manual-findings YAML/JSON
file into one unified DORA Article 24 Markdown or JSON report.  Never
contacts ZAP directly -- it operates purely on previously-produced
artifacts.

Two subcommands:
    init-template  -- emit a blank manual-findings YAML/JSON template
    generate       -- merge ZAP report + manual findings into a combined report
"""

from __future__ import annotations

import argparse
import datetime as dt
import getpass
import json
import os
import pathlib
import sys
from typing import Any

# ---------------------------------------------------------------------------
# Imports from zap_scan (pure/no-network helpers only)
# ---------------------------------------------------------------------------

from zap_scan import (
    _dedupe_findings,
    _map_dora_article,
    _is_third_party_finding,
    _third_party_risk_flags,
    _severity_counts,
    _format_url_list,
    RISK_ORDER,
    _render_findings_table,
    _render_detailed_findings,
)

# ---------------------------------------------------------------------------
# YAML support (soft dependency -- same status as in zap_scan.py)
# ---------------------------------------------------------------------------

try:
    import yaml  # type: ignore[import-untyped]
    _HAS_YAML = True
except ImportError:
    _HAS_YAML = False

# ---------------------------------------------------------------------------
# Checklist schema -- single source of truth for template, validation,
# coverage tracking, and rendering.
# ---------------------------------------------------------------------------

CHECKLIST_SCHEMA: list[dict[str, Any]] = [
    {
        "category": "authentication",
        "title": "Authentication Testing",
        "items": [
            {"id": "auth_weak_password_policy", "test": "Weak password policy — trivial passwords rejected on registration/change"},
            {"id": "auth_brute_force_lockout", "test": "Brute-force / rate limiting — lockout, delay, or CAPTCHA after N failed attempts"},
            {"id": "auth_reset_token_strength", "test": "Password reset token strength — long, random, single-use, time-limited"},
            {"id": "auth_reset_token_reuse", "test": "Password reset token reuse — reused link after use must fail"},
            {"id": "auth_session_fixation", "test": "Session fixation — session token changes on login/logout"},
            {"id": "auth_session_expiry", "test": "Session expiry — enforced idle/absolute timeout"},
            {"id": "auth_token_tampering", "test": "Token tampering (JWT or similar) — server validates signature on modified claims"},
            {"id": "auth_logout_invalidation", "test": "Logout invalidation — old session tokens rejected after logout"},
            {"id": "auth_mfa_bypass", "test": "Multi-factor auth bypass — MFA cannot be skipped via direct API call, back button, or race condition"},
        ],
    },
    {
        "category": "access_control",
        "title": "Access Control / IDOR",
        "items": [
            {"id": "ac_horizontal_privesc", "test": "Horizontal privilege escalation — User B cannot access/modify/delete User A's object by ID"},
            {"id": "ac_id_predictability", "test": "ID predictability — object IDs are non-sequential / non-enumerable"},
            {"id": "ac_vertical_privesc", "test": "Vertical privilege escalation — standard user cannot reach admin-only endpoints directly"},
            {"id": "ac_api_level_idor", "test": "API-level IDOR — restrictions enforced server-side, not just in the UI"},
            {"id": "ac_mass_assignment", "test": "Mass assignment — server rejects unexpected fields (role, permission flags, verified status) in update requests"},
        ],
    },
    {
        "category": "business_logic",
        "title": "Business Logic Testing",
        "items": [
            {"id": "bl_rate_quota_bypass", "test": "Rate/quota bypass — usage limits enforced server-side, not client-side only"},
            {"id": "bl_input_boundary_abuse", "test": "Input boundary abuse — negative/zero/oversized/malformed numeric values rejected"},
            {"id": "bl_workflow_step_skipping", "test": "Workflow step-skipping — later-stage endpoints reject calls that bypass required earlier steps"},
            {"id": "bl_duplicate_replay", "test": "Duplicate/replay submission — resubmission does not create duplicate records or inconsistent state"},
            {"id": "bl_race_conditions", "test": "Race conditions — concurrent requests against check-then-act logic cannot bypass the check"},
        ],
    },
    {
        "category": "transaction_payment",
        "title": "Transaction / Payment Logic",
        "items": [
            {"id": "tx_price_tampering", "test": "Price/amount tampering — client-supplied amount/quantity/price cannot be modified in transit"},
            {"id": "tx_negative_invalid_values", "test": "Negative/invalid values — negative quantities, mismatched currencies, decimal precision abuse rejected"},
            {"id": "tx_idempotency", "test": "Idempotency — replayed transaction confirmation does not cause double charge/credit"},
            {"id": "tx_discount_abuse", "test": "Discount/coupon logic abuse — stacking, reuse, or manipulation of promo codes prevented"},
        ],
    },
    {
        "category": "input_handling",
        "title": "Input Handling",
        "items": [
            {"id": "ih_file_upload", "test": "File upload — double extensions, MIME spoofing, oversized files, path traversal in filenames rejected"},
            {"id": "ih_error_verbosity", "test": "Error message verbosity — no stack traces, DB errors, or internal paths leaked in error responses"},
            {"id": "ih_open_redirect", "test": "Open redirect — redirect parameters restricted to allow-listed destinations"},
            {"id": "ih_cors_misconfig", "test": "CORS misconfiguration — Access-Control-Allow-Origin is not wildcard-with-credentials"},
        ],
    },
]


# ---------------------------------------------------------------------------
# Manual severity order (separate from ZAP's RISK_ORDER)
# ---------------------------------------------------------------------------

MANUAL_SEVERITY_ORDER: dict[str, int] = {
    "Critical": 0,
    "High": 1,
    "Medium": 2,
    "Low": 3,
}

COMBINED_SEVERITY_RANK: dict[str, int] = {
    "Critical": 0,
    "High": 1,
    "Medium": 2,
    "Low": 3,
    "Informational": 4,
}

_VALID_STATUSES = {"not_tested", "pass", "fail", "not_applicable"}
_VALID_SEVERITIES = {"Critical", "High", "Medium", "Low"}


# ---------------------------------------------------------------------------
# B2: Template generation
# ---------------------------------------------------------------------------

def build_manual_template(target: str = "") -> dict[str, Any]:
    """Build the nested dict structure for a blank manual-findings file.

    Walks ``CHECKLIST_SCHEMA`` and emits one entry per item, all defaulted
    to ``status="not_tested"``.  Pure function -- no I/O -- so it is
    directly testable and also reused by ``--format json`` for
    ``init-template``.
    """
    data: dict[str, Any] = {
        "meta": {
            "target": target,
            "tester": "",
            "test_date": "",
            "authorization_reference": "",
        },
    }
    for cat in CHECKLIST_SCHEMA:
        category_data: dict[str, Any] = {}
        for item in cat["items"]:
            category_data[item["id"]] = {
                "test": item["test"],
                "status": "not_tested",
                "severity": None,
                "evidence": "",
                "steps_to_reproduce": "",
            }
        data[cat["category"]] = category_data
    return data


def write_manual_template(
    path: pathlib.Path,
    target: str = "",
    fmt: str = "yaml",
) -> None:
    """Render ``build_manual_template()`` to *path* as YAML (default) or JSON.

    When writing YAML, a header comment block is prepended with usage
    instructions.
    """
    data = build_manual_template(target)

    if fmt == "json":
        path.write_text(
            json.dumps(data, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
    else:
        if not _HAS_YAML:
            sys.exit(
                "ERROR: PyYAML is required for YAML template output.\n"
                "Install it with:  pip install pyyaml"
            )
        header = (
            "# MANUAL PENTEST FINDINGS -- fill in each item below.\n"
            "# status: one of not_tested | pass | fail | not_applicable\n"
            "# severity: required if status is \"fail\" -- one of Critical | High | Medium | Low\n"
            "# Leave status as \"not_tested\" if you have not yet performed this test --\n"
            "# the combined report will flag any remaining not_tested items.\n\n"
        )
        yaml_body = yaml.dump(
            data,
            default_flow_style=False,
            allow_unicode=True,
            sort_keys=False,
        )
        path.write_text(header + yaml_body, encoding="utf-8")


# ---------------------------------------------------------------------------
# B3: Loading and validation
# ---------------------------------------------------------------------------

class ManualFindingsError(Exception):
    """Raised for structurally invalid manual-findings input."""


def _validate_manual_findings(data: dict[str, Any]) -> list[str]:
    """Return a list of validation problem strings (empty list = valid).

    Checks, walking ``CHECKLIST_SCHEMA`` as the source of truth:
      - top-level ``meta`` key present
      - every category in ``CHECKLIST_SCHEMA`` is present as a top-level key
      - every item id under each category is present
      - ``status`` is one of ``_VALID_STATUSES``
      - ``severity`` is one of ``_VALID_SEVERITIES`` when ``status == "fail"``
      - a lingering severity on a non-fail item is flagged (non-fatal warning)
    """
    problems: list[str] = []

    if "meta" not in data:
        problems.append("Missing top-level 'meta' key.")

    for cat in CHECKLIST_SCHEMA:
        cat_key = cat["category"]
        if cat_key not in data:
            problems.append(f"Missing category '{cat_key}'.")
            continue
        cat_data = data[cat_key]
        if not isinstance(cat_data, dict):
            problems.append(f"Category '{cat_key}' is not a mapping.")
            continue
        for item in cat["items"]:
            item_id = item["id"]
            if item_id not in cat_data:
                problems.append(f"Missing item '{item_id}' in category '{cat_key}'.")
                continue
            entry = cat_data[item_id]
            if not isinstance(entry, dict):
                problems.append(
                    f"Item '{item_id}' in '{cat_key}' is not a mapping."
                )
                continue

            status = entry.get("status", "")
            if status not in _VALID_STATUSES:
                problems.append(
                    f"Item '{item_id}': invalid status '{status}' "
                    f"(expected one of {sorted(_VALID_STATUSES)})."
                )

            severity = entry.get("severity")
            if status == "fail":
                if severity not in _VALID_SEVERITIES:
                    problems.append(
                        f"Item '{item_id}': status is 'fail' but severity "
                        f"is '{severity}' (expected one of {sorted(_VALID_SEVERITIES)})."
                    )
            else:
                if severity is not None and severity != "":
                    # Non-fatal: lingering severity on a non-fail item
                    problems.append(
                        f"Item '{item_id}': severity '{severity}' set but "
                        f"status is '{status}' (not 'fail') -- severity "
                        f"will be ignored (consider clearing it)."
                    )

    return problems


def load_manual_findings(path: pathlib.Path) -> dict[str, Any]:
    """Load and structurally validate a manual-findings YAML/JSON file.

    Accepts either extension; dispatches on suffix (``.yaml``/``.yml`` ->
    ``yaml.safe_load``, ``.json`` -> ``json.loads``).  Raises
    ``ManualFindingsError`` on structural problems rather than letting a
    ``KeyError``/``TypeError`` propagate from deep inside the renderer.
    """
    if not path.is_file():
        raise ManualFindingsError(f"File not found: {path}")

    raw = path.read_text(encoding="utf-8")
    suffix = path.suffix.lower()

    if suffix in (".yaml", ".yml"):
        if not _HAS_YAML:
            raise ManualFindingsError(
                "PyYAML is required to load YAML files. "
                "Install it with:  pip install pyyaml"
            )
        data = yaml.safe_load(raw)
    elif suffix == ".json":
        data = json.loads(raw)
    else:
        raise ManualFindingsError(
            f"Unsupported file extension '{suffix}'. "
            "Expected .yaml, .yml, or .json."
        )

    if not isinstance(data, dict):
        raise ManualFindingsError("Top-level structure must be a mapping.")

    problems = _validate_manual_findings(data)
    # Separate fatal from non-fatal problems
    fatal = [
        p for p in problems
        if "will be ignored" not in p
    ]
    warnings = [
        p for p in problems
        if "will be ignored" in p
    ]

    for w in warnings:
        print(f"WARNING: {w}", file=sys.stderr)

    if fatal:
        raise ManualFindingsError(
            "Manual findings file has structural errors:\n"
            + "\n".join(f"  - {p}" for p in fatal)
        )

    return data


# ---------------------------------------------------------------------------
# B4: ZAP report loading
# ---------------------------------------------------------------------------

def load_zap_report(path: pathlib.Path) -> dict[str, Any]:
    """Load a ``zap_scan.py`` JSON report (``--format json`` output).

    Prefers the ``deduped_findings`` key (added in zap_scan.py).  If
    absent (older report predating that change), recomputes it by calling
    ``zap_scan._dedupe_findings()`` on the raw ``alerts`` list and
    re-applying the DORA/third-party enrichment passes.
    """
    if not path.is_file():
        sys.exit(f"ERROR: ZAP report not found: {path}")

    raw = json.loads(path.read_text(encoding="utf-8"))

    if "deduped_findings" in raw:
        deduped = raw["deduped_findings"]
    else:
        # Fall back to recomputing from raw alerts
        alerts = raw.get("alerts", [])
        deduped = _dedupe_findings(alerts)
        for f in deduped:
            f["dora_article"] = _map_dora_article(f)
            f["is_third_party"] = _is_third_party_finding(f)

    return {
        "summary": raw.get("summary", {}),
        "deduped_findings": deduped,
    }


# ---------------------------------------------------------------------------
# B5: Analysis functions
# ---------------------------------------------------------------------------

def _manual_severity_counts(manual_data: dict[str, Any]) -> dict[str, int]:
    """Count severity across all ``fail`` items in *manual_data*.

    Only items with ``status == "fail"`` contribute; pass/not_applicable/
    not_tested have no severity.
    """
    counts: dict[str, int] = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for cat in CHECKLIST_SCHEMA:
        cat_data = manual_data.get(cat["category"], {})
        for item in cat["items"]:
            entry = cat_data.get(item["id"], {})
            if entry.get("status") == "fail":
                sev = entry.get("severity", "")
                if sev in counts:
                    counts[sev] += 1
    return counts


def _manual_status_counts(
    manual_data: dict[str, Any],
) -> dict[str, dict[str, int]]:
    """Return ``{category: {status: count}}`` plus a ``TOTAL`` pseudo-category.

    Used for the coverage map and completeness sections.
    """
    result: dict[str, dict[str, int]] = {}
    total: dict[str, int] = {s: 0 for s in _VALID_STATUSES}

    for cat in CHECKLIST_SCHEMA:
        cat_counts: dict[str, int] = {s: 0 for s in _VALID_STATUSES}
        cat_data = manual_data.get(cat["category"], {})
        for item in cat["items"]:
            entry = cat_data.get(item["id"], {})
            status = entry.get("status", "not_tested")
            if status in cat_counts:
                cat_counts[status] += 1
                total[status] += 1
            else:
                cat_counts["not_tested"] += 1
                total["not_tested"] += 1
        result[cat["category"]] = cat_counts

    result["TOTAL"] = total
    return result


def _combined_compliance_verdict(
    automated_counts: dict[str, int],
    manual_counts: dict[str, int],
) -> dict[str, Any]:
    """Derive the combined DORA Art. 24 verdict as the worst-case across
    BOTH finding sets.

    Rule (evaluated top-down, first match wins):
      - Any manual Critical fail -> Non-Compliant
      - Any automated High OR manual High fail -> Non-Compliant
      - Any automated Medium OR manual Medium fail -> Partially Compliant
      - Otherwise -> Compliant
    """
    driven_by: list[str] = []

    # Check Critical (manual only)
    if manual_counts.get("Critical", 0) > 0:
        driven_by.append(
            f"manual: {manual_counts['Critical']} Critical-severity finding(s)"
        )
    # Check High (both sources)
    if automated_counts.get("High", 0) > 0:
        driven_by.append(
            f"automated: {automated_counts['High']} High-severity finding(s)"
        )
    if manual_counts.get("High", 0) > 0:
        driven_by.append(
            f"manual: {manual_counts['High']} High-severity finding(s)"
        )

    # Non-Compliant if Critical or High from either side
    if manual_counts.get("Critical", 0) > 0 or automated_counts.get("High", 0) > 0 or manual_counts.get("High", 0) > 0:
        return {
            "verdict": "Non-Compliant",
            "rationale": (
                "Critical or High-severity finding(s) identified across "
                "automated and/or manual testing — immediate remediation "
                "required under Art. 24(1)."
            ),
            "driven_by": driven_by,
        }

    # Check Medium (both sources)
    medium_driven: list[str] = []
    if automated_counts.get("Medium", 0) > 0:
        medium_driven.append(
            f"automated: {automated_counts['Medium']} Medium-severity finding(s)"
        )
    if manual_counts.get("Medium", 0) > 0:
        medium_driven.append(
            f"manual: {manual_counts['Medium']} Medium-severity finding(s)"
        )
    if medium_driven:
        return {
            "verdict": "Partially Compliant",
            "rationale": (
                "Medium-severity finding(s) identified — remediation "
                "required to achieve full alignment with Art. 24(1)."
            ),
            "driven_by": medium_driven,
        }

    return {
        "verdict": "Compliant",
        "rationale": (
            "No Critical, High, or Medium-severity findings identified "
            "across automated and manual testing in this assessment window."
        ),
        "driven_by": [],
    }


def _assess_completeness(
    scan_type: str | None,
    manual_data: dict[str, Any],
) -> dict[str, Any]:
    """Determine whether this assessment is complete enough to stand alone
    as a regulatory submission, and enumerate exactly what is missing.

    Returns a dict with keys: is_complete, automated_gap, manual_not_tested,
    manual_completion_pct, summary_line.
    """
    # Automated gap
    automated_gap: str | None = None
    if scan_type == "baseline":
        automated_gap = (
            "Only a baseline (passive) scan was performed; no active scan "
            "has been run."
        )

    # Manual gaps
    manual_not_tested: list[dict[str, str]] = []
    total_items = 0
    applicable_items = 0

    for cat in CHECKLIST_SCHEMA:
        cat_data = manual_data.get(cat["category"], {})
        for item in cat["items"]:
            total_items += 1
            entry = cat_data.get(item["id"], {})
            status = entry.get("status", "not_tested")
            if status == "not_applicable":
                continue
            applicable_items += 1
            if status == "not_tested":
                manual_not_tested.append({
                    "id": item["id"],
                    "category": cat["title"],
                    "test": item["test"],
                })

    tested_count = applicable_items - len(manual_not_tested)
    completion_pct = (
        (tested_count / applicable_items * 100) if applicable_items > 0 else 100.0
    )

    is_complete = (automated_gap is None) and (len(manual_not_tested) == 0)

    # Summary line
    parts: list[str] = []
    if automated_gap:
        parts.append("automated scan is baseline-only")
    if manual_not_tested:
        parts.append(
            f"{len(manual_not_tested)} manual checklist item(s) not yet tested"
        )
    summary_line = (
        "Assessment is complete."
        if is_complete
        else "Assessment is INCOMPLETE: " + "; ".join(parts) + "."
    )

    return {
        "is_complete": is_complete,
        "automated_gap": automated_gap,
        "manual_not_tested": manual_not_tested,
        "manual_completion_pct": round(completion_pct, 1),
        "summary_line": summary_line,
    }


def _combined_regulatory_recommendations(
    scan_type: str,
    automated_counts: dict[str, int],
    manual_counts: dict[str, int],
    verdict: str,
    completeness: dict[str, Any],
) -> dict[str, Any]:
    """Build combined regulatory recommendations merging automated and
    manual findings awareness.

    Extends the automated-side logic with manual-findings-driven next steps,
    TLPT escalation for manual Critical/High, and completeness warnings.
    """
    from zap_scan import _regulatory_recommendations

    # Start with automated-only recommendations
    base_recs = _regulatory_recommendations(scan_type, automated_counts, verdict)

    next_steps: list[str] = list(base_recs["next_steps"])

    # Completeness warning as first step if incomplete
    if not completeness["is_complete"]:
        next_steps.insert(
            0,
            "Complete outstanding manual test items before this assessment "
            "can be considered final — see Assessment Completeness section.",
        )

    # Manual-fail remediation items, ordered by severity
    manual_fail_items: list[tuple[int, str]] = []
    for cat in CHECKLIST_SCHEMA:
        # We need manual_data but we receive counts -- we'll add manual fail
        # next steps based on counts only (item-level detail is in the report)
        pass

    # Manual Critical/High forces TLPT
    tlpt_warranted = base_recs["tlpt_warranted"]
    tlpt_rationale = base_recs["tlpt_rationale"]
    if manual_counts.get("Critical", 0) > 0 or manual_counts.get("High", 0) > 0:
        tlpt_warranted = True
        manual_parts: list[str] = []
        if manual_counts.get("Critical", 0) > 0:
            manual_parts.append(
                f"{manual_counts['Critical']} Critical-severity manual finding(s)"
            )
        if manual_counts.get("High", 0) > 0:
            manual_parts.append(
                f"{manual_counts['High']} High-severity manual finding(s)"
            )
        tlpt_rationale = (
            f"Manual testing identified {', '.join(manual_parts)} "
            "(auth bypass, IDOR, or equivalent); a Threat-Led Penetration "
            "Test under Art. 26 is strongly recommended to validate "
            "resilience under realistic attack conditions. "
            + tlpt_rationale
        )

    # Add manual-specific remediation next steps
    if manual_counts.get("Critical", 0) > 0:
        next_steps.append(
            f"Prioritise immediate remediation of {manual_counts['Critical']} "
            "Critical-severity manual finding(s) — see Manual Test Findings."
        )
    if manual_counts.get("High", 0) > 0:
        next_steps.append(
            f"Remediate {manual_counts['High']} High-severity manual finding(s) "
            "— see Manual Test Findings."
        )
    if manual_counts.get("Medium", 0) > 0:
        next_steps.append(
            f"Remediate {manual_counts['Medium']} Medium-severity manual "
            "finding(s) within a defined remediation window."
        )

    # Re-assessment timeline (worst-case across both)
    if verdict == "Non-Compliant":
        reassessment = "30 days (post-remediation verification required)."
    elif verdict == "Partially Compliant":
        reassessment = "90 days."
    else:
        reassessment = "12 months (standard periodic testing cycle per Art. 24(6))."

    # Art. 24 minimum
    art24_minimum_met = base_recs["art24_minimum_met"]
    art24_note = base_recs["art24_note"]

    return {
        "tlpt_warranted": tlpt_warranted,
        "tlpt_rationale": tlpt_rationale,
        "next_steps": next_steps,
        "reassessment_timeline": reassessment,
        "art24_minimum_met": art24_minimum_met,
        "art24_note": art24_note,
    }


def _build_coverage_map(
    scan_type: str,
    manual_data: dict[str, Any],
) -> list[dict[str, str]]:
    """Build coverage table rows combining automated and manual testing.

    Returns a list of dicts with keys: layer, method, status.
    """
    status_counts = _manual_status_counts(manual_data)
    scan_label = f"Tested — {scan_type} scan"

    rows: list[dict[str, str]] = [
        {
            "layer": "SQLi, XSS, XXE, path traversal, command injection",
            "method": "Automated (ZAP)",
            "status": scan_label,
        },
        {
            "layer": "Header/cookie misconfiguration, TLS issues",
            "method": "Automated (ZAP)",
            "status": scan_label,
        },
        {
            "layer": "Known-CVE component detection",
            "method": "Automated (ZAP)",
            "status": scan_label,
        },
    ]

    # Manual categories
    category_info = [
        ("authentication", "Authentication depth (session, MFA, token handling)"),
        ("access_control", "Access Control / IDOR"),
        ("business_logic", "Business Logic"),
        ("transaction_payment", "Transaction / Payment Integrity"),
        ("input_handling", "Input Handling (business-logic layer)"),
    ]
    for cat_key, layer_label in category_info:
        cat_counts = status_counts.get(cat_key, {})
        total = sum(cat_counts.values())
        not_tested = cat_counts.get("not_tested", 0)
        tested = total - not_tested
        rows.append({
            "layer": layer_label,
            "method": "Manual",
            "status": f"{tested}/{total} items tested",
        })

    rows.append({
        "layer": "ICT Third-Party Dependency Cataloguing",
        "method": "Automated (partial)",
        "status": "See Third-Party Risk Flags",
    })

    return rows


# ---------------------------------------------------------------------------
# B6: Report rendering
# ---------------------------------------------------------------------------

def _render_entity_header(
    *,
    target: str,
    entity_name: str,
    entity_lei: str,
    assessor_name: str,
    assessment_date: str,
    scan_type: str,
    completion_pct: float,
    timestamp: str,
    is_complete: bool,
) -> list[str]:
    """Render the entity header block (Section 1)."""
    lines: list[str] = []
    title = "# DORA Article 24 Digital Operational Resilience Testing Report"
    if not is_complete:
        title += " — DRAFT (Assessment Incomplete)"
    lines.append(title + "\n")
    lines.append(f"- **Entity Name**: {entity_name}")
    lines.append(f"- **LEI / Registration Number**: {entity_lei}")
    lines.append(f"- **Assessment Date**: {assessment_date}")
    lines.append(f"- **Assessor**: {assessor_name}")
    lines.append(f"- **Target URL**: {target}")
    lines.append(f"- **Automated Scan Type**: {scan_type}")
    lines.append(f"- **Manual Testing Coverage**: {completion_pct}% of checklist items assessed")
    lines.append(f"- **Report Generated**: {timestamp}")
    lines.append("")
    lines.append(
        "> This assessment is performed with reference to **DORA Regulation "
        "(EU) 2022/2554 — Article 24: General requirements for the "
        "performance of digital operational resilience testing**."
    )
    lines.append("")
    return lines


def _render_manual_findings(manual_data: dict[str, Any]) -> list[str]:
    """Render the Manual Test Findings section (Section 5).

    Groups by CHECKLIST_SCHEMA category, renders a summary table per
    category, and expands detail blocks for ``fail`` items only.
    """
    lines: list[str] = []
    lines.append("## Manual Test Findings\n")

    for cat in CHECKLIST_SCHEMA:
        cat_data = manual_data.get(cat["category"], {})
        lines.append(f"### {cat['title']}\n")

        # Summary table
        lines.append("| Status | Test | Severity | Notes |")
        lines.append("|--------|------|----------|-------|")

        fail_items: list[dict[str, Any]] = []

        for item in cat["items"]:
            entry = cat_data.get(item["id"], {})
            status = entry.get("status", "not_tested")
            severity = entry.get("severity")
            status_display = status.upper().replace("_", " ")
            sev_display = severity if severity and status == "fail" else "—"

            if status == "fail":
                notes = "See detail below"
                fail_items.append({
                    "id": item["id"],
                    "test": item["test"],
                    "severity": severity,
                    "steps_to_reproduce": entry.get("steps_to_reproduce", ""),
                    "evidence": entry.get("evidence", ""),
                })
            else:
                notes = "—"

            lines.append(
                f"| {status_display} | {item['test']} | {sev_display} | {notes} |"
            )
        lines.append("")

        # Expanded detail for fail items
        for fi in fail_items:
            lines.append(f"#### {fi['id']} — FAIL ({fi['severity']})\n")
            steps = fi["steps_to_reproduce"] or "(not provided)"
            evidence = fi["evidence"] or "(not provided)"
            lines.append("**Steps to Reproduce**\n")
            lines.append(f"{steps}\n")
            lines.append("**Evidence**\n")
            lines.append(f"{evidence}\n")
            lines.append("---\n")

    return lines


def _render_combined_report(
    *,
    target: str,
    entity_name: str,
    entity_lei: str,
    assessor_name: str,
    assessment_date: str,
    zap_summary: dict[str, Any],
    automated_deduped: list[dict[str, Any]],
    manual_data: dict[str, Any],
    out: pathlib.Path,
) -> None:
    """Assemble and write the full combined DORA Article 24 report.

    Keyword-only arguments ensure call-site clarity.  Writes Markdown to
    *out*.
    """
    scan_type = zap_summary.get("scan_type", "unknown")
    timestamp = zap_summary.get(
        "timestamp",
        dt.datetime.now(dt.timezone.utc).isoformat(),
    )

    # Pre-compute all analysis
    auto_counts = _severity_counts(automated_deduped)
    manual_counts = _manual_severity_counts(manual_data)
    manual_statuses = _manual_status_counts(manual_data)
    verdict = _combined_compliance_verdict(auto_counts, manual_counts)
    completeness = _assess_completeness(scan_type, manual_data)
    tp_flags = _third_party_risk_flags(automated_deduped)
    recs = _combined_regulatory_recommendations(
        scan_type, auto_counts, manual_counts,
        verdict["verdict"], completeness,
    )
    coverage_map = _build_coverage_map(scan_type, manual_data)

    lines: list[str] = []

    # --- Section 1: Entity header ---
    lines.extend(_render_entity_header(
        target=target,
        entity_name=entity_name,
        entity_lei=entity_lei,
        assessor_name=assessor_name,
        assessment_date=assessment_date,
        scan_type=scan_type,
        completion_pct=completeness["manual_completion_pct"],
        timestamp=timestamp,
        is_complete=completeness["is_complete"],
    ))

    # --- Section 2: Assessment Incomplete callout (conditional) ---
    if not completeness["is_complete"]:
        lines.append(
            "> **ASSESSMENT INCOMPLETE.** This report reflects a partial assessment"
        )
        lines.append(
            "> and MUST NOT be treated as a final compliance determination."
        )
        auto_gap_text = completeness["automated_gap"] or "Complete"
        lines.append(f"> - Automated: {auto_gap_text}")
        not_tested_count = len(completeness["manual_not_tested"])
        total_items = sum(
            len(cat["items"]) for cat in CHECKLIST_SCHEMA
        )
        lines.append(
            f"> - Manual: {not_tested_count} of {total_items} checklist "
            "item(s) not yet tested (see Assessment Completeness section "
            "for the full list)."
        )
        lines.append("")

    # --- Section 3: Executive Summary ---
    lines.append("## Executive Summary\n")

    verdict_label = (
        "Provisional verdict based on partial testing"
        if not completeness["is_complete"]
        else "Overall Compliance Verdict"
    )
    lines.append(f"**{verdict_label}: {verdict['verdict']}**\n")
    lines.append(f"{verdict['rationale']}\n")

    lines.append("**Key Statistics**\n")
    lines.append("*Automated Scan Findings*\n")
    lines.append(f"- Unique findings: {len(automated_deduped)}")
    total_instances = sum(f.get("instance_count", 0) for f in automated_deduped)
    lines.append(f"- Total alert instances: {total_instances}")
    for sev in ("High", "Medium", "Low", "Informational"):
        lines.append(f"  - {sev}: {auto_counts.get(sev, 0)}")
    lines.append(f"- Third-party dependency flags: {len(tp_flags)}")
    lines.append("")

    lines.append("*Manual Test Findings*\n")
    total_statuses = manual_statuses.get("TOTAL", {})
    items_tested = (
        total_statuses.get("pass", 0)
        + total_statuses.get("fail", 0)
        + total_statuses.get("not_applicable", 0)
    )
    total_items_all = sum(total_statuses.values())
    lines.append(f"- Items tested: {items_tested} / {total_items_all}")
    lines.append(f"  - Pass: {total_statuses.get('pass', 0)}")
    lines.append(f"  - Fail: {total_statuses.get('fail', 0)}")
    lines.append(f"  - Not applicable: {total_statuses.get('not_applicable', 0)}")
    lines.append(f"  - Not tested: {total_statuses.get('not_tested', 0)}")
    if any(manual_counts.get(s, 0) > 0 for s in ("Critical", "High", "Medium", "Low")):
        lines.append("- Fail breakdown by severity:")
        for sev in ("Critical", "High", "Medium", "Low"):
            if manual_counts.get(sev, 0) > 0:
                lines.append(f"  - {sev}: {manual_counts[sev]}")
    lines.append("")

    # Narrative paragraph
    driven_text = ""
    if verdict["driven_by"]:
        driven_text = (
            " The verdict is driven by: "
            + "; ".join(verdict["driven_by"])
            + "."
        )
    lines.append(
        f"This combined assessment of {target} incorporates automated "
        f"scanning ({scan_type}) identifying {len(automated_deduped)} unique "
        f"finding(s) and manual testing covering {items_tested} of "
        f"{total_items_all} checklist items. The assessment yields "
        f"{'a provisional' if not completeness['is_complete'] else 'an overall'} "
        f"compliance verdict of **{verdict['verdict']}** against DORA "
        f"Article 24(1) ICT security testing requirements.{driven_text}"
    )
    lines.append("")

    # --- Section 4: Automated Scan Findings ---
    lines.append("## Automated Scan Findings\n")
    if automated_deduped:
        lines.extend(_render_findings_table(automated_deduped))
        lines.extend(_render_detailed_findings(automated_deduped))
    else:
        lines.append("No automated findings to report.\n")

    # --- Section 5: Manual Test Findings ---
    lines.extend(_render_manual_findings(manual_data))

    # --- Section 6: Combined Compliance Verdict ---
    lines.append("## Combined Compliance Verdict\n")
    lines.append(f"**Verdict: {verdict['verdict']}**\n")
    lines.append(f"{verdict['rationale']}\n")
    if verdict["driven_by"]:
        lines.append("**Driven by:**\n")
        for item in verdict["driven_by"]:
            lines.append(f"- {item}")
        lines.append("")

    # --- Section 7: ICT Third-Party Risk Flags ---
    lines.append("## ICT Third-Party Risk Flags (DORA Chapter V)\n")
    lines.append(
        "This section addresses ICT third-party risk management obligations "
        "under DORA Articles 28–44, which require financial entities to "
        "identify, monitor, and manage risks arising from ICT third-party "
        "service providers and dependencies.\n"
    )
    if not tp_flags:
        lines.append(
            "No third-party ICT dependency concerns were identified in "
            "this assessment.\n"
        )
    else:
        for f in tp_flags:
            lines.append(f"### {f['alert']}\n")
            lines.append(f"- **Severity**: {f['severity']}")
            lines.append(f"- **DORA Reference**: {f['dora_article']}")
            lines.append(f"- **Affected URLs**: {f['instance_count']}")
            lines.append(f"- **Risk Note**: {f.get('risk_note', '')}")
            lines.append("")
    lines.append(
        "*Note: Manual testing does not independently assess ICT third-party "
        "dependencies; see the Automated Scan Findings section for third-party "
        "flags identified via passive/active scanning.*\n"
    )

    # --- Section 8: Regulatory Recommendations ---
    lines.append("## Regulatory Recommendations\n")

    lines.append("### Threat-Led Penetration Test (Art. 26)\n")
    tlpt_yn = "Yes" if recs["tlpt_warranted"] else "No"
    lines.append(f"**TLPT Recommended**: {tlpt_yn}\n")
    lines.append(f"{recs['tlpt_rationale']}\n")

    lines.append("### Recommended Next Steps\n")
    for step in recs["next_steps"]:
        lines.append(f"- {step}")
    lines.append("")

    lines.append("### Re-assessment Timeline\n")
    lines.append(f"{recs['reassessment_timeline']}\n")

    lines.append("### Art. 24 Minimum Testing Requirements\n")
    met_str = "Met" if recs["art24_minimum_met"] else "Not Met"
    lines.append(f"**Status**: {met_str}\n")
    lines.append(f"{recs['art24_note']}\n")

    # --- Section 9: Coverage Map ---
    lines.append("## Coverage Map\n")
    lines.append("| Layer | Method | Status |")
    lines.append("|-------|--------|--------|")
    for row in coverage_map:
        lines.append(f"| {row['layer']} | {row['method']} | {row['status']} |")
    lines.append("")

    # --- Section 10: Assessment Completeness ---
    lines.append("## Assessment Completeness\n")

    if completeness["automated_gap"]:
        lines.append(f"**Automated Scan Gap**: {completeness['automated_gap']}\n")
    else:
        lines.append("**Automated Scan Gap**: None — active scan performed.\n")

    not_tested_items = completeness["manual_not_tested"]
    if not_tested_items:
        lines.append(
            f"**Manual Items Not Tested** ({len(not_tested_items)} remaining):\n"
        )
        for nt in not_tested_items:
            lines.append(f"- `{nt['id']}` ({nt['category']}): {nt['test']}")
        lines.append("")
    else:
        lines.append("**Manual Items Not Tested**: None — all items assessed.\n")

    lines.append(
        f"**Manual Completion**: {completeness['manual_completion_pct']}%\n"
    )

    status_str = (
        "COMPLETE"
        if completeness["is_complete"]
        else "INCOMPLETE — see gaps above"
    )
    lines.append(f"**Assessment Status**: {status_str}\n")

    out.write_text("\n".join(lines), encoding="utf-8")


# ---------------------------------------------------------------------------
# B7: CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser with ``init-template`` and ``generate``
    subcommands."""
    p = argparse.ArgumentParser(
        prog="combined_report",
        description=(
            "Combined DORA Article 24 assessment report generator. "
            "Merges automated ZAP scan results with manual penetration "
            "test findings into a unified regulatory report."
        ),
    )
    sub = p.add_subparsers(dest="command", required=True)

    # --- init-template ---
    p_init = sub.add_parser(
        "init-template",
        help="Generate a blank manual-findings template",
    )
    p_init.add_argument(
        "--output",
        type=pathlib.Path,
        default=pathlib.Path("manual_findings.yaml"),
        help="Output template file path (default: manual_findings.yaml)",
    )
    p_init.add_argument(
        "--format",
        choices=["yaml", "json"],
        default="yaml",
        dest="template_format",
        help="Template format (default: yaml)",
    )
    p_init.add_argument(
        "--target",
        default="",
        help="Pre-fill meta.target with this URL",
    )

    # --- generate ---
    p_gen = sub.add_parser(
        "generate",
        help="Merge ZAP + manual findings into one DORA report",
    )
    p_gen.add_argument(
        "--zap-report",
        type=pathlib.Path,
        required=True,
        help="Path to zap_scan.py JSON report (--format json output)",
    )
    p_gen.add_argument(
        "--manual-findings",
        type=pathlib.Path,
        required=True,
        help="Path to filled-in manual-findings YAML/JSON file",
    )
    p_gen.add_argument(
        "--entity-name",
        required=True,
        help="Name of the regulated entity being assessed",
    )
    p_gen.add_argument(
        "--entity-lei",
        required=True,
        help="Legal Entity Identifier (LEI) or national registration number",
    )
    p_gen.add_argument(
        "--assessor-name",
        default=os.environ.get("ZAP_ASSESSOR_NAME", "") or getpass.getuser(),
        help="Name of the person/team performing the assessment (default: current user)",
    )
    p_gen.add_argument(
        "--assessment-date",
        default=dt.date.today().isoformat(),
        help="Assessment date in ISO format (default: today)",
    )
    p_gen.add_argument(
        "--output",
        type=pathlib.Path,
        default=None,
        help="Output report path (default: combined_report_<timestamp>.md)",
    )
    p_gen.add_argument(
        "--format",
        choices=["md", "json"],
        default="md",
        dest="report_format",
        help="Report output format (default: md)",
    )
    p_gen.add_argument(
        "--allow-incomplete",
        action="store_true",
        help=(
            "Generate the report even if manual items remain not_tested "
            "or only a baseline automated scan was run (report will still "
            "flag incompleteness prominently; this flag only controls "
            "whether generation is blocked outright)"
        ),
    )

    return p


def _cmd_init_template(args: argparse.Namespace) -> None:
    """Handler for the ``init-template`` subcommand."""
    write_manual_template(args.output, target=args.target, fmt=args.template_format)
    print(f"Template written to {args.output}")


def _cmd_generate(args: argparse.Namespace) -> None:
    """Handler for the ``generate`` subcommand."""
    # Load inputs
    zap_data = load_zap_report(args.zap_report)
    zap_summary = zap_data["summary"]
    automated_deduped = zap_data["deduped_findings"]

    try:
        manual_data = load_manual_findings(args.manual_findings)
    except ManualFindingsError as exc:
        sys.exit(f"ERROR: {exc}")

    target = zap_summary.get("target", "")

    # Check completeness
    scan_type = zap_summary.get("scan_type")
    completeness = _assess_completeness(scan_type, manual_data)
    if not completeness["is_complete"] and not args.allow_incomplete:
        not_tested_count = len(completeness["manual_not_tested"])
        msg = (
            f"ERROR: Assessment is incomplete "
            f"({not_tested_count} manual item(s) not_tested"
        )
        if completeness["automated_gap"]:
            msg += ", automated scan is baseline-only"
        msg += (
            ").\n"
            "Re-run with --allow-incomplete to generate a draft report anyway "
            "(it will be clearly marked DRAFT / INCOMPLETE)."
        )
        sys.exit(msg)

    # Resolve output path
    if args.output:
        output_path = args.output
    else:
        ts = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
        ext = args.report_format
        output_path = pathlib.Path(f"combined_report_{ts}.{ext}")

    if args.report_format == "md":
        _render_combined_report(
            target=target,
            entity_name=args.entity_name,
            entity_lei=args.entity_lei,
            assessor_name=args.assessor_name,
            assessment_date=args.assessment_date,
            zap_summary=zap_summary,
            automated_deduped=automated_deduped,
            manual_data=manual_data,
            out=output_path,
        )
    elif args.report_format == "json":
        auto_counts = _severity_counts(automated_deduped)
        manual_counts = _manual_severity_counts(manual_data)
        manual_statuses = _manual_status_counts(manual_data)
        verdict = _combined_compliance_verdict(auto_counts, manual_counts)
        tp_flags = _third_party_risk_flags(automated_deduped)
        recs = _combined_regulatory_recommendations(
            scan_type or "unknown", auto_counts, manual_counts,
            verdict["verdict"], completeness,
        )
        coverage_map = _build_coverage_map(scan_type or "unknown", manual_data)

        report = {
            "entity_name": args.entity_name,
            "entity_lei": args.entity_lei,
            "assessment_date": args.assessment_date,
            "assessor": args.assessor_name,
            "target": target,
            "zap_summary": zap_summary,
            "automated_findings": automated_deduped,
            "automated_severity_counts": auto_counts,
            "manual_severity_counts": manual_counts,
            "manual_status_counts": manual_statuses,
            "combined_verdict": verdict,
            "third_party_flags": tp_flags,
            "regulatory_recommendations": recs,
            "coverage_map": coverage_map,
            "completeness": completeness,
        }
        output_path.write_text(
            json.dumps(report, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

    print(f"Report written to {output_path}")
    if not completeness["is_complete"]:
        print("NOTE: Report is marked DRAFT / INCOMPLETE.")


def main() -> None:
    """Entry point -- dispatches on subcommand."""
    parser = build_parser()
    args = parser.parse_args()
    if args.command == "init-template":
        _cmd_init_template(args)
    elif args.command == "generate":
        _cmd_generate(args)


if __name__ == "__main__":
    main()
