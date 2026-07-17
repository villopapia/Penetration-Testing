#!/usr/bin/env python3
"""OWASP ZAP scan orchestrator CLI.

Drives ZAP's spider, passive scan, active scan, and OpenAPI import
through the official ``zaproxy`` Python client, then produces a
structured vulnerability report (JSON / Markdown / HTML).

Reports follow a fixed 7-section template and can merge automated ZAP
findings with manual test findings supplied via ``--manual-findings``.
"""

from __future__ import annotations

import argparse
import datetime as dt
import getpass
import json
import logging
import os
import pathlib
import re
import sys
import time
from typing import Any

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

try:
    import yaml as _yaml  # type: ignore[import-untyped]
    _HAS_YAML = True
except ImportError:
    _yaml = None  # type: ignore[assignment]
    _HAS_YAML = False

# ---------------------------------------------------------------------------
# Prerequisites
# ---------------------------------------------------------------------------

def _check_zaproxy_installed() -> None:
    """Exit immediately if the ``zaproxy`` package is missing."""
    try:
        import zapv2  # noqa: F401
    except ImportError:
        sys.exit(
            "ERROR: The 'zaproxy' Python package is not installed.\n"
            "Install it with:  pip install zaproxy"
        )


def _check_zap_reachable(base_url: str, api_key: str) -> None:
    """Exit immediately if ZAP is not responding at *base_url*."""
    from zapv2 import ZAPv2
    try:
        zap = ZAPv2(apikey=api_key, proxies={"http": base_url, "https": base_url})
        zap.core.version
    except Exception as exc:
        sys.exit(
            f"ERROR: Cannot reach ZAP at {base_url}.\n"
            f"Make sure ZAP is running in daemon mode (zap.sh -daemon -port 8080).\n"
            f"Details: {exc}"
        )


# ---------------------------------------------------------------------------
# Audit logging
# ---------------------------------------------------------------------------

AUDIT_LOG = pathlib.Path("scan_audit.log")

_audit_logger = logging.getLogger("zap_audit")
_audit_handler = logging.FileHandler(AUDIT_LOG, encoding="utf-8")
_audit_handler.setFormatter(logging.Formatter("%(message)s"))
_audit_logger.addHandler(_audit_handler)
_audit_logger.setLevel(logging.INFO)


def _audit(msg: str) -> None:
    _audit_logger.info(msg)


def _log_scan_event(
    event: str,
    target: str,
    scan_type: str,
    *,
    extra: str = "",
) -> None:
    ts = dt.datetime.now(dt.timezone.utc).isoformat()
    user = getpass.getuser()
    line = f"[{ts}] {event} | target={target} | type={scan_type} | user={user}"
    if extra:
        line += f" | {extra}"
    _audit(line)
    print(line)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser."""
    p = argparse.ArgumentParser(
        prog="zap_scan",
        description="Orchestrate OWASP ZAP scans and produce vulnerability reports.",
    )
    p.add_argument(
        "--target",
        required=True,
        help="Full URL to scan, e.g. https://staging.example.com",
    )
    p.add_argument(
        "--api-key",
        default=os.environ.get("ZAP_API_KEY", ""),
        help="ZAP API key (or set ZAP_API_KEY env var)",
    )
    p.add_argument(
        "--zap-url",
        default="http://localhost:8080",
        help="Base URL where ZAP is listening (default: http://localhost:8080)",
    )
    p.add_argument(
        "--scan-type",
        choices=["baseline", "full", "api"],
        default="baseline",
        help=(
            "baseline = passive scan only; "
            "full = spider + active scan; "
            "api = import OpenAPI spec and scan defined endpoints"
        ),
    )
    p.add_argument(
        "--confirm",
        action="store_true",
        help="Required flag to authorise active scanning (full / api)",
    )
    p.add_argument(
        "--openapi-spec",
        type=pathlib.Path,
        help="Path to an OpenAPI/Swagger spec file (required for --scan-type=api)",
    )
    p.add_argument(
        "--entity-name",
        default=None,
        help="Name of the regulated entity being assessed (required for --format=md)",
    )
    p.add_argument(
        "--entity-lei",
        default=None,
        help="Legal Entity Identifier (LEI) or national registration number (required for --format=md)",
    )
    p.add_argument(
        "--assessor-name",
        default=os.environ.get("ZAP_ASSESSOR_NAME", "") or getpass.getuser(),
        help="Name of the person/team performing the assessment (default: current user)",
    )
    p.add_argument(
        "--assessment-date",
        default=dt.date.today().isoformat(),
        help="Assessment date in ISO format (default: today)",
    )
    p.add_argument(
        "--output",
        type=pathlib.Path,
        default=None,
        help="Output report path (default: zap_report_<timestamp>.<ext>)",
    )
    p.add_argument(
        "--format",
        choices=["json", "html", "md"],
        default="md",
        dest="report_format",
        help="Report output format (default: md)",
    )
    p.add_argument(
        "--timeout",
        type=int,
        default=3600,
        help="Maximum scan duration in seconds (default: 3600)",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Print what would happen without contacting ZAP",
    )
    p.add_argument(
        "--manual-findings",
        type=pathlib.Path,
        default=None,
        help="Path to JSON file with manual test findings (list of finding objects)",
    )
    p.add_argument(
        "--regulatory-framework",
        choices=["none", "dora"],
        default="none",
        help="Include regulatory alignment section (default: none)",
    )
    p.add_argument(
        "--business-context",
        type=pathlib.Path,
        default=None,
        help="Path to JSON/YAML file mapping finding categories to business impact statements",
    )
    p.add_argument(
        "--exclude-urls",
        nargs="*",
        default=None,
        help="URL patterns excluded from scanning (reported in methodology section)",
    )
    return p


def validate_args(args: argparse.Namespace) -> None:
    """Enforce safety constraints on parsed arguments."""
    if args.scan_type == "full" and not args.confirm:
        sys.exit(
            "ERROR: --scan-type=full requires --confirm to authorise active scanning.\n"
            "Active scans send attack payloads — only run against targets you own."
        )
    if args.scan_type == "api" and not args.confirm:
        sys.exit(
            "ERROR: --scan-type=api runs active scans and requires --confirm."
        )
    if args.scan_type == "api" and not args.openapi_spec:
        sys.exit("ERROR: --scan-type=api requires --openapi-spec.")
    if args.openapi_spec and not args.openapi_spec.is_file():
        sys.exit(f"ERROR: OpenAPI spec not found: {args.openapi_spec}")
    if args.manual_findings and not args.manual_findings.is_file():
        sys.exit(f"ERROR: Manual findings file not found: {args.manual_findings}")
    if args.business_context and not args.business_context.is_file():
        sys.exit(f"ERROR: Business context file not found: {args.business_context}")


def resolve_output_path(args: argparse.Namespace) -> pathlib.Path:
    """Return the output path, generating a timestamped default if needed."""
    if args.output:
        return args.output
    ext_map = {"json": "json", "html": "html", "md": "md"}
    ts = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    return pathlib.Path(f"zap_report_{ts}.{ext_map[args.report_format]}")


# ---------------------------------------------------------------------------
# Interactive confirmation
# ---------------------------------------------------------------------------

def interactive_confirm(target: str, scan_type: str) -> None:
    """Prompt user to type 'yes' before an active scan."""
    print(f"\n{'='*60}")
    print(f"  Target   : {target}")
    print(f"  Scan type: {scan_type}")
    print(f"{'='*60}")
    print(
        "\nThis scan will send active attack payloads to the target.\n"
        "Only proceed if you have authorisation to test this target.\n"
    )
    answer = input("Type 'yes' to continue: ").strip().lower()
    if answer != "yes":
        sys.exit("Aborted by user.")


# ---------------------------------------------------------------------------
# ZAP helpers
# ---------------------------------------------------------------------------

def _make_zap(api_key: str, zap_url: str) -> Any:
    from zapv2 import ZAPv2
    return ZAPv2(apikey=api_key, proxies={"http": zap_url, "https": zap_url})


def _new_session(zap: Any) -> None:
    """Start a fresh ZAP session so results are isolated."""
    zap.core.new_session(name="zap_scan_session", overwrite=True)


def _seed_target(zap: Any, target: str) -> None:
    """Access the target URL through ZAP so it appears in the sites tree."""
    print(f"Seeding target in ZAP sites tree: {target}")
    try:
        zap.core.access_url(url=target, followredirects="true")
    except Exception:
        try:
            zap.urlopen(target)
        except Exception:
            print("  Warning: could not seed target URL, spider may start cold")
    time.sleep(5)


def _run_spider(zap: Any, target: str, timeout: int) -> None:
    """Run ZAP's spider and block until it finishes or *timeout* expires."""
    _seed_target(zap, target)
    print(f"Starting spider against {target} ...")
    scan_id = zap.spider.scan(target)
    if not str(scan_id).isdigit():
        raise RuntimeError(
            f"Spider failed to start: ZAP returned '{scan_id}'. "
            "Check that the target URL is accessible."
        )
    deadline = time.monotonic() + timeout
    while int(zap.spider.status(scan_id)) < 100:
        if time.monotonic() > deadline:
            zap.spider.stop(scan_id)
            raise TimeoutError("Spider timed out")
        pct = zap.spider.status(scan_id)
        print(f"  Spider progress: {pct}%")
        time.sleep(10)
    results = zap.spider.results(scan_id)
    print(f"Spider complete. {len(results)} URL(s) found.")


def _run_passive_scan_wait(zap: Any, timeout: int) -> None:
    """Wait for ZAP's passive scanner to finish processing queued messages."""
    print("Waiting for passive scan to complete ...")
    time.sleep(5)
    deadline = time.monotonic() + timeout
    checks_at_zero = 0
    while True:
        if time.monotonic() > deadline:
            raise TimeoutError("Passive scan timed out")
        remaining = int(zap.pscan.records_to_scan)
        if remaining > 0:
            checks_at_zero = 0
            print(f"  Passive scan records remaining: {remaining}")
        else:
            checks_at_zero += 1
            if checks_at_zero >= 3:
                break
        time.sleep(5)
    print("Passive scan complete.")


def _find_scan_target(zap: Any, target: str) -> str | None:
    """Find a URL in ZAP's sites tree that matches the target domain."""
    from urllib.parse import urlparse
    parsed = urlparse(target)
    domain = parsed.netloc

    urls = zap.core.urls(target)
    if urls:
        return target

    urls = zap.core.urls(target.rstrip("/"))
    if urls:
        return target.rstrip("/")

    all_urls = zap.core.urls()
    for u in all_urls:
        if domain in u:
            print(f"  Found matching URL in sites tree: {u}")
            return u

    return None


def _run_active_scan(zap: Any, target: str, timeout: int) -> bool:
    """Run ZAP's active scanner. Returns True if scan ran, False if skipped."""
    print(f"Starting active scan against {target} ...")

    scan_target = _find_scan_target(zap, target)
    if not scan_target:
        print(
            "  WARNING: No URLs in ZAP's sites tree for this target.\n"
            "  Active scan skipped. Passive findings will still be reported."
        )
        return False

    scan_id = zap.ascan.scan(scan_target)
    if not str(scan_id).isdigit():
        print(
            f"  WARNING: Active scan could not start (ZAP returned '{scan_id}').\n"
            "  Active scan skipped. Passive findings will still be reported."
        )
        return False

    deadline = time.monotonic() + timeout
    while int(zap.ascan.status(scan_id)) < 100:
        if time.monotonic() > deadline:
            zap.ascan.stop(scan_id)
            raise TimeoutError("Active scan timed out")
        pct = zap.ascan.status(scan_id)
        print(f"  Active scan progress: {pct}%")
        time.sleep(10)
    print("Active scan complete.")
    return True


def _import_openapi(zap: Any, spec_path: pathlib.Path, target: str) -> None:
    """Import an OpenAPI specification into ZAP."""
    print(f"Importing OpenAPI spec from {spec_path} ...")
    spec_text = spec_path.read_text(encoding="utf-8")
    try:
        json.loads(spec_text)
    except json.JSONDecodeError:
        import yaml  # type: ignore[import-untyped]
        try:
            yaml.safe_load(spec_text)
        except Exception:
            raise ValueError(f"Cannot parse OpenAPI spec at {spec_path} as JSON or YAML")
    result = zap.openapi.import_file(str(spec_path.resolve()), target)
    print(f"OpenAPI import result: {result}")


def _fetch_alerts(zap: Any, target: str) -> list[dict[str, Any]]:
    """Return all alerts for *target* from ZAP."""
    alerts = zap.core.alerts(baseurl=target)
    if not alerts:
        base = target.rstrip("/")
        alerts = zap.core.alerts(baseurl=base)
    if not alerts:
        all_alerts = zap.core.alerts()
        alerts = [a for a in all_alerts if target.rstrip("/") in a.get("url", "")]
    if not alerts:
        alerts = zap.core.alerts()
        print(f"  Warning: URL filter returned 0 alerts, returning all {len(alerts)} alerts from session")
    return alerts


# ---------------------------------------------------------------------------
# Report building
# ---------------------------------------------------------------------------

RISK_ORDER = {"Critical": -1, "High": 0, "Medium": 1, "Low": 2, "Informational": 3}


def _risk_label(risk_code: str | int) -> str:
    mapping = {"4": "Critical", "3": "High", "2": "Medium", "1": "Low", "0": "Informational"}
    return mapping.get(str(risk_code), "Informational")


def _parse_alerts(raw_alerts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Normalise ZAP alerts into a clean list of dicts."""
    parsed: list[dict[str, Any]] = []
    for a in raw_alerts:
        parsed.append({
            "severity": _risk_label(a.get("riskcode", a.get("risk", "0"))),
            "alert": a.get("alert", a.get("name", "Unknown")),
            "url": a.get("url", ""),
            "description": a.get("description", ""),
            "solution": a.get("solution", ""),
            "cweid": a.get("cweid", ""),
            "wascid": a.get("wascid", ""),
            "reference": a.get("reference", ""),
        })
    parsed.sort(key=lambda x: RISK_ORDER.get(x["severity"], 99))
    return parsed


def _dedupe_findings(alerts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Group parsed alerts by alert name and collect unique URLs per group.

    Returns a list of deduplicated finding dicts sorted by severity
    (``RISK_ORDER``) then alert name.
    """
    groups: dict[str, list[dict[str, Any]]] = {}
    for a in alerts:
        groups.setdefault(a["alert"], []).append(a)

    deduped: list[dict[str, Any]] = []
    for alert_name, instances in groups.items():
        # Take the highest-risk severity across instances (should be uniform,
        # but guard against edge cases).
        best_sev = min(instances, key=lambda x: RISK_ORDER.get(x["severity"], 99))["severity"]
        urls = sorted({inst["url"] for inst in instances if inst["url"]})
        first = instances[0]
        deduped.append({
            "alert": alert_name,
            "severity": best_sev,
            "urls": urls,
            "instance_count": len(urls),
            "description": first["description"],
            "solution": first["solution"],
            "cweid": first["cweid"],
            "wascid": first["wascid"],
            "reference": first["reference"],
        })

    deduped.sort(key=lambda x: (RISK_ORDER.get(x["severity"], 99), x["alert"]))
    return deduped


# ---------------------------------------------------------------------------
# DORA Article 24 mapping
# ---------------------------------------------------------------------------

DORA_ARTICLE_TEXT: dict[str, str] = {
    "24_1_a": "Art. 24(1)(a) — ICT security testing",
    "24_1_b": "Art. 24(1)(b) — Assessment of ICT third-party dependencies",
}

_DORA_KEYWORD_MAP: list[tuple[tuple[str, ...], str]] = [
    (("cookie", "session"), "24_1_a"),
    (("content security policy", "csp", "xss", "cross site scripting"), "24_1_a"),
    (("csrf", "cross-site request forgery", "cross site request forgery"), "24_1_a"),
    (("cross-domain javascript", "cross domain javascript", "third-party",
      "third party", "external resource", "loading of"), "24_1_b"),
    (("information disclosure", "information leakage", "disclosure"), "24_1_a"),
    (("sub resource integrity", "subresource integrity", "sri"), "24_1_b"),
    (("cache control", "cache-control", "caching"), "24_1_a"),
]
_DORA_DEFAULT = "24_1_a"


def _map_dora_article(finding: dict[str, Any]) -> str:
    """Return the DORA Article 24 reference string for *finding*."""
    for source_field in ("alert", "description"):
        text = finding.get(source_field, "").lower()
        for keywords, key in _DORA_KEYWORD_MAP:
            if any(kw in text for kw in keywords):
                return DORA_ARTICLE_TEXT[key]
    return DORA_ARTICLE_TEXT[_DORA_DEFAULT]


# ---------------------------------------------------------------------------
# Third-party risk detection (DORA Chapter V)
# ---------------------------------------------------------------------------

_THIRD_PARTY_KEYWORDS: tuple[str, ...] = (
    "cross-domain javascript",
    "cross domain javascript",
    "sub resource integrity",
    "subresource integrity",
    "sri",
    "external resource",
    "third-party",
    "third party",
    "loading of",
    "cdn",
)


def _is_third_party_finding(finding: dict[str, Any]) -> bool:
    """Return ``True`` if *finding* relates to an ICT third-party dependency."""
    for source_field in ("alert", "description"):
        text = finding.get(source_field, "").lower()
        if any(kw in text for kw in _THIRD_PARTY_KEYWORDS):
            return True
    return False


def _third_party_risk_flags(
    deduped: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Return third-party findings with an attached ``risk_note``."""
    flagged: list[dict[str, Any]] = []
    for f in deduped:
        if not f.get("is_third_party"):
            continue
        if f["severity"] in ("High", "Medium"):
            note = (
                "Elevated risk: unvetted third-party code execution in this "
                "context should be treated as a critical ICT third-party "
                "dependency under Art. 28 due-diligence obligations."
            )
        else:
            note = (
                "Lower immediate risk, but should be catalogued in the "
                "entity's ICT third-party register (Art. 28) and reviewed "
                "at the next contract/vendor review cycle."
            )
        f["risk_note"] = note
        flagged.append(f)
    return flagged


# ---------------------------------------------------------------------------
# Severity counting / compliance verdict / recommendations
# ---------------------------------------------------------------------------

def _severity_counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    """Count occurrences of each severity level in *findings*."""
    counts: dict[str, int] = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
    for f in findings:
        sev = f["severity"]
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def _compliance_verdict(counts: dict[str, int]) -> dict[str, str]:
    """Derive DORA Art. 24 compliance verdict from deduplicated severity counts."""
    if counts.get("High", 0) > 0:
        return {
            "verdict": "Non-Compliant",
            "rationale": (
                f"{counts['High']} High-severity finding(s) identified "
                "— immediate remediation required under Art. 24(1)."
            ),
        }
    if counts.get("Medium", 0) > 0:
        return {
            "verdict": "Partially Compliant",
            "rationale": (
                f"{counts['Medium']} Medium-severity finding(s) identified "
                "— remediation required to achieve full alignment "
                "with Art. 24(1)."
            ),
        }
    return {
        "verdict": "Compliant",
        "rationale": (
            "No High or Medium-severity findings identified in this "
            "assessment window."
        ),
    }


def _regulatory_recommendations(
    scan_type: str,
    counts: dict[str, int],
    verdict: str,
) -> dict[str, Any]:
    """Build the regulatory-recommendations data consumed by the report renderer."""
    has_high_or_medium = counts.get("High", 0) > 0 or counts.get("Medium", 0) > 0

    # --- TLPT (Art. 26) ---
    if scan_type in ("full", "api") and not has_high_or_medium:
        tlpt_warranted = False
        tlpt_rationale = (
            "Active testing was performed with no High or Medium-severity "
            "findings; TLPT can be scheduled on the entity's standard "
            "cycle rather than immediately."
        )
    else:
        tlpt_warranted = True
        parts: list[str] = []
        if has_high_or_medium:
            parts.append(
                "High/Medium-severity findings indicate exploitable "
                "weaknesses; a full Threat-Led Penetration Test under "
                "Art. 26 is recommended to validate resilience under "
                "realistic attack conditions."
            )
        if scan_type == "baseline":
            parts.append(
                "This was a passive baseline scan only; Art. 24(1) "
                "contemplates a range of testing measures and Art. 26 "
                "TLPT provides assurance that active/adversarial testing "
                "has not been substituted by passive analysis alone."
            )
        tlpt_rationale = " ".join(parts)

    # --- Next steps ---
    next_steps: list[str] = []
    if verdict == "Non-Compliant":
        next_steps.append(
            "Prioritise immediate remediation of all High-severity findings."
        )
        next_steps.append(
            "Re-scan affected endpoints after remediation to confirm fixes."
        )
        next_steps.append(
            "Escalate findings to the entity's ICT risk committee for "
            "awareness and resource allocation."
        )
    elif verdict == "Partially Compliant":
        next_steps.append(
            "Remediate Medium-severity findings within a defined remediation window."
        )
        next_steps.append(
            "Confirm fixes via a targeted re-scan of affected endpoints."
        )
    else:
        next_steps.append(
            "Maintain current control baseline and continue periodic testing cadence."
        )
        next_steps.append(
            "Review Low and Informational items opportunistically during "
            "regular development cycles."
        )
    next_steps.append(
        "Update the entity's ICT third-party register to reflect findings "
        "in the Chapter V section of this report."
    )

    # --- Re-assessment timeline ---
    if verdict == "Non-Compliant":
        reassessment = "30 days (post-remediation verification scan required)."
    elif verdict == "Partially Compliant":
        reassessment = "90 days."
    else:
        reassessment = "12 months (standard periodic testing cycle per Art. 24(6))."

    # --- Art. 24 minimum requirements ---
    art24_minimum_met = scan_type in ("full", "api")
    if art24_minimum_met:
        art24_note = (
            "Active testing was performed, consistent with Art. 24(1) "
            "minimum expectations for regular vulnerability assessments."
        )
    else:
        art24_note = (
            "A passive baseline scan alone is unlikely to satisfy "
            "Art. 24(1) minimum testing expectations; an active "
            "vulnerability assessment (or TLPT where applicable under "
            "Art. 26) should be scheduled."
        )

    return {
        "tlpt_warranted": tlpt_warranted,
        "tlpt_rationale": tlpt_rationale,
        "next_steps": next_steps,
        "reassessment_timeline": reassessment,
        "art24_minimum_met": art24_minimum_met,
        "art24_note": art24_note,
    }


def _format_url_list(urls: list[str], limit: int = 10) -> list[str]:
    """Return Markdown bullet strings for *urls*, truncating beyond *limit*."""
    lines: list[str] = [f"- {u}" for u in urls[:limit]]
    remaining = len(urls) - limit
    if remaining > 0:
        lines.append(f"- … and {remaining} more")
    return lines


def _summary(
    target: str,
    scan_type: str,
    alerts: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "target": target,
        "scan_type": scan_type,
        "timestamp": dt.datetime.now(dt.timezone.utc).isoformat(),
        "total_alerts": len(alerts),
        "by_severity": _severity_counts(alerts),
    }


# ---------------------------------------------------------------------------
# Shared finding preparation (dedup + enrich + merge)
# ---------------------------------------------------------------------------

def _prepare_findings(
    alerts: list[dict[str, Any]],
    manual_findings: list[dict[str, Any]] | None = None,
) -> tuple[list[dict[str, Any]], bool]:
    """Deduplicate, enrich, and merge automated + manual findings.

    Returns (merged_findings, has_manual).
    """
    deduped = _dedupe_findings(alerts)
    for f in deduped:
        f["dora_article"] = _map_dora_article(f)
        f["is_third_party"] = _is_third_party_finding(f)
        f["source"] = "Automated"
        if "category" not in f:
            f["category"] = f.get("alert", "")

    has_manual = manual_findings is not None and len(manual_findings) > 0
    if has_manual:
        merged = _merge_findings(deduped, manual_findings)
    else:
        merged = deduped

    return merged, has_manual


# --- JSON report ---

def _report_json(
    target: str,
    scan_type: str,
    alerts: list[dict[str, Any]],
    out: pathlib.Path,
    *,
    manual_findings: list[dict[str, Any]] | None = None,
    business_context: dict[str, str] | None = None,
    regulatory_framework: str = "none",
) -> None:
    merged, has_manual = _prepare_findings(alerts, manual_findings)

    report: dict[str, Any] = {
        "summary": _summary(target, scan_type, alerts),
        "alerts": alerts,
        "merged_findings": merged,
    }
    if has_manual:
        report["manual_findings"] = manual_findings
    if regulatory_framework != "none":
        report["regulatory_framework"] = regulatory_framework

    out.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")


def _render_findings_table(deduped: list[dict[str, Any]]) -> list[str]:
    """Lines for the '## Findings Summary' table.

    Extracted from ``_report_md`` so that ``combined_report.py`` can reuse
    the exact same rendering for the automated-findings section.
    """
    lines: list[str] = []
    lines.append("## Findings Summary\n")
    lines.append("| Severity | Finding | Instances | DORA Reference | CWE |")
    lines.append("|----------|---------|-----------|----------------|-----|")
    for f in deduped:
        cwe = f["cweid"] if f["cweid"] else "—"
        lines.append(
            f"| {f['severity']} | {f['alert']} | {f['instance_count']} "
            f"| {f['dora_article']} | {cwe} |"
        )
    lines.append("")
    return lines


def _render_detailed_findings(deduped: list[dict[str, Any]]) -> list[str]:
    """Lines for the per-severity detailed findings sections.

    Extracted from ``_report_md`` so that ``combined_report.py`` can reuse
    the exact same rendering for the automated-findings section.
    """
    lines: list[str] = []
    for sev in ("High", "Medium", "Low", "Informational"):
        group = [f for f in deduped if f["severity"] == sev]
        if not group:
            continue
        lines.append(f"## {sev} ({len(group)})\n")
        for f in group:
            lines.append(f"### {f['alert']}\n")
            lines.append(f"**DORA Reference**: {f['dora_article']}  ")
            lines.append(
                f"\n**Affected URLs ({f['instance_count']})**\n"
            )
            lines.extend(_format_url_list(f["urls"]))
            lines.append("")
            if f["cweid"]:
                lines.append(f"**CWE**: {f['cweid']}  ")
            lines.append(f"\n**Description**\n\n{f['description']}\n")
            lines.append(f"**Solution**\n\n{f['solution']}\n")
            if f.get("is_third_party"):
                lines.append(
                    "**Third-Party Dependency Risk**: Yes "
                    "— see Chapter V section below.\n"
                )
            lines.append("---\n")
    return lines


# ---------------------------------------------------------------------------
# Manual findings loading
# ---------------------------------------------------------------------------

def _load_manual_findings(path: pathlib.Path) -> list[dict[str, Any]]:
    """Load manual findings from a JSON file.

    Each finding object should have: severity, title, category,
    description, affected_component, proof_of_concept, recommendation,
    and optionally business_impact.
    """
    raw = path.read_text(encoding="utf-8")
    data = json.loads(raw)
    if not isinstance(data, list):
        sys.exit(f"ERROR: Manual findings file must contain a JSON array, got {type(data).__name__}")
    findings: list[dict[str, Any]] = []
    for item in data:
        findings.append({
            "severity": item.get("severity", "Informational"),
            "title": item.get("title", "Untitled Finding"),
            "category": item.get("category", "General"),
            "description": item.get("description", ""),
            "affected_component": item.get("affected_component", ""),
            "proof_of_concept": item.get("proof_of_concept", ""),
            "recommendation": item.get("recommendation", ""),
            "business_impact": item.get("business_impact", ""),
            "source": "Manual",
        })
    return findings


# ---------------------------------------------------------------------------
# Business context loading
# ---------------------------------------------------------------------------

def _load_business_context(path: pathlib.Path) -> dict[str, str]:
    """Load category-to-business-impact mapping from a JSON or YAML file.

    Returns a dict mapping category names to impact statement strings.
    """
    raw = path.read_text(encoding="utf-8")
    suffix = path.suffix.lower()
    if suffix in (".yaml", ".yml"):
        if not _HAS_YAML:
            sys.exit(
                "ERROR: PyYAML is required to load YAML business-context files.\n"
                "Install it with:  pip install pyyaml"
            )
        data = _yaml.safe_load(raw)
    else:
        data = json.loads(raw)
    return data.get("category_impacts", {})


# ---------------------------------------------------------------------------
# Findings merge logic
# ---------------------------------------------------------------------------

def _normalize_manual_for_merge(manual_findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Convert manual findings into the same shape as deduped ZAP findings
    so they can be merged into a single list."""
    normalized: list[dict[str, Any]] = []
    for mf in manual_findings:
        normalized.append({
            "alert": mf.get("title", "Untitled Finding"),
            "severity": mf.get("severity", "Informational"),
            "category": mf.get("category", "General"),
            "urls": [mf["affected_component"]] if mf.get("affected_component") else [],
            "instance_count": 1 if mf.get("affected_component") else 0,
            "description": mf.get("description", ""),
            "solution": mf.get("recommendation", ""),
            "cweid": "",
            "wascid": "",
            "reference": "",
            "proof_of_concept": mf.get("proof_of_concept", ""),
            "business_impact": mf.get("business_impact", ""),
            "source": "Manual",
        })
    return normalized


def _merge_findings(
    automated: list[dict[str, Any]],
    manual: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Merge automated and manual findings, deduplicate by title+category,
    and sort by severity."""
    # Tag automated findings
    for f in automated:
        if "source" not in f:
            f["source"] = "Automated"
        if "category" not in f:
            f["category"] = f.get("alert", "")

    # Deduplicate: if same title+category exists in both, keep automated
    seen: set[tuple[str, str]] = set()
    merged: list[dict[str, Any]] = []
    for f in automated:
        key = (f.get("alert", "").lower().strip(), f.get("category", "").lower().strip())
        if key not in seen:
            seen.add(key)
            merged.append(f)

    manual_normalized = _normalize_manual_for_merge(manual)
    for f in manual_normalized:
        key = (f.get("alert", "").lower().strip(), f.get("category", "").lower().strip())
        if key not in seen:
            seen.add(key)
            merged.append(f)

    merged.sort(key=lambda x: (RISK_ORDER.get(x["severity"], 99), x.get("alert", "")))
    return merged


# ---------------------------------------------------------------------------
# Effort estimation
# ---------------------------------------------------------------------------

def _estimate_effort(finding: dict[str, Any]) -> str:
    """Derive effort estimate from solution/recommendation complexity.

    Returns one of: 'Quick Fix', 'Moderate', 'Significant'.
    """
    solution = (finding.get("solution", "") or "").lower()
    # Quick fix indicators
    quick_keywords = [
        "add header", "set header", "configure header", "set flag",
        "set cookie", "add attribute", "enable", "disable",
        "update configuration", "set the", "add the",
    ]
    # Significant effort indicators
    significant_keywords = [
        "redesign", "rewrite", "architecture", "refactor",
        "implement", "migrate", "overhaul", "replace",
    ]
    for kw in quick_keywords:
        if kw in solution:
            return "Quick Fix"
    for kw in significant_keywords:
        if kw in solution:
            return "Significant"
    return "Moderate"


def _estimate_likelihood(finding: dict[str, Any]) -> str:
    """Derive likelihood from severity level.

    Returns one of: 'Confirmed', 'Likely', 'Theoretical'.
    """
    sev = finding.get("severity", "Informational")
    if sev in ("Critical", "High"):
        return "Confirmed"
    elif sev == "Medium":
        return "Likely"
    else:
        return "Theoretical"


# ---------------------------------------------------------------------------
# Section-based report builder — 7 sections
# ---------------------------------------------------------------------------

_SEVERITY_TIERS = ("Critical", "High", "Medium", "Low", "Informational")

_SEVERITY_IMPACT_SUMMARY: dict[str, str] = {
    "Critical": "Immediate threat to system integrity, data confidentiality, or service availability",
    "High": "Significant security weakness that could lead to data breach or service compromise",
    "Medium": "Notable weakness requiring remediation within a defined timeline",
    "Low": "Minor weakness representing a defense-in-depth concern",
    "Informational": "Best practice observation with no direct exploitability",
}


def _section_executive_summary(
    findings: list[dict[str, Any]],
    scan_type: str,
    target: str,
    *,
    has_manual: bool,
    entity_name: str | None = None,
    entity_lei: str | None = None,
    assessor_name: str = "",
    assessment_date: str = "",
    timestamp: str = "",
) -> list[str]:
    """Section 1: Executive Summary."""
    lines: list[str] = []
    lines.append("# Vulnerability Assessment Report\n")

    # Entity info if provided
    if entity_name:
        lines.append(f"- **Entity Name**: {entity_name}")
    if entity_lei:
        lines.append(f"- **LEI / Registration Number**: {entity_lei}")
    lines.append(f"- **Assessment Date**: {assessment_date}")
    lines.append(f"- **Assessor**: {assessor_name}")
    lines.append(f"- **Target URL**: {target}")
    lines.append(f"- **Scan Type**: {scan_type}")
    methodology_parts = ["Automated (OWASP ZAP)"]
    if has_manual:
        methodology_parts.append("Manual Testing")
    lines.append(f"- **Methodology**: {' + '.join(methodology_parts)}")
    if timestamp:
        lines.append(f"- **Report Generated**: {timestamp}")
    lines.append("")

    lines.append("## 1. Executive Summary\n")

    # Severity at-a-glance table
    counts = _severity_counts(findings)
    lines.append("### Vulnerabilities at a Glance\n")
    lines.append("| Severity | Vulnerabilities | Business Impact Summary |")
    lines.append("|----------|----------------|------------------------|")
    for sev in _SEVERITY_TIERS:
        count = counts.get(sev, 0)
        if count > 0:
            # Find the highest-impact finding description in this tier
            tier_findings = [f for f in findings if f["severity"] == sev]
            # Use business_impact if available, otherwise default summary
            impact = _SEVERITY_IMPACT_SUMMARY.get(sev, "")
            for tf in tier_findings:
                if tf.get("business_impact"):
                    impact = tf["business_impact"]
                    break
            lines.append(f"| {sev} | {count} | {impact} |")
    lines.append("")

    # Top priority recommendations
    lines.append("### Priority Recommendations\n")
    priority_findings = [f for f in findings if f["severity"] in ("Critical", "High", "Medium")]
    priority_findings = priority_findings[:5]
    if priority_findings:
        for i, f in enumerate(priority_findings, 1):
            rec = f.get("solution", "") or f.get("recommendation", "") or "Review and remediate"
            # Truncate long recommendations
            if len(rec) > 200:
                rec = rec[:197] + "..."
            lines.append(f"{i}. **{f['alert']}** ({f['severity']}): {rec}")
    else:
        lines.append("No critical or high-priority recommendations at this time.")
    lines.append("")

    return lines


def _section_risk_methodology() -> list[str]:
    """Section 2: Risk Categorization Methodology (static)."""
    lines: list[str] = []
    lines.append("## 2. Risk Categorization Methodology\n")
    lines.append(
        "The following severity definitions are used to categorize findings "
        "in this report.\n"
    )
    lines.append("| Severity | Impact | Likelihood | Data Sensitivity |")
    lines.append("|----------|--------|------------|------------------|")
    lines.append(
        "| Critical | Immediate threat to system integrity, data, or availability "
        "| Actively exploitable "
        "| Sensitive data directly at risk |"
    )
    lines.append(
        "| High | Significant security weakness "
        "| Likely exploitable with moderate effort "
        "| May expose sensitive data |"
    )
    lines.append(
        "| Medium | Notable weakness requiring attention "
        "| Exploitable under specific conditions "
        "| Limited data exposure potential |"
    )
    lines.append(
        "| Low | Minor weakness, defense-in-depth concern "
        "| Difficult to exploit "
        "| Minimal data sensitivity |"
    )
    lines.append(
        "| Informational | Best practice observation "
        "| Not directly exploitable "
        "| No data sensitivity |"
    )
    lines.append("")
    return lines


def _section_technical_findings(
    findings: list[dict[str, Any]],
    business_context: dict[str, str] | None,
) -> list[str]:
    """Section 3: Technical Findings."""
    lines: list[str] = []
    lines.append("## 3. Technical Findings\n")

    if not findings:
        lines.append("No findings to report.\n")
        return lines

    finding_ref = 0
    for sev in _SEVERITY_TIERS:
        group = [f for f in findings if f["severity"] == sev]
        if not group:
            continue
        vword = "vulnerability" if len(group) == 1 else "vulnerabilities"
        lines.append(f"### {sev} — {len(group)} {vword}\n")
        for f in group:
            finding_ref += 1
            ref_id = f"F-{finding_ref:03d}"
            f["_ref_id"] = ref_id
            source_tag = f.get("source", "Automated")
            lines.append(f"#### {ref_id}: {f['alert']} [{source_tag}]\n")

            # Category
            category = f.get("category", f.get("alert", ""))
            if category:
                lines.append(f"**Category**: {category}  ")

            # CWE reference
            cweid = f.get("cweid", "")
            if cweid:
                lines.append(f"**CWE**: CWE-{cweid}  ")

            # Affected component(s)
            if f.get("urls"):
                lines.append(f"\n**Affected Components ({f.get('instance_count', len(f['urls']))}):**\n")
                lines.extend(_format_url_list(f["urls"]))
                lines.append("")
            elif f.get("affected_component"):
                lines.append(f"\n**Affected Component**: {f['affected_component']}  \n")

            # Technical description
            if f.get("description"):
                lines.append(f"**Description**\n\n{f['description']}\n")

            # Business impact
            bi = f.get("business_impact", "")
            if not bi and business_context:
                bi = business_context.get(category, "")
            if not bi:
                bi = "[NEEDS MANUAL INPUT: business impact]"
            lines.append(f"**Business Impact**: {bi}\n")

            # Likelihood
            likelihood = _estimate_likelihood(f)
            lines.append(f"**Likelihood**: {likelihood}  ")

            # Proof of concept
            poc = f.get("proof_of_concept", "")
            if poc:
                lines.append(f"\n**Proof of Concept**\n\n{poc}\n")

            # Recommendation
            solution = f.get("solution", "") or f.get("recommendation", "")
            if solution:
                lines.append(f"**Recommendation**\n\n{solution}\n")

            # Effort estimate
            effort = _estimate_effort(f)
            lines.append(f"**Effort Estimate**: {effort}\n")

            lines.append("---\n")

    return lines


def _section_recommendations(findings: list[dict[str, Any]]) -> list[str]:
    """Section 4: Recommendations Summary."""
    lines: list[str] = []
    lines.append("## 4. Recommendations Summary\n")

    if not findings:
        lines.append("No recommendations to report.\n")
        return lines

    # Build recommendation table
    lines.append("| Priority | Recommendation | Addresses | Target Timeline |")
    lines.append("|----------|---------------|-----------|-----------------|")

    priority = 0
    for f in findings:
        if f["severity"] in ("Critical", "High", "Medium"):
            priority += 1
            rec = f.get("solution", "") or f.get("recommendation", "") or "Review and remediate"
            if len(rec) > 120:
                rec = rec[:117] + "..."
            ref_id = f.get("_ref_id", f["alert"])
            if f["severity"] == "Critical":
                timeline = "Immediate"
            elif f["severity"] == "High":
                timeline = "Within 30 days"
            else:
                timeline = "Within 90 days"
            lines.append(f"| {priority} | {rec} | {ref_id} | {timeline} |")
    lines.append("")

    # Quick Wins
    quick_wins = [f for f in findings if _estimate_effort(f) == "Quick Fix" and f["severity"] in ("Critical", "High", "Medium")]
    if quick_wins:
        lines.append("### Quick Wins\n")
        lines.append("Low-effort, high-impact fixes that should be prioritised:\n")
        for f in quick_wins:
            ref_id = f.get("_ref_id", f["alert"])
            lines.append(f"- **{ref_id}: {f['alert']}** — {f.get('solution', '') or f.get('recommendation', '')}")
        lines.append("")

    # Structural Recommendations
    structural = [f for f in findings if _estimate_effort(f) == "Significant"]
    if structural:
        lines.append("### Structural Recommendations\n")
        lines.append("Architecture or design changes requiring significant effort:\n")
        for f in structural:
            ref_id = f.get("_ref_id", f["alert"])
            lines.append(f"- **{ref_id}: {f['alert']}** — {f.get('solution', '') or f.get('recommendation', '')}")
        lines.append("")

    # Process Recommendations
    lines.append("### Process Recommendations\n")
    lines.append("Policy and process improvements to strengthen the overall security posture:\n")
    lines.append("- Establish a regular vulnerability scanning cadence")
    lines.append("- Implement a security review process for code changes")
    lines.append("- Maintain an up-to-date software inventory and patch management programme")
    if not any(f.get("source") == "Manual" for f in findings):
        lines.append("- Conduct manual penetration testing to complement automated scanning")
    lines.append("")

    return lines


def _section_scope_methodology(
    target: str,
    scan_type: str,
    exclude_urls: list[str] | None,
    has_manual: bool,
) -> list[str]:
    """Section 5: Testing Scope & Methodology (appendix)."""
    lines: list[str] = []
    lines.append("## 5. Testing Scope & Methodology\n")

    # Tools used
    lines.append("### Tools Used\n")
    lines.append("- OWASP ZAP (automated vulnerability scanner)")
    if has_manual:
        lines.append("- Manual testing (findings provided via --manual-findings)")
    lines.append("")

    # Test types performed
    lines.append("### Test Types Performed\n")
    if scan_type == "baseline":
        lines.append("- Passive vulnerability scanning (baseline)")
        lines.append("- Spider/crawler for page discovery")
    elif scan_type == "full":
        lines.append("- Spider/crawler for page discovery")
        lines.append("- Passive vulnerability scanning")
        lines.append("- Active vulnerability scanning")
    elif scan_type == "api":
        lines.append("- OpenAPI/Swagger specification import")
        lines.append("- Passive vulnerability scanning")
        lines.append("- Active vulnerability scanning against defined API endpoints")
    if has_manual:
        lines.append("- Manual business logic and security testing")
    lines.append("")

    # Test types NOT performed
    lines.append("### Test Types Not Performed\n")
    not_performed: list[str] = []
    if scan_type == "baseline":
        not_performed.append("Active vulnerability scanning was not performed (baseline scan only)")
    if not has_manual:
        not_performed.append("Manual business logic testing was not performed")
    if scan_type != "api":
        not_performed.append("API-specific endpoint testing was not performed")
    if not_performed:
        for np in not_performed:
            lines.append(f"- {np}")
    else:
        lines.append("- All standard test types were performed")
    lines.append("")

    # Excluded URLs
    if exclude_urls:
        lines.append("### Excluded URL Patterns\n")
        lines.append("The following URL patterns were excluded from scanning:\n")
        for pattern in exclude_urls:
            lines.append(f"- `{pattern}`")
        lines.append("")

    # Environment tested
    lines.append("### Environment Tested\n")
    lines.append(f"- **Target URL**: {target}")
    lines.append("")

    return lines


# ---------------------------------------------------------------------------
# DORA risk categories for Section 6
# ---------------------------------------------------------------------------

_DORA_RISK_CATEGORIES = {
    "ict_risk_management": {
        "title": "ICT Risk Management (Articles 5-16)",
        "description": "Security configuration, vulnerability management, and ICT risk controls.",
        "keywords": [
            "cookie", "session", "csrf", "cross-site", "xss",
            "content security policy", "csp", "cache", "configuration",
            "security", "vulnerability", "injection", "authentication",
        ],
    },
    "incident_reporting": {
        "title": "Incident Reporting Readiness (Articles 17-23)",
        "description": "Information disclosure, monitoring gaps, and incident detection capabilities.",
        "keywords": [
            "information disclosure", "information leakage", "disclosure",
            "error", "stack trace", "debug", "monitoring", "logging",
            "verbose", "server header", "version",
        ],
    },
    "resilience_testing": {
        "title": "Resilience Testing (Articles 24-27)",
        "description": "Testing coverage, methodology adequacy, and operational resilience.",
        "keywords": [
            "third-party", "third party", "external", "cdn",
            "subresource integrity", "sri", "dependency",
            "availability", "denial", "dos",
        ],
    },
}


def _map_finding_to_dora_category(finding: dict[str, Any]) -> str:
    """Map a finding to a DORA risk category key."""
    text = (
        (finding.get("alert", "") + " " + finding.get("description", ""))
        .lower()
    )
    best_match = "ict_risk_management"  # default
    best_score = 0
    for cat_key, cat_info in _DORA_RISK_CATEGORIES.items():
        score = sum(1 for kw in cat_info["keywords"] if kw in text)
        if score > best_score:
            best_score = score
            best_match = cat_key
    return best_match


def _section_dora_alignment(findings: list[dict[str, Any]]) -> list[str]:
    """Section 6: Regulatory Alignment — DORA (conditional)."""
    lines: list[str] = []
    lines.append("## 6. Regulatory Alignment — DORA\n")

    lines.append(
        "> **Disclaimer**: This section maps findings to DORA's ICT risk "
        "management and digital operational resilience testing requirements "
        "(Articles 24-27) at a high level. This mapping is provided for "
        "informational purposes and does not constitute a formal Threat-Led "
        "Penetration Testing (TLPT) engagement under Article 26, nor a "
        "formal compliance assessment under the DORA regulation.\n"
    )

    # Group findings by DORA category
    categorized: dict[str, list[dict[str, Any]]] = {
        k: [] for k in _DORA_RISK_CATEGORIES
    }
    for f in findings:
        cat = _map_finding_to_dora_category(f)
        categorized[cat].append(f)

    for cat_key, cat_info in _DORA_RISK_CATEGORIES.items():
        cat_findings = categorized.get(cat_key, [])
        lines.append(f"### {cat_info['title']}\n")
        lines.append(f"{cat_info['description']}\n")
        if cat_findings:
            lines.append(f"**{len(cat_findings)} finding(s) mapped to this category:**\n")
            for f in cat_findings:
                sev = f["severity"]
                ref_id = f.get("_ref_id", "")
                ref_str = f" ({ref_id})" if ref_id else ""
                lines.append(f"- [{sev}] {f['alert']}{ref_str}")
            lines.append("")
        else:
            lines.append("No findings mapped to this category.\n")

    return lines


def _section_disclaimer(has_manual: bool) -> list[str]:
    """Section 7: Disclaimer (static)."""
    lines: list[str] = []
    lines.append("## 7. Disclaimer\n")
    lines.append(
        "This vulnerability assessment report represents the findings "
        "identified during the testing period specified above. The results "
        "are based on the information available and the testing methodology "
        "employed at the time of the assessment.\n"
    )
    lines.append(
        "This assessment is not exhaustive. The absence of a finding does "
        "not guarantee the absence of a vulnerability. New vulnerabilities "
        "may emerge after the assessment date due to software updates, "
        "configuration changes, or newly discovered attack vectors.\n"
    )
    if not has_manual:
        lines.append(
            "**Note**: Manual business logic testing was not performed as "
            "part of this assessment. Automated scanning alone cannot detect "
            "all categories of vulnerabilities, particularly those related to "
            "business logic, access control, and authentication flaws. Manual "
            "penetration testing is recommended to complement these findings.\n"
        )
    lines.append(
        "This is an internal assessment. For organisations subject to DORA "
        "regulatory requirements, a formal third-party Threat-Led "
        "Penetration Test (TLPT) under Article 26 is recommended for "
        "comprehensive compliance assurance.\n"
    )
    return lines


# ---------------------------------------------------------------------------
# Report assembler
# ---------------------------------------------------------------------------

def _build_report_sections(
    *,
    findings: list[dict[str, Any]],
    target: str,
    scan_type: str,
    has_manual: bool,
    regulatory_framework: str = "none",
    business_context: dict[str, str] | None = None,
    entity_name: str | None = None,
    entity_lei: str | None = None,
    assessor_name: str = "",
    assessment_date: str = "",
    exclude_urls: list[str] | None = None,
    timestamp: str = "",
) -> list[str]:
    """Assemble all report sections in order, returning Markdown lines."""
    all_lines: list[str] = []

    # Section 1: Executive Summary
    all_lines.extend(_section_executive_summary(
        findings, scan_type, target,
        has_manual=has_manual,
        entity_name=entity_name,
        entity_lei=entity_lei,
        assessor_name=assessor_name,
        assessment_date=assessment_date,
        timestamp=timestamp,
    ))

    # Section 2: Risk Categorization Methodology
    all_lines.extend(_section_risk_methodology())

    # Section 3: Technical Findings
    all_lines.extend(_section_technical_findings(findings, business_context))

    # Section 4: Recommendations Summary
    all_lines.extend(_section_recommendations(findings))

    # Section 5: Testing Scope & Methodology
    all_lines.extend(_section_scope_methodology(
        target, scan_type, exclude_urls, has_manual,
    ))

    # Section 6: DORA Alignment (conditional)
    if regulatory_framework == "dora":
        all_lines.extend(_section_dora_alignment(findings))

    # Section 7: Disclaimer
    all_lines.extend(_section_disclaimer(has_manual))

    return all_lines


# ---------------------------------------------------------------------------
# Report output functions (new section-based)
# ---------------------------------------------------------------------------

# --- Markdown report ---

def _report_md(
    target: str,
    scan_type: str,
    alerts: list[dict[str, Any]],
    out: pathlib.Path,
    *,
    entity_name: str | None = None,
    entity_lei: str | None = None,
    assessor_name: str = "",
    assessment_date: str = "",
    manual_findings: list[dict[str, Any]] | None = None,
    regulatory_framework: str = "none",
    business_context: dict[str, str] | None = None,
    exclude_urls: list[str] | None = None,
) -> None:
    merged, has_manual = _prepare_findings(alerts, manual_findings)
    ts = _summary(target, scan_type, alerts)["timestamp"]

    lines = _build_report_sections(
        findings=merged,
        target=target,
        scan_type=scan_type,
        has_manual=has_manual,
        regulatory_framework=regulatory_framework,
        business_context=business_context,
        entity_name=entity_name,
        entity_lei=entity_lei,
        assessor_name=assessor_name,
        assessment_date=assessment_date,
        exclude_urls=exclude_urls,
        timestamp=ts,
    )

    out.write_text("\n".join(lines), encoding="utf-8")


# --- HTML report ---

_HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Vulnerability Assessment Report</title>
<style>
  body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto,
                 "Helvetica Neue", Arial, sans-serif;
    line-height: 1.6;
    color: #333;
    max-width: 960px;
    margin: 0 auto;
    padding: 2rem;
  }}
  h1 {{ color: #1a1a2e; border-bottom: 2px solid #e94560; padding-bottom: 0.5rem; }}
  h2 {{ color: #16213e; margin-top: 2rem; border-bottom: 1px solid #ddd; padding-bottom: 0.3rem; }}
  h3 {{ color: #0f3460; }}
  h4 {{ color: #333; }}
  table {{
    border-collapse: collapse;
    width: 100%;
    margin: 1rem 0;
  }}
  th, td {{
    border: 1px solid #ddd;
    padding: 8px 12px;
    text-align: left;
  }}
  th {{ background-color: #f4f4f4; font-weight: 600; }}
  tr:nth-child(even) {{ background-color: #fafafa; }}
  blockquote {{
    border-left: 4px solid #e94560;
    margin: 1rem 0;
    padding: 0.5rem 1rem;
    background-color: #fff5f5;
    color: #555;
  }}
  code {{
    background-color: #f4f4f4;
    padding: 2px 6px;
    border-radius: 3px;
    font-size: 0.9em;
  }}
  hr {{ border: none; border-top: 1px solid #eee; margin: 1.5rem 0; }}
  .severity-critical {{ color: #8b0000; font-weight: bold; }}
  .severity-high {{ color: #d32f2f; font-weight: bold; }}
  .severity-medium {{ color: #f57c00; font-weight: bold; }}
  .severity-low {{ color: #1976d2; }}
  .severity-informational {{ color: #757575; }}
</style>
</head>
<body>
{body}
</body>
</html>
"""


def _md_to_html_basic(md_text: str) -> str:
    """Convert basic Markdown to HTML.

    Handles: headers, bold, tables, blockquotes, lists, horizontal rules,
    and code spans. This is intentionally simple — not a full Markdown parser.
    """
    html_lines: list[str] = []
    in_table = False
    in_list = False
    in_blockquote = False

    for line in md_text.split("\n"):
        stripped = line.strip()

        # Blank line — close open blocks
        if not stripped:
            if in_table:
                html_lines.append("</table>")
                in_table = False
            if in_list:
                html_lines.append("</ul>")
                in_list = False
            if in_blockquote:
                html_lines.append("</blockquote>")
                in_blockquote = False
            html_lines.append("")
            continue

        # Horizontal rule
        if stripped == "---":
            if in_table:
                html_lines.append("</table>")
                in_table = False
            html_lines.append("<hr>")
            continue

        # Table separator row — skip
        if re.match(r"^\|[\s\-:|]+\|$", stripped):
            continue

        # Table row
        if stripped.startswith("|") and stripped.endswith("|"):
            cells = [c.strip() for c in stripped.split("|")[1:-1]]
            if not in_table:
                html_lines.append("<table>")
                in_table = True
                # First row is header
                html_lines.append("<tr>" + "".join(f"<th>{_inline_md(c)}</th>" for c in cells) + "</tr>")
            else:
                html_lines.append("<tr>" + "".join(f"<td>{_inline_md(c)}</td>" for c in cells) + "</tr>")
            continue

        # Close table if we left it
        if in_table and not stripped.startswith("|"):
            html_lines.append("</table>")
            in_table = False

        # Headers
        m = re.match(r"^(#{1,6})\s+(.*)", stripped)
        if m:
            level = len(m.group(1))
            text = _inline_md(m.group(2))
            html_lines.append(f"<h{level}>{text}</h{level}>")
            continue

        # Blockquote
        if stripped.startswith(">"):
            text = stripped.lstrip("> ").strip()
            if not in_blockquote:
                html_lines.append("<blockquote>")
                in_blockquote = True
            html_lines.append(f"<p>{_inline_md(text)}</p>")
            continue

        if in_blockquote and not stripped.startswith(">"):
            html_lines.append("</blockquote>")
            in_blockquote = False

        # List items
        if re.match(r"^[\-\*]\s+", stripped):
            text = re.sub(r"^[\-\*]\s+", "", stripped)
            if not in_list:
                html_lines.append("<ul>")
                in_list = True
            html_lines.append(f"<li>{_inline_md(text)}</li>")
            continue

        if re.match(r"^\d+\.\s+", stripped):
            text = re.sub(r"^\d+\.\s+", "", stripped)
            if not in_list:
                html_lines.append("<ul>")
                in_list = True
            html_lines.append(f"<li>{_inline_md(text)}</li>")
            continue

        if in_list and not re.match(r"^[\-\*\d]", stripped):
            html_lines.append("</ul>")
            in_list = False

        # Regular paragraph
        html_lines.append(f"<p>{_inline_md(stripped)}</p>")

    # Close any remaining open blocks
    if in_table:
        html_lines.append("</table>")
    if in_list:
        html_lines.append("</ul>")
    if in_blockquote:
        html_lines.append("</blockquote>")

    return "\n".join(html_lines)


def _inline_md(text: str) -> str:
    """Convert inline Markdown: **bold**, `code`, *italic*."""
    text = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", text)
    text = re.sub(r"`(.+?)`", r"<code>\1</code>", text)
    text = re.sub(r"(?<!\*)\*(?!\*)(.+?)(?<!\*)\*(?!\*)", r"<em>\1</em>", text)
    return text


def _report_html(
    target: str,
    scan_type: str,
    alerts: list[dict[str, Any]],
    out: pathlib.Path,
    *,
    entity_name: str | None = None,
    entity_lei: str | None = None,
    assessor_name: str = "",
    assessment_date: str = "",
    manual_findings: list[dict[str, Any]] | None = None,
    regulatory_framework: str = "none",
    business_context: dict[str, str] | None = None,
    exclude_urls: list[str] | None = None,
) -> None:
    merged, has_manual = _prepare_findings(alerts, manual_findings)
    ts = _summary(target, scan_type, alerts)["timestamp"]

    md_lines = _build_report_sections(
        findings=merged,
        target=target,
        scan_type=scan_type,
        has_manual=has_manual,
        regulatory_framework=regulatory_framework,
        business_context=business_context,
        entity_name=entity_name,
        entity_lei=entity_lei,
        assessor_name=assessor_name,
        assessment_date=assessment_date,
        exclude_urls=exclude_urls,
        timestamp=ts,
    )

    md_text = "\n".join(md_lines)
    html_body = _md_to_html_basic(md_text)
    html = _HTML_TEMPLATE.format(body=html_body)
    out.write_text(html, encoding="utf-8")


# ---------------------------------------------------------------------------
# Scan orchestration
# ---------------------------------------------------------------------------

def run_baseline(zap: Any, target: str, timeout: int) -> list[dict[str, Any]]:
    """Baseline scan: spider (for page discovery) + passive scan only."""
    _new_session(zap)
    _run_spider(zap, target, timeout)
    _run_passive_scan_wait(zap, timeout)
    return _fetch_alerts(zap, target)


def run_full(zap: Any, target: str, timeout: int) -> list[dict[str, Any]]:
    """Full scan: spider → passive scan → active scan."""
    _new_session(zap)
    _run_spider(zap, target, timeout)
    _run_passive_scan_wait(zap, timeout)
    active_ran = _run_active_scan(zap, target, timeout)
    if active_ran:
        _run_passive_scan_wait(zap, timeout)
    return _fetch_alerts(zap, target)


def run_api(
    zap: Any,
    target: str,
    spec_path: pathlib.Path,
    timeout: int,
) -> list[dict[str, Any]]:
    """API scan: import OpenAPI spec → active scan defined endpoints."""
    _new_session(zap)
    _import_openapi(zap, spec_path, target)
    _run_passive_scan_wait(zap, timeout)
    _run_active_scan(zap, target, timeout)
    return _fetch_alerts(zap, target)


# ---------------------------------------------------------------------------
# Dry-run
# ---------------------------------------------------------------------------

def print_dry_run(args: argparse.Namespace, output_path: pathlib.Path) -> None:
    """Print what would happen without actually contacting ZAP."""
    print("\n=== DRY RUN ===\n")
    print(f"  Target       : {args.target}")
    print(f"  ZAP URL      : {args.zap_url}")
    print(f"  Scan type    : {args.scan_type}")
    print(f"  Timeout      : {args.timeout}s")
    print(f"  Report format: {args.report_format}")
    print(f"  Output file  : {output_path}")
    if args.scan_type == "api":
        print(f"  OpenAPI spec : {args.openapi_spec}")
    print()

    steps: list[str] = ["Check ZAP is reachable", "Start new ZAP session"]
    if args.scan_type == "baseline":
        steps += ["Run spider", "Wait for passive scan"]
    elif args.scan_type == "full":
        steps += ["Run spider", "Wait for passive scan", "Run active scan"]
    elif args.scan_type == "api":
        steps += ["Import OpenAPI spec", "Wait for passive scan", "Run active scan"]
    steps += ["Fetch alerts", f"Generate {args.report_format.upper()} report"]

    print("  Steps that would execute:")
    for i, step in enumerate(steps, 1):
        print(f"    {i}. {step}")
    print("\n=== END DRY RUN ===")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    """Entry point."""
    parser = build_parser()
    args = parser.parse_args()
    validate_args(args)
    output_path = resolve_output_path(args)

    if args.dry_run:
        print_dry_run(args, output_path)
        return

    # --- Prerequisites ---
    _check_zaproxy_installed()
    _check_zap_reachable(args.zap_url, args.api_key)

    # --- Interactive confirmation for active scans ---
    if args.scan_type in ("full", "api"):
        interactive_confirm(args.target, args.scan_type)

    zap = _make_zap(args.api_key, args.zap_url)
    _log_scan_event("SCAN_START", args.target, args.scan_type)

    try:
        if args.scan_type == "baseline":
            raw_alerts = run_baseline(zap, args.target, args.timeout)
        elif args.scan_type == "full":
            raw_alerts = run_full(zap, args.target, args.timeout)
        elif args.scan_type == "api":
            assert args.openapi_spec is not None
            raw_alerts = run_api(zap, args.target, args.openapi_spec, args.timeout)
        else:
            sys.exit(f"Unknown scan type: {args.scan_type}")
    except TimeoutError as exc:
        _log_scan_event("SCAN_TIMEOUT", args.target, args.scan_type, extra=str(exc))
        sys.exit(f"ERROR: {exc}")
    except KeyboardInterrupt:
        _log_scan_event("SCAN_INTERRUPTED", args.target, args.scan_type)
        sys.exit("\nScan interrupted by user.")
    except Exception as exc:
        _log_scan_event("SCAN_ERROR", args.target, args.scan_type, extra=str(exc))
        sys.exit(f"ERROR during scan: {exc}")

    _log_scan_event("SCAN_END", args.target, args.scan_type,
                    extra=f"alerts={len(raw_alerts)}")

    # --- Load optional inputs ---
    manual_findings: list[dict[str, Any]] | None = None
    if args.manual_findings:
        manual_findings = _load_manual_findings(args.manual_findings)
        print(f"Loaded {len(manual_findings)} manual finding(s) from {args.manual_findings}")

    business_context: dict[str, str] | None = None
    if args.business_context:
        business_context = _load_business_context(args.business_context)
        print(f"Loaded business context with {len(business_context)} category mapping(s)")

    # --- Report ---
    alerts = _parse_alerts(raw_alerts)

    report_kwargs = dict(
        entity_name=args.entity_name,
        entity_lei=args.entity_lei,
        assessor_name=args.assessor_name,
        assessment_date=args.assessment_date,
        manual_findings=manual_findings,
        regulatory_framework=args.regulatory_framework,
        business_context=business_context,
        exclude_urls=args.exclude_urls,
    )

    if args.report_format == "json":
        _report_json(args.target, args.scan_type, alerts, output_path,
                     manual_findings=manual_findings,
                     business_context=business_context,
                     regulatory_framework=args.regulatory_framework)
    elif args.report_format == "md":
        _report_md(
            args.target,
            args.scan_type,
            alerts,
            output_path,
            **report_kwargs,
        )
    elif args.report_format == "html":
        _report_html(
            args.target,
            args.scan_type,
            alerts,
            output_path,
            **report_kwargs,
        )

    summary = _summary(args.target, args.scan_type, alerts)
    print(f"\nReport written to {output_path}")
    print(f"Total vulnerabilities: {summary['total_alerts']}")
    for sev in ("Critical", "High", "Medium", "Low", "Informational"):
        count = summary["by_severity"].get(sev, 0)
        if count:
            print(f"  {sev}: {count}")


if __name__ == "__main__":
    main()
