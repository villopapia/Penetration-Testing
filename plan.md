# Implementation Plan: Combined Automated + Manual DORA Article 24 Assessment

Target files:
- New: `C:\Users\User\Desktop\pen\manual_findings_template.yaml` (generated template)
- New: `C:\Users\User\Desktop\pen\combined_report.py` (combined report generator)
- Reference (read-only, no changes needed): `C:\Users\User\Desktop\pen\zap_scan.py`
- Reference (source of checklist structure): `C:\Users\User\Desktop\pen\manual_pentest_checklist.md`

Scope: build a second CLI script that (a) can emit a blank manual-findings
YAML template derived from the checklist categories, and (b) can merge a
completed ZAP JSON report with a filled-in manual-findings YAML file into one
unified DORA Article 24 Markdown report. `zap_scan.py` is left completely
unmodified except for one small, additive change (documented in §1) so its
JSON output carries everything the combiner needs without re-deriving it.

---

## 0. Architecture decision: new script, not an extension of zap_scan.py

**Decision: create `combined_report.py` as a standalone script that imports
reusable pieces from `zap_scan.py`.**

Rationale:
- `zap_scan.py`'s job is *running a scan against a live ZAP instance*. The
  combined report's job is *merging two already-produced artifacts* (a ZAP
  JSON report file + a manual-findings YAML file) — it never needs to talk
  to ZAP, spider anything, or hold an API key. Bolting this onto `zap_scan.py`
  would mean threading a whole parallel "no-scan, just-merge" code path
  through `main()`, `validate_args()`, and the CLI parser, which muddies a
  currently clean single-purpose tool.
- The regulator's real workflow is two separate moments in time: run the ZAP
  scan today (or reuse an existing report from days ago), then some time
  later (after a tester works through the manual checklist) produce the
  combined report. A separate script models that timing honestly — you don't
  need ZAP running (or even installed) to generate the combined report.
- `zap_scan.py` already writes a clean, stable JSON report shape
  (`_report_json`: `{"summary": {...}, "alerts": [...]}`). That JSON file is
  the natural interchange format between the two scripts — no coupling
  beyond "read this file", which keeps `combined_report.py` decoupled from
  ZAP's live API entirely.
- Import, don't duplicate: `combined_report.py` imports the pure/no-network
  helper functions it needs from `zap_scan.py` (`_parse_alerts` is not
  needed since JSON is already parsed; but `_dedupe_findings`,
  `_map_dora_article`, `_is_third_party_finding`, `_third_party_risk_flags`,
  `_severity_counts`, `RISK_ORDER`, `_format_url_list` are all reused
  as-is). This avoids re-implementing dedup/DORA-mapping/third-party logic
  a second time and guarantees the automated-findings section of the
  combined report is byte-for-byte consistent with what `zap_scan.py`'s own
  standalone Markdown report would say.

### 0.1 Required additive change to `zap_scan.py`

`_report_json()` currently writes only `{"summary": ..., "alerts": ...}`
(raw, non-deduplicated alerts — see line ~642). The combined report needs
the same deduplicated/enriched view that `_report_md` builds internally, so
that automated-side severity counts in the combined verdict match what a
standalone `--format md` run would show. Rather than recompute dedup from
raw alerts inside `combined_report.py` (fine, and actually kept as the
primary path — see §3.1), also **extend `_report_json` to include the
dedup+DORA+third-party-enriched view**, so `combined_report.py` can consume
either the raw or the enriched shape and a human/CI can inspect the JSON
directly:

```python
def _report_json(
    target: str,
    scan_type: str,
    alerts: list[dict[str, Any]],
    out: pathlib.Path,
) -> None:
    deduped = _dedupe_findings(alerts)
    for f in deduped:
        f["dora_article"] = _map_dora_article(f)
        f["is_third_party"] = _is_third_party_finding(f)
    report = {
        "summary": _summary(target, scan_type, alerts),
        "alerts": alerts,
        "deduped_findings": deduped,
    }
    out.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
```

This is additive only (existing keys `summary`/`alerts` unchanged) so it
cannot break any existing consumer of `--format json`. `combined_report.py`
reads `deduped_findings` if present, and falls back to recomputing via
`_dedupe_findings(raw["alerts"])` if an older JSON report (pre-change) is
passed in — see §3.1.

---

## 1. Manual findings template — file structure

### 1.1 Format choice: YAML

YAML over JSON for the tester-facing template: testers hand-edit this file
in a text editor between test sessions, and YAML supports comments
(`#`) directly above each field, which JSON does not. The checklist's
guidance text ("should be long, random, single-use, and time-limited") can
live as an inline comment next to the field the tester fills in, which
halves the chance of a tester leaving a field blank because they forgot what
"good" looks like. `combined_report.py` uses `pyyaml` (already a soft
dependency of `zap_scan.py` for OpenAPI spec parsing, so no new dependency
is introduced).

### 1.2 Template generation command

```
python combined_report.py init-template --output manual_findings.yaml
```

`init-template` is a subcommand (see §4 for full CLI) that writes a
**deterministically generated** template — not a hand-maintained static
file — produced by walking a Python data structure (`CHECKLIST_SCHEMA`,
§1.3) that mirrors `manual_pentest_checklist.md`. Generating it from a
schema (rather than hand-authoring the YAML) means the schema is also the
single source of truth used later for completeness tracking (§5) and
category-level rendering (§3.3) — the template, the "did the tester finish
everything" check, and the report renderer all walk the same list, so they
can never drift out of sync with each other.

### 1.3 `CHECKLIST_SCHEMA` — encodes the 5 testable categories

Placed near the top of `combined_report.py`, after imports:

```python
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
```

This is a direct 1:1 transcription of the checkboxes in
`manual_pentest_checklist.md` sections 1-5 (section 6, "Reporting Format",
is not a test item — it's instructions, and is realized as the per-item
field structure below rather than a schema entry).

### 1.4 Per-item YAML shape (what `init-template` emits)

```yaml
# MANUAL PENTEST FINDINGS — fill in each item below.
# status: one of not_tested | pass | fail | not_applicable
# severity: required if status is "fail" — one of Critical | High | Medium | Low
# Leave status as "not_tested" if you have not yet performed this test —
# the combined report will flag any remaining not_tested items.

meta:
  target: ""                 # e.g. https://staging.example.com
  tester: ""
  test_date: ""               # ISO date, e.g. 2026-07-16
  authorization_reference: "" # ticket/RoE reference confirming written authorization to test

authentication:
  auth_weak_password_policy:
    test: "Weak password policy — trivial passwords rejected on registration/change"
    status: not_tested
    severity: null
    evidence: ""
    steps_to_reproduce: ""
  auth_brute_force_lockout:
    test: "Brute-force / rate limiting — lockout, delay, or CAPTCHA after N failed attempts"
    status: not_tested
    severity: null
    evidence: ""
    steps_to_reproduce: ""
  # ... (one block per item id in that category, same 5 fields each)

access_control:
  ac_horizontal_privesc:
    test: "..."
    status: not_tested
    severity: null
    evidence: ""
    steps_to_reproduce: ""
  # ...

business_logic: { ... }
transaction_payment: { ... }
input_handling: { ... }
```

Field definitions (identical across every item, matching the checklist's
own §6 "Reporting Format" plus the task's explicit field list):

| Field | Type | Allowed values | Notes |
|---|---|---|---|
| `test` | str | — | Pre-filled from schema, read-only by convention (not enforced, but not meant to be edited) |
| `status` | str | `not_tested` \| `pass` \| `fail` \| `not_applicable` | Defaults to `not_tested` in the generated template |
| `severity` | str \| null | `Critical` \| `High` \| `Medium` \| `Low` \| `null` | Must be non-null when `status == "fail"`; validated at load time (§2.2) |
| `evidence` | str | free text | Request/response pair, screenshot reference/path, or notes |
| `steps_to_reproduce` | str | free text | Exact steps/request needed to reproduce a `fail` |

`not_applicable` exists separately from `pass` because e.g. the entire
"Transaction / Payment Logic" category and "Multi-factor auth bypass" item
are conditional in the source checklist ("if applicable" / "if MFA
exists") — marking these `not_applicable` (with a short note in `evidence`
explaining why, e.g. "no payment functionality in this application") keeps
them out of both the "pass" count and the "not tested" completeness
warning, which would otherwise incorrectly flag a false gap.

### 1.5 Template generation function

```python
def build_manual_template(target: str = "") -> dict[str, Any]:
    """Build the nested dict structure for a blank manual-findings file.

    Walks CHECKLIST_SCHEMA and emits one entry per item, all defaulted to
    status="not_tested". Pure function — no I/O — so it's directly
    testable and also reused by --output-format json for init-template.
    """

def write_manual_template(path: pathlib.Path, target: str = "", fmt: str = "yaml") -> None:
    """Render build_manual_template() to *path* as YAML (default) or JSON."""
```

---

## 2. Manual findings loader / validator

### 2.1 Loading

```python
def load_manual_findings(path: pathlib.Path) -> dict[str, Any]:
    """Load and structurally validate a manual-findings YAML/JSON file.

    Accepts either extension; dispatches on suffix (.yaml/.yml -> yaml.safe_load,
    .json -> json.loads). Raises ManualFindingsError on structural problems
    (see _validate_manual_findings) rather than letting a KeyError/TypeError
    propagate from deep inside the renderer later.
    """
```

### 2.2 Validation

```python
class ManualFindingsError(Exception):
    """Raised for structurally invalid manual-findings input."""


_VALID_STATUSES = {"not_tested", "pass", "fail", "not_applicable"}
_VALID_SEVERITIES = {"Critical", "High", "Medium", "Low"}


def _validate_manual_findings(data: dict[str, Any]) -> list[str]:
    """Return a list of validation problem strings (empty list = valid).

    Checks, walking CHECKLIST_SCHEMA as the source of truth:
      - top-level 'meta' key present
      - every category in CHECKLIST_SCHEMA is present as a top-level key
      - every item id under each category is present
      - status is one of _VALID_STATUSES
      - severity is one of _VALID_SEVERITIES when status == "fail"; must be
        null/absent otherwise (a lingering severity on a since-fixed
        "pass" item is a common stale-data bug worth flagging, not fatal —
        emitted as a problem string but does not block report generation,
        see main() handling)
    Does NOT require every item to be status != "not_tested" — that is a
    completeness signal (§5), not a validity error. An assessment with
    remaining not_tested items is valid input; it just isn't COMPLETE.
    """
```

Call site behaviour (in `combined_report.py`'s `main()`): structural
problems (missing category/item, bad enum value) are **fatal** — exit
before generating a report, because the renderer indexes by item id and a
missing key would crash mid-render. The "severity set on a non-fail item"
class of problem is **non-fatal** — printed as a warning to stderr, report
generation proceeds. This mirrors `zap_scan.py`'s existing pattern of
`sys.exit()` for fatal preconditions (see `validate_args`) versus
warnings printed via `print()`.

---

## 3. Combined report data flow

### 3.1 Loading the automated side

```python
def load_zap_report(path: pathlib.Path) -> dict[str, Any]:
    """Load a zap_scan.py JSON report (--format json output).

    Prefers the 'deduped_findings' key (added in zap_scan.py §0.1). If
    absent (older report predating that change), recomputes it by calling
    zap_scan._dedupe_findings() on the raw 'alerts' list and re-applying
    the DORA/third-party enrichment passes, so combined_report.py works
    against both old and new zap_scan.py JSON output.
    """
```

This is the only integration point with a live/prior ZAP run — the
combined report never imports `zapv2` or touches the network. It imports
from `zap_scan`:

```python
from zap_scan import (
    _dedupe_findings,
    _map_dora_article,
    _is_third_party_finding,
    _third_party_risk_flags,
    _severity_counts,
    _format_url_list,
    RISK_ORDER,
)
```

### 3.2 Manual severity counting

Manual findings use a 4-level severity scale (`Critical/High/Medium/Low`)
vs. ZAP's `High/Medium/Low/Informational` — Critical does not exist on the
automated side (ZAP has no concept of it) and Informational does not exist
on the manual side (every manual test is a deliberate pass/fail, not an
"FYI" observation). This mismatch is handled explicitly rather than papered
over:

```python
MANUAL_SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}

def _manual_severity_counts(manual_data: dict[str, Any]) -> dict[str, int]:
    """Count severity across all 'fail' items in manual_data, across all
    categories. Only items with status == 'fail' contribute (pass/
    not_applicable/not_tested have no severity)."""

def _manual_status_counts(manual_data: dict[str, Any]) -> dict[str, dict[str, int]]:
    """Return {category: {status: count}} plus a 'TOTAL' pseudo-category,
    for the coverage map and completeness sections."""
```

### 3.3 Combined verdict — worst-case across both sources

```python
COMBINED_SEVERITY_RANK = {
    "Critical": 0,   # manual-only
    "High": 1,       # both
    "Medium": 2,     # both
    "Low": 3,        # both
    "Informational": 4,  # automated-only
}

def _combined_compliance_verdict(
    automated_counts: dict[str, int],
    manual_counts: dict[str, int],
) -> dict[str, str]:
    """Derive the combined DORA Art. 24 verdict as the worst-case (lowest
    rank number = most severe) across BOTH finding sets, using
    COMBINED_SEVERITY_RANK as the single ordering that spans both scales.

    Rule (evaluated top-down, first match wins):
      - Any manual 'Critical' fail -> "Non-Compliant"
        rationale references the specific manual finding(s).
      - Any automated High OR manual High fail -> "Non-Compliant"
      - Any automated Medium OR manual Medium fail -> "Partially Compliant"
      - Any manual Low fail (automated Low never affects verdict, matching
        existing zap_scan.py behavior where only High/Medium drive verdict)
        -> "Partially Compliant" is NOT triggered by Low alone, to stay
        consistent with the automated-only verdict rule; Low findings are
        listed but do not by themselves move the verdict. This is a
        deliberate consistency choice: the automated verdict function in
        zap_scan.py already ignores Low/Informational for verdict purposes,
        so the combined verdict must not silently become stricter than the
        automated-only verdict for the same class of severity label.
      - Otherwise -> "Compliant"

    Returns:
        {
            "verdict": str,
            "rationale": str,          # cites which side (automated/manual/both) drove the result
            "driven_by": list[str],    # e.g. ["manual: Critical severity IDOR finding", "automated: 2 High-severity findings"]
        }
    """
```

Why worst-case rather than averaging or a weighted score: DORA Article
24(1) testing is about surfacing operational resilience gaps; a
weighted/averaged score could mask a single severe access-control failure
found manually behind a clean automated scan. Worst-case is also the same
philosophy `zap_scan.py` already applies internally (any High finding
forces Non-Compliant regardless of how many Lows exist).

### 3.4 Combined third-party risk flags

Automated side reuses `_third_party_risk_flags()` unchanged (§0). Manual
side has no automatic third-party detector (the checklist doesn't test
third-party JS/CDN inclusion — that's inherently a passive/automated-scan
concern), but the "Mass assignment" and "API-level IDOR" categories can
surface third-party-adjacent risk if the tester notes it in `evidence`
free-text. Rather than attempt keyword-detection on free-text notes
(unreliable), add one optional structured field surfaced only in the
template's category-level comments, kept simple:

- No new schema field. Instead, `combined_report.py`'s Section E (§ below)
  is titled "ICT Third-Party Risk Flags" and is explicitly automated-sourced
  in the combined report, with one trailing note: "Manual testing does not
  independently assess ICT third-party dependencies; see the Automated Scan
  Findings section for third-party flags identified via passive/active
  scanning." This keeps the combined report honest about a genuine
  methodology gap rather than fabricating a manual-side signal.

### 3.5 Combined regulatory recommendations

```python
def _combined_regulatory_recommendations(
    scan_type: str,
    automated_counts: dict[str, int],
    manual_counts: dict[str, int],
    verdict: str,
    completeness: dict[str, Any],   # from §5
) -> dict[str, Any]:
    """Extends zap_scan._regulatory_recommendations with manual-findings
    awareness. Reuses the automated function for the TLPT/reassessment/
    art24-minimum logic (calls zap_scan._regulatory_recommendations
    internally with automated_counts), then layers on:

      - next_steps: prepend remediation items for any manual 'fail' items,
        ordered Critical -> High -> Medium -> Low, each citing the item id
        and category (e.g. "Remediate ac_horizontal_privesc (Access
        Control/IDOR, Critical): <first line of steps_to_reproduce>").
      - If completeness['is_complete'] is False: prepend a next_step
        "Complete outstanding manual test items before this assessment can
        be considered final — see Assessment Completeness section."
      - tlpt_warranted: forced True if any manual Critical/High fail exists,
        regardless of what the automated-only rule would say (a critical
        IDOR or auth bypass is exactly the class of finding Art. 26 TLPT
        exists to pressure-test).
    """
```

---

## 4. `combined_report.py` — CLI interface

Two subcommands (using `argparse` subparsers, unlike `zap_scan.py`'s flat
parser, because the two operations — template generation vs. report
generation — take almost entirely disjoint argument sets):

```
python combined_report.py init-template \
    --output manual_findings.yaml \
    [--format yaml|json]                 # default yaml
    [--target https://staging.example.com]  # pre-fills meta.target

python combined_report.py generate \
    --zap-report zap_report_20260716_101500.json \
    --manual-findings manual_findings.yaml \
    --entity-name "Example Bank Ltd" \
    --entity-lei "5493001KJTIIGC8Y1R12" \
    --assessor-name "J. Doe" \
    --assessment-date 2026-07-16 \
    [--output combined_report_<timestamp>.md] \
    [--format md|json]                   # default md
    [--allow-incomplete]                 # see §6
```

```python
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="combined_report", ...)
    sub = p.add_subparsers(dest="command", required=True)

    p_init = sub.add_parser("init-template", help="Generate a blank manual-findings template")
    p_init.add_argument("--output", type=pathlib.Path, default=pathlib.Path("manual_findings.yaml"))
    p_init.add_argument("--format", choices=["yaml", "json"], default="yaml", dest="template_format")
    p_init.add_argument("--target", default="")

    p_gen = sub.add_parser("generate", help="Merge ZAP + manual findings into one DORA report")
    p_gen.add_argument("--zap-report", type=pathlib.Path, required=True)
    p_gen.add_argument("--manual-findings", type=pathlib.Path, required=True)
    p_gen.add_argument("--entity-name", required=True)
    p_gen.add_argument("--entity-lei", required=True)
    p_gen.add_argument("--assessor-name", default=os.environ.get("ZAP_ASSESSOR_NAME", "") or getpass.getuser())
    p_gen.add_argument("--assessment-date", default=dt.date.today().isoformat())
    p_gen.add_argument("--output", type=pathlib.Path, default=None)
    p_gen.add_argument("--format", choices=["md", "json"], default="md", dest="report_format")
    p_gen.add_argument("--allow-incomplete", action="store_true",
                        help="Generate the report even if manual items remain not_tested "
                             "or only a baseline automated scan was run (report will still "
                             "flag incompleteness prominently; this flag only controls "
                             "whether generation is blocked outright)")
    return p
```

`entity-name`/`entity-lei` are **unconditionally required** in `generate`
(unlike `zap_scan.py` where they're conditional on `--format md`) because
the combined report's entire purpose is regulatory submission — there's no
"just give me raw JSON for internal use" use case that skips entity
identity the way a quick ad-hoc ZAP JSON dump might.

`main()` dispatches on `args.command`:

```python
def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    if args.command == "init-template":
        _cmd_init_template(args)
    elif args.command == "generate":
        _cmd_generate(args)
```

---

## 5. Assessment completeness tracking

### 5.1 What "incomplete" means (two independent dimensions)

```python
def _assess_completeness(
    scan_type: str | None,          # from zap report's summary.scan_type; None if no zap report at all (not supported by CLI, but defensive)
    manual_data: dict[str, Any],
) -> dict[str, Any]:
    """Determine whether this assessment is complete enough to stand alone
    as a regulatory submission, and enumerate exactly what's missing.

    Returns:
        {
            "is_complete": bool,
            "automated_gap": str | None,      # e.g. "Only a baseline (passive) scan was performed; no active scan has been run."
            "manual_not_tested": list[dict],  # [{"id": ..., "category": ..., "test": ...}, ...] for every status == "not_tested" item
            "manual_completion_pct": float,   # (total items - not_tested items) / total items * 100, informational
            "summary_line": str,              # one-line human-readable rollup for the exec summary
        }
    """
```

Logic:
- **Automated gap**: `scan_type == "baseline"` is always flagged as a gap
  (mirrors `zap_scan.py`'s own `art24_minimum_met` logic — a passive-only
  scan does not meet Art. 24(1) minimum expectations). `full`/`api` scans
  are not flagged as an automated gap.
- **Manual gap**: any item across all 5 categories still at
  `status == "not_tested"` is collected into `manual_not_tested`.
  `not_applicable` items are excluded from both the denominator and the gap
  list — they were explicitly assessed as out-of-scope, not skipped.
- `is_complete = (automated_gap is None) and (len(manual_not_tested) == 0)`.

### 5.2 Enforcement in `generate`

```python
def _cmd_generate(args: argparse.Namespace) -> None:
    ...
    completeness = _assess_completeness(zap_summary.get("scan_type"), manual_data)
    if not completeness["is_complete"] and not args.allow_incomplete:
        sys.exit(
            "ERROR: Assessment is incomplete "
            f"({len(completeness['manual_not_tested'])} manual item(s) not_tested"
            + (", automated scan is baseline-only" if completeness["automated_gap"] else "")
            + ").\n"
            "Re-run with --allow-incomplete to generate a draft report anyway "
            "(it will be clearly marked DRAFT / INCOMPLETE)."
        )
    ...
```

This mirrors `zap_scan.py`'s existing `--confirm` gate pattern (block by
default, require an explicit opt-in flag to proceed) — consistent CLI
philosophy across both tools: dangerous/premature actions require an
explicit flag, not a default `yes`.

### 5.3 Report-level rendering of incompleteness

Regardless of `--allow-incomplete`, if `is_complete` is `False`:
- The report's H1 title gets a suffix: `# DORA Article 24 Digital
  Operational Resilience Testing Report — DRAFT (Assessment Incomplete)`
- A prominent callout immediately under the entity header, before the
  executive summary:
  ```
  > **ASSESSMENT INCOMPLETE.** This report reflects a partial assessment
  > and MUST NOT be treated as a final compliance determination.
  > - Automated: <automated_gap text, or "Complete">
  > - Manual: <N> of <total> checklist item(s) not yet tested (see Assessment
  >   Completeness section for the full list).
  ```
- The dedicated "Assessment Completeness" section (§7, new bottom section)
  lists every `not_tested` item by category with its id, so the next
  tester/regulator knows exactly what remains.
- The combined verdict itself is still computed and shown (worst-case over
  whatever *was* tested — §3.3) but is prefixed in the exec summary with
  "Provisional verdict based on partial testing:" instead of "Overall
  Compliance Verdict:" when incomplete, so nobody mistakes a provisional
  read for a final one.

---

## 6. Unified report sections — `_render_combined_report()`

```python
def _render_combined_report(
    *,
    target: str,
    entity_name: str,
    entity_lei: str,
    assessor_name: str,
    assessment_date: str,
    zap_summary: dict[str, Any],
    automated_deduped: list[dict[str, Any]],       # from load_zap_report
    manual_data: dict[str, Any],                    # from load_manual_findings
    out: pathlib.Path,
) -> None:
```

Section order (per the task's requirement, using `##`/`###` exactly as
`zap_scan.py`'s existing `_report_md` does, for visual/structural
consistency between standalone and combined reports):

1. **Entity header + DORA reference** — identical block to
   `zap_scan.py _report_md` Section A, plus two added lines: `**Automated
   Scan Type**: {scan_type}` and `**Manual Testing Coverage**:
   {completion_pct}% of checklist items assessed`. Reused via a shared
   helper `_render_entity_header()` extracted conceptually from
   `zap_scan.py` (duplicated here rather than imported, since it's a
   trivial ~10-line string-building function not worth a cross-module
   import for).

2. **Assessment Incomplete callout** (conditional — only rendered if
   `not completeness["is_complete"]`, placed here per §5.3).

3. **Executive Summary** — covers BOTH sources:
   - Combined verdict (§3.3) headline.
   - Key statistics split into two clearly labeled sub-lists: "Automated
     Scan Findings" (unique findings, instances, by-severity, reusing
     `_severity_counts(automated_deduped)`) and "Manual Test Findings"
     (items tested / passed / failed / not_applicable / not_tested,
     by-severity for fails, reusing `_manual_status_counts` /
     `_manual_severity_counts`).
   - One narrative paragraph synthesizing both, explicitly naming which
     side drove the verdict (uses `verdict["driven_by"]` from §3.3).

4. **Automated Scan Findings** — this is `zap_scan.py`'s existing Sections
   C+D (Findings Summary table + Detailed Findings) reused verbatim by
   calling extracted helper functions `_render_findings_table(deduped)`
   and `_render_detailed_findings(deduped)` (factor these two out of
   `zap_scan.py`'s `_report_md` as standalone functions taking `deduped` +
   returning `list[str]` lines — the only refactor needed inside
   `zap_scan.py` beyond §0.1's JSON change, and it's non-behavior-changing:
   `_report_md` calls them too after the refactor, output is identical).

5. **Manual Test Findings** — new renderer, grouped by
   `CHECKLIST_SCHEMA` category (Authentication, Access Control/IDOR,
   Business Logic, Transaction/Payment, Input Handling) in that fixed
   order:
   ```
   ## Manual Test Findings

   ### Authentication Testing

   | Status | Test | Severity | Notes |
   |--------|------|----------|-------|
   | FAIL | Session fixation ... | High | See detail below |
   | PASS | Weak password policy ... | — | — |
   | NOT TESTED | MFA bypass ... | — | — |

   #### auth_session_fixation — FAIL (High)

   **Steps to Reproduce**

   <steps_to_reproduce text>

   **Evidence**

   <evidence text>

   ---
   ```
   Only `fail` items get the expanded `####` detail block (mirrors
   `zap_scan.py`'s pattern of a summary table + expanded detail sections
   for substantive findings only). `pass`/`not_applicable`/`not_tested`
   stay as single table rows.

6. **Combined Compliance Verdict** — explicit, separate section (not just
   folded into the exec summary) restating `verdict["verdict"]` +
   `verdict["rationale"]` + `verdict["driven_by"]` list, because this is
   the single number a regulator will cite — it deserves its own
   unambiguous, quotable section rather than being buried in prose.

7. **ICT Third-Party Risk Flags** — reuses `zap_scan.py`'s
   `_third_party_risk_flags(automated_deduped)` output rendered the same
   way as the standalone report's Section E, plus the manual-methodology-
   gap note from §3.4.

8. **Regulatory Recommendations** — renders `_combined_regulatory_
   recommendations()` output (§3.5): TLPT, next steps (automated +
   manual-derived, merged and severity-ordered), re-assessment timeline,
   Art. 24 minimum-testing-requirements status.

9. **Coverage Map** — new section, the most novel structural addition.
   Renders a table, statically seeded from the checklist's own coverage
   map (`manual_pentest_checklist.md` lines 66-77) plus a per-manual-item
   "tested?" column pulled from live data:
   ```
   ## Coverage Map

   | Layer | Method | Status |
   |-------|--------|--------|
   | SQLi, XSS, XXE, path traversal, command injection | Automated (ZAP) | Tested — {scan_type} scan |
   | Header/cookie misconfiguration, TLS issues | Automated (ZAP) | Tested — {scan_type} scan |
   | Known-CVE component detection | Automated (ZAP) | Tested — {scan_type} scan |
   | Authentication depth (session, MFA, token handling) | Manual | {N}/{9} items tested |
   | Access Control / IDOR | Manual | {N}/{5} items tested |
   | Business Logic | Manual | {N}/{5} items tested |
   | Transaction / Payment Integrity | Manual | {N}/{4} items tested |
   | Input Handling (business-logic layer) | Manual | {N}/{4} items tested |
   | ICT Third-Party Dependency Cataloguing | Automated (partial) | See Third-Party Risk Flags |
   ```
   Built by a helper `_build_coverage_map(scan_type, manual_data) ->
   list[dict]` that computes the per-category "{N}/{total} tested" strings
   from `_manual_status_counts`, so this table is always live data, never
   hand-copied.

10. **Overall Assessment Completeness** — final section, renders
    `completeness` (§5) in full: automated gap statement (or "None — active
    scan performed"), the full itemized `manual_not_tested` list (id +
    category + test description, so it reads as an actionable to-do list
    for the next testing session), and completion percentage. Ends with an
    explicit machine-and-human-readable status line:
    `**Assessment Status**: {"COMPLETE" if is_complete else "INCOMPLETE — see gaps above"}`

---

## 7. Function inventory (new file `combined_report.py`)

| Function | Purpose |
|---|---|
| `CHECKLIST_SCHEMA` (constant) | Category/item schema, single source of truth (§1.3) |
| `build_manual_template(target)` | Build blank findings dict from schema (§1.5) |
| `write_manual_template(path, target, fmt)` | Serialize template to YAML/JSON (§1.5) |
| `ManualFindingsError` | Exception type for structural validation failures |
| `load_manual_findings(path)` | Load + validate manual YAML/JSON (§2.1) |
| `_validate_manual_findings(data)` | Return list of problem strings (§2.2) |
| `load_zap_report(path)` | Load ZAP JSON, use/derive `deduped_findings` (§3.1) |
| `_manual_severity_counts(manual_data)` | Count fails by severity (§3.2) |
| `_manual_status_counts(manual_data)` | `{category: {status: count}}` + TOTAL (§3.2) |
| `_combined_compliance_verdict(auto_counts, manual_counts)` | Worst-case verdict (§3.3) |
| `_combined_regulatory_recommendations(...)` | Extends automated recs with manual fails (§3.5) |
| `_assess_completeness(scan_type, manual_data)` | Completeness dict (§5.1) |
| `_build_coverage_map(scan_type, manual_data)` | Coverage table rows (§6, item 9) |
| `_render_entity_header(...)` | Section 1 lines |
| `_render_manual_findings(manual_data)` | Section 5 lines |
| `_render_combined_report(...)` | Top-level assembler, writes `out` (§6) |
| `build_parser()` | argparse with `init-template`/`generate` subcommands (§4) |
| `_cmd_init_template(args)` | Handler for `init-template` |
| `_cmd_generate(args)` | Handler for `generate`, including completeness gate (§5.2) |
| `main()` | Dispatch on `args.command` |

### 7.1 Small refactor required inside `zap_scan.py` (non-behavioral)

To satisfy §6 item 4 (reuse, don't duplicate, the findings-table and
detailed-findings rendering), extract two pure functions out of the current
monolithic `_report_md` body:

```python
def _render_findings_table(deduped: list[dict[str, Any]]) -> list[str]:
    """Lines for the '## Findings Summary' table — extracted from
    _report_md's current inline table-building block."""

def _render_detailed_findings(deduped: list[dict[str, Any]]) -> list[str]:
    """Lines for the per-severity detailed findings sections — extracted
    from _report_md's current inline per-severity loop."""
```

`_report_md` is updated to call these two functions and splice their output
into `lines` instead of building the table/detail blocks inline — output is
character-identical to today, verified by a before/after diff of a sample
report during implementation. This is the only behavior-preserving
refactor needed in `zap_scan.py`; everything else in §0.1 is additive.

---

## 8. Worked example (end-to-end CLI flow)

```
# Day 1 — automated baseline already run (per current state):
#   zap_report_20260714_090000.json  already exists

# Day 2 — tester generates a blank manual template:
python combined_report.py init-template \
    --output manual_findings_examplebank.yaml \
    --target https://staging.examplebank.com

# Tester works through the checklist over several sessions, editing
# manual_findings_examplebank.yaml, setting status/severity/evidence per item.

# Day 5 — regulator runs a full active ZAP scan for better automated coverage:
python zap_scan.py --target https://staging.examplebank.com \
    --scan-type full --confirm \
    --format json --output zap_report_20260718.json

# Day 6 — combine, tester has finished 24/27 manual items:
python combined_report.py generate \
    --zap-report zap_report_20260718.json \
    --manual-findings manual_findings_examplebank.yaml \
    --entity-name "Example Bank Ltd" \
    --entity-lei "5493001KJTIIGC8Y1R12" \
    --assessor-name "J. Doe" \
    --output dora_combined_report_examplebank.md
    # --> exits with ERROR (3 items not_tested) unless --allow-incomplete passed

python combined_report.py generate ... --allow-incomplete
    # --> generates dora_combined_report_examplebank.md, marked DRAFT/INCOMPLETE,
    #     verdict computed as provisional, remaining 3 items listed by name
    #     in the Assessment Completeness section.

# Day 9 — tester finishes remaining 3 items, re-run without --allow-incomplete:
python combined_report.py generate ...
    # --> generates final report, no DRAFT marker, verdict is final.
```

---

## 9. Testing considerations

- `build_manual_template()` / `_validate_manual_findings()` are pure
  functions — unit-testable with synthetic dicts, no file I/O or ZAP
  connectivity required.
- Verify `_combined_compliance_verdict` against the matrix of cases: (a)
  automated clean + manual clean → Compliant; (b) automated High + manual
  all-pass → Non-Compliant, `driven_by` cites automated; (c) automated
  clean + manual one Critical fail → Non-Compliant, `driven_by` cites
  manual; (d) automated Medium + manual Low fail → Partially Compliant
  (Medium wins, Low doesn't independently escalate); (e) both sides
  contribute High-equivalent findings → Non-Compliant, `driven_by` lists
  both.
- Verify `_assess_completeness` correctly excludes `not_applicable` items
  from the gap list and percentage denominator, using a fixture with a
  mix of all four statuses across categories.
- Verify `load_zap_report` works against both an old-shape JSON (no
  `deduped_findings` key — falls back to recomputation) and a new-shape
  JSON (uses the key directly) and that both paths produce identical
  `automated_deduped` output for the same underlying alerts.
- Golden-file test: run `_report_md` (unchanged behavior after the §7.1
  refactor) before and after the refactor against a fixed synthetic
  `alerts` fixture and diff the output — must be byte-identical.
- End-to-end smoke test using the `--allow-incomplete` flow in §8 against
  a hand-built small `manual_findings.yaml` (3-4 items) and a small
  synthetic ZAP JSON report, confirming the generated Markdown contains
  all 10 sections from §6 in order.
