#!/usr/bin/env python3
"""Single-command DORA compliance assessment.

Runs a full ZAP scan, merges manual findings if provided, and produces
a complete 7-section report with DORA regulatory alignment — all in
one invocation.
"""

from __future__ import annotations

import argparse
import datetime as dt
import getpass
import os
import pathlib
import sys
from typing import Any

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from zap_scan import (
    _check_zaproxy_installed,
    _check_zap_reachable,
    _log_scan_event,
    _make_zap,
    _parse_alerts,
    _summary,
    _load_manual_findings,
    _load_business_context,
    _report_md,
    _report_html,
    _report_json,
    run_full,
)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="assess",
        description=(
            "Run a full DORA Article 24 compliance assessment: "
            "automated ZAP scan + optional manual findings -> single report."
        ),
    )
    p.add_argument(
        "--target",
        required=True,
        help="Full URL to scan, e.g. https://staging.example.com",
    )
    p.add_argument(
        "--entity-name",
        required=True,
        help="Name of the regulated entity being assessed",
    )
    p.add_argument(
        "--entity-lei",
        required=True,
        help="Legal Entity Identifier (LEI) or registration number",
    )
    p.add_argument(
        "--api-key",
        default=os.environ.get("ZAP_API_KEY", ""),
        help="ZAP API key (default: ZAP_API_KEY env var)",
    )
    p.add_argument(
        "--zap-url",
        default="http://localhost:8080",
        help="ZAP base URL (default: http://localhost:8080)",
    )
    p.add_argument(
        "--manual-findings",
        type=pathlib.Path,
        default=None,
        help="Path to JSON file with manual test findings",
    )
    p.add_argument(
        "--business-context",
        type=pathlib.Path,
        default=None,
        help="Path to JSON/YAML file mapping categories to business impact",
    )
    p.add_argument(
        "--assessor-name",
        required=True,
        help="Full name of the person/team performing the assessment",
    )
    p.add_argument(
        "--assessment-date",
        default=dt.date.today().isoformat(),
        help="Assessment date ISO format (default: today)",
    )
    p.add_argument(
        "--output",
        type=pathlib.Path,
        default=None,
        help="Output report path (default: dora_assessment_<timestamp>.md)",
    )
    p.add_argument(
        "--format",
        choices=["md", "html", "json"],
        default="md",
        dest="report_format",
        help="Report format (default: md)",
    )
    p.add_argument(
        "--timeout",
        type=int,
        default=3600,
        help="Max scan duration in seconds (default: 3600)",
    )
    p.add_argument(
        "--exclude-urls",
        nargs="*",
        default=None,
        help="URL patterns excluded from scanning",
    )
    return p


def resolve_output(args: argparse.Namespace) -> pathlib.Path:
    if args.output:
        return args.output
    ext = {"md": "md", "html": "html", "json": "json"}
    ts = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    return pathlib.Path(f"dora_assessment_{ts}.{ext[args.report_format]}")


_PLACEHOLDER_PATTERNS = {
    "company name", "entity name", "your company", "test company",
    "example", "placeholder", "xxx", "tbd", "n/a", "na", "none",
    "lei_number", "lei number", "lei123", "your_lei", "insert",
}


def _looks_like_placeholder(value: str) -> bool:
    return value.strip().lower() in _PLACEHOLDER_PATTERNS


def _validate_inputs(args: argparse.Namespace) -> None:
    """Reject placeholder values that would produce a misleading report."""
    problems: list[str] = []
    if _looks_like_placeholder(args.entity_name):
        problems.append(
            f"--entity-name '{args.entity_name}' looks like a placeholder. "
            "Use the actual registered name of the entity being assessed."
        )
    if _looks_like_placeholder(args.entity_lei):
        problems.append(
            f"--entity-lei '{args.entity_lei}' looks like a placeholder. "
            "Use the entity's real LEI or national registration number."
        )
    if _looks_like_placeholder(args.assessor_name):
        problems.append(
            f"--assessor-name '{args.assessor_name}' looks like a placeholder. "
            "Use your full name or team name."
        )
    if problems:
        sys.exit("ERROR: Report would contain placeholder data.\n  - " + "\n  - ".join(problems))


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    output_path = resolve_output(args)

    _validate_inputs(args)

    if args.manual_findings and not args.manual_findings.is_file():
        sys.exit(f"ERROR: Manual findings file not found: {args.manual_findings}")
    if args.business_context and not args.business_context.is_file():
        sys.exit(f"ERROR: Business context file not found: {args.business_context}")

    # --- Prerequisites ---
    _check_zaproxy_installed()
    _check_zap_reachable(args.zap_url, args.api_key)

    # --- Pre-scan confirmation ---
    print(f"\n{'='*60}")
    print(f"  DORA Article 24 Full Assessment")
    print(f"{'='*60}")
    print(f"  Target      : {args.target}")
    print(f"  Entity      : {args.entity_name}")
    print(f"  LEI         : {args.entity_lei}")
    print(f"  Assessor    : {args.assessor_name}")
    print(f"  Date        : {args.assessment_date}")
    print(f"  Scan type   : full (spider + active scan)")
    print(f"  DORA section: included")
    if args.manual_findings:
        print(f"  Manual finds: {args.manual_findings}")
    print(f"  Output      : {output_path}")
    print(f"{'='*60}")
    print(
        "\nThis will run an active scan sending attack payloads to the target."
        "\nOnly proceed if you have written authorisation to test this target."
        "\n"
    )
    answer = input("Type 'yes' to confirm all details and start: ").strip().lower()
    if answer != "yes":
        sys.exit("Aborted by user.")

    # --- Scan ---
    zap = _make_zap(args.api_key, args.zap_url)
    _log_scan_event("SCAN_START", args.target, "full")

    try:
        raw_alerts = run_full(zap, args.target, args.timeout)
    except TimeoutError as exc:
        _log_scan_event("SCAN_TIMEOUT", args.target, "full", extra=str(exc))
        sys.exit(f"ERROR: {exc}")
    except KeyboardInterrupt:
        _log_scan_event("SCAN_INTERRUPTED", args.target, "full")
        sys.exit("\nScan interrupted by user.")
    except Exception as exc:
        _log_scan_event("SCAN_ERROR", args.target, "full", extra=str(exc))
        sys.exit(f"ERROR during scan: {exc}")

    _log_scan_event("SCAN_END", args.target, "full",
                    extra=f"alerts={len(raw_alerts)}")

    # --- Load optional inputs ---
    manual_findings: list[dict[str, Any]] | None = None
    if args.manual_findings:
        manual_findings = _load_manual_findings(args.manual_findings)
        print(f"Loaded {len(manual_findings)} manual finding(s)")

    business_context: dict[str, str] | None = None
    if args.business_context:
        business_context = _load_business_context(args.business_context)
        print(f"Loaded business context ({len(business_context)} categories)")

    # --- Report ---
    alerts = _parse_alerts(raw_alerts)

    report_kwargs: dict[str, Any] = dict(
        entity_name=args.entity_name,
        entity_lei=args.entity_lei,
        assessor_name=args.assessor_name,
        assessment_date=args.assessment_date,
        manual_findings=manual_findings,
        regulatory_framework="dora",
        business_context=business_context,
        exclude_urls=args.exclude_urls,
    )

    if args.report_format == "json":
        _report_json(args.target, "full", alerts, output_path,
                     manual_findings=manual_findings,
                     business_context=business_context,
                     regulatory_framework="dora")
    elif args.report_format == "md":
        _report_md(args.target, "full", alerts, output_path, **report_kwargs)
    elif args.report_format == "html":
        _report_html(args.target, "full", alerts, output_path,
                     **report_kwargs)

    summary = _summary(args.target, "full", alerts)
    print(f"\nReport written to {output_path}")
    print(f"Total vulnerabilities: {summary['total_alerts']}")
    for sev in ("Critical", "High", "Medium", "Low", "Informational"):
        count = summary["by_severity"].get(sev, 0)
        if count:
            print(f"  {sev}: {count}")


if __name__ == "__main__":
    main()
