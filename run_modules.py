#!/usr/bin/env python3
"""Unified orchestrator for custom security testing modules.

Runs one or more custom security modules against a target and produces
a vulnerability report compatible with the existing zap_scan.py report
pipeline.  Can run standalone or merge results with a ZAP JSON report.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import getpass
import pathlib
import sys
from typing import Any

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from modules.common import audit_log, interactive_confirm
from modules import auth_test, supply_chain, prompt_injection, ransomware_readiness
from modules import authenticated_scan
from modules import tls_check
from modules import api_discovery

from zap_scan import (
    _parse_alerts,
    _report_md,
    _report_html,
    _report_json,
    _summary,
)

# ---------------------------------------------------------------------------
# Module registry
# ---------------------------------------------------------------------------

ALL_MODULES = ("auth", "supply-chain", "prompt-injection", "ransomware", "authenticated-scan", "tls", "api-discovery")

_ACTIVE_MODULES = {"auth", "prompt-injection", "authenticated-scan"}


def _run_module(
    name: str,
    target: str,
    *,
    confirm: bool,
    timeout: int,
    dry_run: bool,
    extra_args: dict[str, Any],
) -> list[dict[str, Any]]:
    """Dispatch to the named module's run_scan and return raw alerts."""
    if name == "auth":
        return auth_test.run_scan(
            target,
            confirm=confirm,
            attempts=extra_args.get("auth_attempts", 10),
            credential_wordlist=extra_args.get("credential_wordlist"),
            login_path=extra_args.get("login_path"),
            test_username=extra_args.get("test_username"),
            timeout=timeout,
            dry_run=dry_run,
        )
    elif name == "supply-chain":
        return supply_chain.run_scan(
            target,
            check_manifests_flag=extra_args.get("check_manifests", False),
            timeout=timeout,
            dry_run=dry_run,
        )
    elif name == "prompt-injection":
        return prompt_injection.run_scan(
            target,
            confirm=confirm,
            chat_endpoint=extra_args.get("chat_endpoint"),
            timeout=timeout,
            dry_run=dry_run,
        )
    elif name == "ransomware":
        return ransomware_readiness.run_scan(
            target,
            confirm=confirm,
            network_scan=extra_args.get("network_scan", False),
            network_ports=extra_args.get("network_ports"),
            timeout=timeout,
            dry_run=dry_run,
        )
    elif name == "authenticated-scan":
        return authenticated_scan.run_scan(
            target,
            login_url=extra_args.get("auth_login_url"),
            username=extra_args.get("auth_username"),
            password=extra_args.get("auth_password"),
            session_cookie=extra_args.get("session_cookie"),
            auth_header=extra_args.get("auth_header"),
            max_pages=extra_args.get("max_pages", 50),
            probe_access_control=extra_args.get("probe_access_control", False),
            confirm=confirm,
            timeout=timeout,
            dry_run=dry_run,
        )
    elif name == "tls":
        return tls_check.run_scan(
            target,
            timeout=timeout,
            dry_run=dry_run,
        )
    elif name == "api-discovery":
        return api_discovery.run_scan(
            target,
            timeout=timeout,
            dry_run=dry_run,
        )
    else:
        print(f"WARNING: Unknown module '{name}', skipping.")
        return []


def run_selected_modules(
    target: str,
    *,
    modules: list[str] | None = None,
    confirm: bool = False,
    timeout: int = 15,
    dry_run: bool = False,
    extra_args: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Run selected modules and return aggregated raw alerts.

    This is the main programmatic entry point used by assess.py.
    """
    selected = list(ALL_MODULES) if modules is None or "all" in modules else modules
    extras = extra_args or {}
    all_raw: list[dict[str, Any]] = []

    for mod_name in selected:
        if mod_name not in ALL_MODULES:
            print(f"WARNING: Unknown module '{mod_name}', skipping.")
            continue
        print(f"\n{'='*60}")
        print(f"  Module: {mod_name}")
        print(f"{'='*60}\n")
        raw = _run_module(
            mod_name, target,
            confirm=confirm,
            timeout=timeout,
            dry_run=dry_run,
            extra_args=extras,
        )
        all_raw.extend(raw)
        print(f"\n  [{mod_name}] {len(raw)} finding(s)")

    return all_raw


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="run_modules",
        description=(
            "Run custom security testing modules and produce a report "
            "compatible with the DORA Article 24 assessment toolkit."
        ),
    )
    p.add_argument(
        "--target", required=True,
        help="Full URL to test, e.g. https://staging.example.com",
    )
    p.add_argument(
        "--modules", default="all",
        help=(
            "Comma-separated list of modules to run, or 'all'. "
            f"Available: {', '.join(ALL_MODULES)}"
        ),
    )
    p.add_argument(
        "--confirm", action="store_true",
        help="Authorise active tests (auth brute-force, prompt injection, network scan)",
    )
    p.add_argument(
        "--entity-name", default=None,
        help="Name of the regulated entity",
    )
    p.add_argument(
        "--entity-lei", default=None,
        help="LEI or registration number",
    )
    p.add_argument(
        "--assessor-name",
        default=os.environ.get("ZAP_ASSESSOR_NAME", "") or getpass.getuser(),
        help="Name of the assessor (default: current user)",
    )
    p.add_argument(
        "--assessment-date",
        default=dt.date.today().isoformat(),
        help="Assessment date (default: today)",
    )
    p.add_argument(
        "--format", choices=["md", "html", "json"], default="md",
        dest="report_format",
        help="Report output format (default: md)",
    )
    p.add_argument(
        "--output", type=pathlib.Path, default=None,
        help="Output report path (default: auto-generated)",
    )
    p.add_argument(
        "--regulatory-framework", choices=["none", "dora"], default="dora",
        help="Include regulatory alignment section (default: dora)",
    )
    p.add_argument(
        "--merge-zap-report", type=pathlib.Path, default=None,
        help="Path to a ZAP JSON report to merge with module results",
    )
    p.add_argument(
        "--timeout", type=int, default=15,
        help="HTTP request timeout in seconds (default: 15)",
    )
    p.add_argument(
        "--dry-run", action="store_true",
        help="Print what would happen without making requests",
    )
    # Module-specific flags
    p.add_argument("--auth-attempts", type=int, default=10, help="Brute-force attempts for auth module")
    p.add_argument("--login-path", default=None, help="Explicit login path for auth module")
    p.add_argument("--test-username", default=None, help="Username for brute-force test")
    p.add_argument("--check-manifests", action="store_true", help="Enable manifest probing in supply-chain module")
    p.add_argument("--chat-endpoint", default=None, help="Explicit chat endpoint for prompt injection module")
    p.add_argument("--network-scan", action="store_true", help="Enable network port scan in ransomware module")
    # Authenticated-scan flags
    p.add_argument("--auth-login-url", default=None, help="Login page path for authenticated scanning")
    p.add_argument("--auth-username", default=None, help="Username for authenticated scanning")
    p.add_argument("--auth-password", default=None,
                   help="Password for authenticated scanning login. Prefer AUTH_PASSWORD env var.")
    p.add_argument("--session-cookie", default=None, help="Pre-authenticated session cookie (name=value)")
    p.add_argument("--auth-header", default=None, help="Auth header (Header-Name: value)")
    p.add_argument("--max-pages", type=int, default=50, help="Max pages for authenticated crawl")
    p.add_argument("--probe-access-control", action="store_true", help="Enable IDOR/ACL probes")
    return p


def resolve_output(args: argparse.Namespace) -> pathlib.Path:
    if args.output:
        return args.output
    ext = {"md": "md", "html": "html", "json": "json"}
    ts = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    return pathlib.Path(f"modules_report_{ts}.{ext[args.report_format]}")


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    output_path = resolve_output(args)

    selected = args.modules.split(",") if args.modules != "all" else list(ALL_MODULES)

    needs_confirm = any(m in _ACTIVE_MODULES for m in selected) or args.network_scan
    if needs_confirm and not args.confirm and not args.dry_run:
        active_list = [m for m in selected if m in _ACTIVE_MODULES]
        if args.network_scan:
            active_list.append("ransomware (network scan)")
        sys.exit(
            f"ERROR: Module(s) {', '.join(active_list)} perform active tests "
            "and require --confirm.\n"
            "Pass --confirm to authorise active testing."
        )

    extra_args = {
        "auth_attempts": args.auth_attempts,
        "login_path": args.login_path,
        "test_username": args.test_username,
        "check_manifests": args.check_manifests,
        "chat_endpoint": args.chat_endpoint,
        "network_scan": args.network_scan,
        "auth_login_url": args.auth_login_url,
        "auth_username": args.auth_username,
        "auth_password": args.auth_password or os.environ.get("AUTH_PASSWORD", ""),
        "session_cookie": args.session_cookie,
        "auth_header": args.auth_header,
        "max_pages": args.max_pages,
        "probe_access_control": args.probe_access_control,
    }

    # Aggregate module alerts
    raw_alerts = run_selected_modules(
        args.target,
        modules=selected,
        confirm=args.confirm,
        timeout=args.timeout,
        dry_run=args.dry_run,
        extra_args=extra_args,
    )

    # Merge with ZAP report if provided
    if args.merge_zap_report:
        if not args.merge_zap_report.is_file():
            sys.exit(f"ERROR: ZAP report not found: {args.merge_zap_report}")
        zap_data = json.loads(args.merge_zap_report.read_text(encoding="utf-8"))
        zap_raw = zap_data.get("alerts", [])
        print(f"\nMerging {len(zap_raw)} ZAP alert(s) with {len(raw_alerts)} module alert(s)")
        raw_alerts = zap_raw + raw_alerts

    if args.dry_run:
        print("\n[dry-run] No report generated.")
        return

    # Feed through the standard report pipeline
    alerts = _parse_alerts(raw_alerts)
    scan_type = "modules"

    report_kwargs = dict(
        entity_name=args.entity_name,
        entity_lei=args.entity_lei,
        assessor_name=args.assessor_name,
        assessment_date=args.assessment_date,
        regulatory_framework=args.regulatory_framework,
        exclude_urls=None,
        manual_findings=None,
        business_context=None,
        modules_run=selected,
    )

    if args.report_format == "json":
        _report_json(args.target, scan_type, alerts, output_path,
                     regulatory_framework=args.regulatory_framework,
                     modules_run=selected)
    elif args.report_format == "md":
        _report_md(args.target, scan_type, alerts, output_path, **report_kwargs)
    elif args.report_format == "html":
        _report_html(args.target, scan_type, alerts, output_path, **report_kwargs)

    summary = _summary(args.target, scan_type, alerts)
    print(f"\n{'='*60}")
    print(f"  Report written to {output_path}")
    print(f"  Total findings: {summary['total_alerts']}")
    for sev in ("Critical", "High", "Medium", "Low", "Informational"):
        count = summary["by_severity"].get(sev, 0)
        if count:
            print(f"    {sev}: {count}")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
