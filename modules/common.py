"""Shared infrastructure for custom security testing modules."""

from __future__ import annotations

import datetime as dt
import getpass
import logging
import pathlib
import sys
import time
from typing import Any
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup

# Reuse the audit log from zap_scan.py
from zap_scan import _audit, _log_scan_event

RISK_CODE_MAP = {
    "Critical": "4",
    "High": "3",
    "Medium": "2",
    "Low": "1",
    "Informational": "0",
}

logger = logging.getLogger("dora_modules")


def make_alert(
    *,
    risk: str,
    alert_name: str,
    url: str,
    description: str,
    solution: str,
    cweid: str = "",
    wascid: str = "",
    reference: str = "",
    evidence: str = "",
) -> dict[str, Any]:
    """Build a dict matching the exact shape zap_scan._parse_alerts expects.

    Keys match what ZAP's API returns so _parse_alerts can normalize them
    identically.
    """
    risk_code = RISK_CODE_MAP[risk]
    return {
        "riskcode": risk_code,
        "risk": risk,
        "alert": alert_name,
        "name": alert_name,
        "url": url,
        "description": description,
        "solution": solution,
        "cweid": cweid,
        "wascid": wascid,
        "reference": reference,
        "evidence": evidence,
    }


def get_session(timeout: int = 15, verify_tls: bool = True) -> requests.Session:
    """Shared requests.Session with a descriptive User-Agent."""
    s = requests.Session()
    s.headers["User-Agent"] = (
        "DORA-Art24-SecurityAssessment/1.0 "
        "(Authorised Regulatory Assessment Tool)"
    )
    s.verify = verify_tls
    return s


def interactive_confirm(target: str, test_name: str, warning: str) -> None:
    """Require typed 'yes' before active tests. Mirrors zap_scan.interactive_confirm."""
    print(f"\n{'=' * 60}")
    print(f"  Target    : {target}")
    print(f"  Test type : {test_name}")
    print(f"{'=' * 60}")
    print(f"\n{warning}\n")
    answer = input("Type 'yes' to continue: ").strip().lower()
    if answer != "yes":
        sys.exit("Aborted by user.")


def audit_log(event: str, target: str, module: str, *, extra: str = "") -> None:
    """Log to the shared scan_audit.log using zap_scan's format."""
    _log_scan_event(event, target, module, extra=extra)


def print_dry_run(
    module_name: str, target: str, checks: list[str], **meta: Any
) -> None:
    """Print dry-run summary matching zap_scan.print_dry_run style."""
    print(f"\n=== DRY RUN: {module_name} ===\n")
    print(f"  Target: {target}")
    for k, v in meta.items():
        print(f"  {k}: {v}")
    print(f"\n  Checks that would execute:")
    for i, check in enumerate(checks, 1):
        print(f"    {i}. {check}")
    print(f"\n=== END DRY RUN ===")


def fetch_page(
    session: requests.Session, url: str, timeout: int = 15
) -> tuple[requests.Response | None, str]:
    """Fetch a URL, return (response, error_message). Returns (None, msg) on failure."""
    try:
        resp = session.get(url, timeout=timeout, allow_redirects=True)
        return resp, ""
    except requests.RequestException as e:
        return None, str(e)


def parse_html(content: str) -> BeautifulSoup:
    """Parse HTML content with BeautifulSoup."""
    return BeautifulSoup(content, "html.parser")


def is_same_origin(base_url: str, resource_url: str) -> bool:
    """Return True if resource_url shares the same origin as base_url."""
    base = urlparse(base_url)
    resource = urlparse(resource_url)
    if not resource.scheme:
        return True
    return (base.scheme, base.hostname, base.port) == (
        resource.scheme,
        resource.hostname,
        resource.port,
    )


def resolve_url(base_url: str, href: str) -> str:
    """Resolve a potentially relative URL against a base URL."""
    from urllib.parse import urljoin

    return urljoin(base_url, href)
