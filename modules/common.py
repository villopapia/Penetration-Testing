"""Shared infrastructure for custom security testing modules."""

from __future__ import annotations

import datetime as dt
import getpass
import logging
import pathlib
import sys
import time
import warnings
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


def extract_form_fields(form_element: Any) -> list[dict[str, str]]:
    """Extract input fields from a bs4 form element."""
    fields: list[dict[str, str]] = []
    for inp in form_element.find_all("input"):
        name = inp.get("name", "")
        if not name:
            continue
        fields.append({
            "name": name,
            "type": inp.get("type", "text").lower(),
            "value": inp.get("value", ""),
        })
    return fields


def extract_meta_csrf_token(html: str) -> str | None:
    """Look for <meta name="csrf-token" content="..."> or similar."""
    import re
    soup = parse_html(html)
    for meta in soup.find_all("meta"):
        name = (meta.get("name") or "").lower()
        if name in ("csrf-token", "csrf-param", "csrf_token", "_token"):
            content = meta.get("content", "")
            if content:
                return content
    return None


def find_matching_form(
    html: str, page_url: str, action_url: str, method: str
) -> Any | None:
    """Parse html, return the bs4 <form> element whose resolved action
    equals action_url and whose method matches."""
    soup = parse_html(html)
    for form in soup.find_all("form"):
        form_action = resolve_url(page_url, form.get("action", ""))
        form_method = (form.get("method", "POST")).upper()
        if form_action == action_url and form_method == method.upper():
            return form
    return None


def refresh_form_fields(
    session: Any,
    page_url: str,
    action_url: str,
    method: str,
    timeout: int = 15,
) -> tuple[list[dict[str, str]] | None, str | None]:
    """Re-GET page_url, locate the matching form, return (fresh_fields, meta_csrf_token)."""
    resp, err = fetch_page(session, page_url, timeout=timeout)
    if resp is None:
        return None, None

    form = find_matching_form(resp.text, page_url, action_url, method)
    if form is None:
        return None, None

    fields = extract_form_fields(form)
    meta_token = extract_meta_csrf_token(resp.text)
    return fields, meta_token


def load_lines(path: pathlib.Path) -> list[str]:
    """Read non-empty, non-comment lines from a text file."""
    if not path.is_file():
        warnings.warn(f"Wordlist not found: {path}")
        return []
    lines: list[str] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        stripped = raw.strip()
        if stripped and not stripped.startswith("#"):
            lines.append(stripped)
    return lines


def extract_script_sources(html: str, base_url: str) -> list[dict[str, Any]]:
    """Parse <script src> and <link href> tags, returning structured info."""
    from urllib.parse import urljoin
    soup = parse_html(html)
    resources: list[dict[str, Any]] = []

    for tag in soup.find_all("script", src=True):
        src = tag["src"]
        absolute = resolve_url(base_url, src)
        resources.append({
            "tag": "script",
            "src": absolute,
            "raw_src": src,
            "integrity": tag.get("integrity", ""),
            "crossorigin": tag.get("crossorigin", ""),
        })

    for tag in soup.find_all("link", href=True):
        rel = " ".join(tag.get("rel", []))
        if "stylesheet" not in rel:
            continue
        href = tag["href"]
        absolute = resolve_url(base_url, href)
        resources.append({
            "tag": "link",
            "src": absolute,
            "raw_src": href,
            "integrity": tag.get("integrity", ""),
            "crossorigin": tag.get("crossorigin", ""),
        })

    return resources
