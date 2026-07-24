"""Authenticated scanning module.

Logs in to the target, crawls authenticated pages, and optionally probes
for broken access control and IDOR vulnerabilities.
"""

from __future__ import annotations

import argparse
import re
import time
from typing import Any
from urllib.parse import urljoin, urlparse

from modules.common import (
    make_alert,
    get_session,
    interactive_confirm,
    audit_log,
    print_dry_run,
    fetch_page,
    parse_html,
    is_same_origin,
    resolve_url,
    extract_form_fields,
    refresh_form_fields,
    extract_meta_csrf_token,
)
from modules.auth_test import (
    _has_password_field,
    _identify_field,
    _build_form_data,
    _PASSWORD_FIELD_NAMES,
    _USERNAME_FIELD_NAMES,
    _SUCCESS_INDICATORS,
    _response_contains,
)

_MAX_PAGES_CAP = 200
_MAX_IDOR_PROBES = 30

_ID_PATTERN = re.compile(
    r"(/(?:users?|accounts?|orders?|invoices?|documents?|profiles?)/)"
    r"(\d+)\b",
    re.I,
)

# Denial phrases for IDOR probes, split by how specific they are. Tunable per
# assessment since target wording varies; neither list is exhaustive.
#
# STRONG: specific enough that a single match means the probe was denied.
_IDOR_DENIAL_STRONG = (
    "not found", "forbidden", "access denied", "permission denied",
    "you don't have permission", "you do not have permission",
    "unauthorized", "unauthorised", "not authorized", "not authorised",
)
# WEAK: short/generic words that also occur in legitimate page chrome
# (privacy-policy links, T&Cs, unrelated UI labels). A single weak match is
# NOT treated as denial on its own, because doing so would silently drop a
# genuinely leaked IDOR response as a false "denial" (a false negative).
_IDOR_DENIAL_WEAK = (
    "private", "restricted", "no access", "not allowed",
)
# A weak match only counts as a denial when corroborated: either 2+ distinct
# weak phrases appear, or a single weak phrase appears in a small,
# error-page-sized response. Above this size a lone weak word is far more
# likely to be incidental content than a denial notice.
_IDOR_WEAK_BODY_MAX = 500


# ---------------------------------------------------------------------------
# Login
# ---------------------------------------------------------------------------

def login_and_get_session(
    target: str,
    *,
    login_url: str | None = None,
    username: str | None = None,
    password: str | None = None,
    session_cookie: str | None = None,
    auth_header: str | None = None,
    timeout: int = 15,
) -> tuple[Any | None, str]:
    """Returns (authenticated_session_or_None, status_message)."""
    session = get_session(timeout=timeout)

    # Strategy 1: session_cookie
    if session_cookie:
        if "=" in session_cookie:
            parts = session_cookie.split("=", 1)
            session.cookies.set(parts[0].strip(), parts[1].strip())
        else:
            session.headers["Cookie"] = session_cookie

        verify_url = login_url or target
        resp, err = fetch_page(session, verify_url, timeout=timeout)
        if resp is None:
            return None, f"Cookie verification failed: {err}"
        final_path = urlparse(resp.url).path.lower()
        if any(x in final_path for x in ("login", "signin")):
            return None, "Session cookie appears invalid (redirected to login)"
        return session, "Authenticated via session cookie"

    # Strategy 2: auth_header
    if auth_header:
        if ":" in auth_header:
            hdr_name, hdr_val = auth_header.split(":", 1)
            session.headers[hdr_name.strip()] = hdr_val.strip()
        else:
            session.headers["Authorization"] = auth_header

        verify_url = login_url or target
        resp, err = fetch_page(session, verify_url, timeout=timeout)
        if resp is None:
            return None, f"Auth header verification failed: {err}"
        final_path = urlparse(resp.url).path.lower()
        if any(x in final_path for x in ("login", "signin")):
            return None, "Auth header appears invalid (redirected to login)"
        return session, "Authenticated via auth header"

    # Strategy 3: username + password + login_url
    if username and password and login_url:
        full_login_url = urljoin(target.rstrip("/") + "/", login_url.lstrip("/"))
        resp, err = fetch_page(session, full_login_url, timeout=timeout)
        if resp is None:
            return None, f"Failed to fetch login page: {err}"

        soup = parse_html(resp.text)
        login_form = None
        for form in soup.find_all("form"):
            if _has_password_field(form):
                login_form = form
                break

        if login_form is None:
            return None, "No password form found on login page"

        fields = extract_form_fields(login_form)
        pw_field = _identify_field(fields, _PASSWORD_FIELD_NAMES, field_type="password")
        if not pw_field:
            pw_field = _identify_field(fields, _PASSWORD_FIELD_NAMES)
        usr_field = _identify_field(fields, _USERNAME_FIELD_NAMES)

        if not pw_field:
            return None, "Could not identify password field"

        action = resolve_url(full_login_url, login_form.get("action", ""))
        method = (login_form.get("method", "POST")).upper()

        # CSRF-aware submission
        fresh_fields, meta_token = refresh_form_fields(
            session, full_login_url, action, method, timeout=timeout,
        )
        if fresh_fields:
            fields = fresh_fields

        data = _build_form_data(
            fields,
            usr_field or "username",
            pw_field,
            username,
            password,
        )

        extra_headers = {}
        if meta_token:
            extra_headers["X-CSRF-Token"] = meta_token
            extra_headers["X-XSRF-TOKEN"] = meta_token

        try:
            if method == "POST":
                login_resp = session.post(
                    action, data=data, timeout=timeout,
                    allow_redirects=True, headers=extra_headers,
                )
            else:
                login_resp = session.get(
                    action, params=data, timeout=timeout,
                    allow_redirects=True, headers=extra_headers,
                )
        except Exception as exc:
            return None, f"Login request failed: {exc}"

        # Verify success
        login_ok = False
        if _response_contains(login_resp.text, _SUCCESS_INDICATORS):
            login_ok = True
        if not login_ok:
            for cookie in login_resp.cookies:
                if any(tok in cookie.name.lower() for tok in ("session", "auth", "token", "sid")):
                    login_ok = True
                    break

        if login_ok:
            return session, f"Logged in as {username} via form submission"
        return None, "Login attempt did not produce a success indicator (no matching keyword and no new session/auth cookie)"

    return None, "No credentials supplied"


# ---------------------------------------------------------------------------
# Authenticated crawl
# ---------------------------------------------------------------------------

def crawl_authenticated(
    session: Any,
    target: str,
    *,
    seed_paths: list[str] | None = None,
    max_pages: int = 50,
    timeout: int = 15,
) -> list[dict[str, Any]]:
    """Same-origin breadth-first crawl using the authenticated session."""
    max_pages = min(max_pages, _MAX_PAGES_CAP)
    visited: set[str] = set()
    results: list[dict[str, Any]] = []
    queue: list[str] = [target]

    if seed_paths:
        for path in seed_paths:
            queue.append(urljoin(target.rstrip("/") + "/", path.lstrip("/")))

    while queue and len(visited) < max_pages:
        url = queue.pop(0)
        if url in visited:
            continue
        visited.add(url)

        if not is_same_origin(target, url):
            continue

        # Skip logout links
        path_lower = urlparse(url).path.lower()
        if re.search(r"logout|signout", path_lower):
            continue

        resp, err = fetch_page(session, url, timeout=timeout)
        if resp is None:
            continue

        content_type = resp.headers.get("content-type", "")
        if "html" not in content_type.lower() and resp.status_code == 200:
            continue

        soup = parse_html(resp.text)
        title_tag = soup.find("title")
        title = title_tag.get_text().strip() if title_tag else ""

        results.append({
            "url": url,
            "status": resp.status_code,
            "title": title,
        })

        # Extract links
        for a in soup.find_all("a", href=True):
            href = resolve_url(url, a["href"])
            parsed = urlparse(href)
            clean = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            if clean not in visited and is_same_origin(target, clean):
                if not re.search(r"logout|signout", parsed.path.lower()):
                    queue.append(clean)

    return results


# ---------------------------------------------------------------------------
# Access control probes
# ---------------------------------------------------------------------------

def test_horizontal_access_control(
    session: Any,
    unauth_session: Any,
    authenticated_urls: list[dict[str, Any]],
    timeout: int = 15,
) -> list[dict[str, Any]]:
    """Re-request authenticated URLs without auth to detect broken access control."""
    alerts: list[dict[str, Any]] = []

    for page in authenticated_urls:
        url = page["url"]
        try:
            resp = unauth_session.get(url, timeout=timeout, allow_redirects=True)
        except Exception:
            continue

        if resp.status_code != 200:
            continue

        # Skip if it looks like a login page
        if _has_password_field_in_html(resp.text):
            continue

        auth_resp, _ = fetch_page(session, url, timeout=timeout)
        if auth_resp is None:
            continue

        auth_len = len(auth_resp.text)
        unauth_len = len(resp.text)
        length_diff_pct = abs(unauth_len - auth_len) / max(auth_len, 1) * 100
        length_similar = auth_len > 0 and length_diff_pct < 20

        auth_text = _visible_text(auth_resp.text)
        unauth_text = _visible_text(resp.text)
        auth_text_len = len(auth_text)
        unauth_text_len = len(unauth_text)
        text_similar = (
            auth_text_len > 0
            and abs(unauth_text_len - auth_text_len) / max(auth_text_len, 1) < 0.2
        )

        # Visible-text similarity is the sole flag driver: identical substantive
        # content served to both sessions signals broken access control even when
        # raw length diverges due to layout chrome (nav/footer) that differs
        # between logged-in and logged-out views. Raw-length agreement is only a
        # corroborating detail, not a requirement.
        if text_similar:
            if length_similar:
                length_note = (
                    f"raw content length is also similar (auth={auth_len}, "
                    f"unauth={unauth_len}, differs by {length_diff_pct:.0f}%)"
                )
            else:
                length_note = (
                    f"raw content length differs by {length_diff_pct:.0f}% "
                    f"(auth={auth_len}, unauth={unauth_len}), likely due to layout "
                    "chrome (nav/footer) that varies between authenticated and "
                    "unauthenticated views"
                )
            alerts.append(make_alert(
                risk="Medium",
                alert_name="Broken Access Control: Page Accessible Without Authentication",
                url=url,
                description=(
                    f"The authenticated page at {url} is also accessible without "
                    f"authentication. Visible text excluding script/style/nav/footer "
                    f"chrome is similar (auth={auth_text_len}, unauth={unauth_text_len} "
                    f"chars), suggesting the same substantive content is exposed; "
                    f"{length_note}. This is a heuristic match, not a confirmed "
                    "content diff -- manually verify that the unauthenticated "
                    "response actually contains the protected data before treating "
                    "this as confirmed."
                ),
                solution=(
                    "Enforce authentication and authorization checks on all "
                    "protected pages. Verify session state server-side before "
                    "serving content."
                ),
                cweid="284",
                reference="https://cwe.mitre.org/data/definitions/284.html",
                evidence=(
                    f"visible-text chars auth={auth_text_len} unauth={unauth_text_len}; "
                    f"raw bytes auth={auth_len} unauth={unauth_len} "
                    f"(diff {length_diff_pct:.0f}%)"
                ),
            ))

    return alerts


def _visible_text(html: str) -> str:
    """Strip script/style/nav/footer chrome and return normalised visible text."""
    soup = parse_html(html)
    for tag in soup(["script", "style", "nav", "footer", "head"]):
        tag.decompose()
    return " ".join(soup.get_text(separator=" ").split())


def _has_password_field_in_html(html: str) -> bool:
    soup = parse_html(html)
    return bool(soup.find("input", attrs={"type": "password"}))


def _looks_like_denial(body_lower: str, body_len: int) -> bool:
    """Return True if an adjacent-ID response looks like an access denial
    rather than genuinely leaked data.

    Strong phrases count on their own. Weak/generic phrases only count when
    corroborated -- 2+ distinct weak phrases, or one weak phrase in a small
    (error-page-sized) body -- so a leaked page that merely mentions a word
    like "private" or "restricted" in unrelated chrome is not misclassified
    as a denial and dropped.
    """
    if any(p in body_lower for p in _IDOR_DENIAL_STRONG):
        return True
    weak_hits = sum(1 for p in _IDOR_DENIAL_WEAK if p in body_lower)
    if weak_hits >= 2:
        return True
    if weak_hits >= 1 and body_len < _IDOR_WEAK_BODY_MAX:
        return True
    return False


def test_idor_probe(
    session: Any,
    authenticated_urls: list[dict[str, Any]],
    timeout: int = 15,
) -> list[dict[str, Any]]:
    """Test for IDOR by requesting adjacent IDs."""
    alerts: list[dict[str, Any]] = []
    probe_count = 0

    for page in authenticated_urls:
        if probe_count >= _MAX_IDOR_PROBES:
            break

        url = page["url"]
        match = _ID_PATTERN.search(urlparse(url).path)
        if not match:
            continue

        prefix = match.group(1)
        current_id = int(match.group(2))
        path = urlparse(url).path

        for adj_id in (current_id - 1, current_id + 1):
            if adj_id < 0 or adj_id == current_id:
                continue
            if probe_count >= _MAX_IDOR_PROBES:
                break

            adj_path = _ID_PATTERN.sub(f"{prefix}{adj_id}", path)
            adj_url = f"{urlparse(url).scheme}://{urlparse(url).netloc}{adj_path}"

            try:
                resp = session.get(adj_url, timeout=timeout, allow_redirects=True)
                probe_count += 1
            except Exception:
                continue

            time.sleep(1)

            if resp.status_code != 200:
                continue
            body_lower = resp.text.lower()
            if _looks_like_denial(body_lower, len(resp.text)):
                continue
            if len(resp.text) < 200:
                continue

            alerts.append(make_alert(
                risk="Medium",
                alert_name="Potential Insecure Direct Object Reference (IDOR)",
                url=adj_url,
                description=(
                    f"Accessing {adj_url} (adjacent ID to {url}) returned "
                    f"HTTP 200 with {len(resp.text)} bytes of content, and none "
                    "of the known denial phrases were present. This is a "
                    "heuristic match, not a confirmed IDOR: the resource may "
                    "legitimately deny access with different wording, or may be "
                    "intentionally public (e.g. an order-confirmation page). "
                    "Manually verify that this response actually contains "
                    "another user's data before treating it as confirmed."
                ),
                solution=(
                    "Implement proper authorization checks on all endpoints "
                    "that accept user-supplied identifiers. Verify that the "
                    "authenticated user has permission to access the requested "
                    "resource."
                ),
                cweid="639",
                reference="https://cwe.mitre.org/data/definitions/639.html",
            ))

    return alerts


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def run_scan(
    target: str,
    *,
    login_url: str | None = None,
    username: str | None = None,
    password: str | None = None,
    session_cookie: str | None = None,
    auth_header: str | None = None,
    seed_paths: list[str] | None = None,
    max_pages: int = 50,
    probe_access_control: bool = False,
    confirm: bool = False,
    timeout: int = 15,
    dry_run: bool = False,
) -> list[dict[str, Any]]:
    """Orchestrate authenticated scanning."""
    checks = ["Login attempt"]
    has_creds = bool(session_cookie or auth_header or (username and password and login_url))
    if has_creds:
        checks.append("Authenticated page crawl")
    if probe_access_control and confirm:
        checks.append("Horizontal access control testing (active)")
        checks.append("IDOR probe with adjacent IDs (active)")

    if dry_run:
        print_dry_run(
            "authenticated_scan", target, checks,
            login_url=login_url or "(not set)",
            username=username or "(not set)",
            max_pages=max_pages,
            probe_access_control=probe_access_control,
        )
        return []

    audit_log("AUTH_SCAN_START", target, "authenticated_scan")
    alerts: list[dict[str, Any]] = []

    if not has_creds:
        print("[authenticated_scan] No authentication credentials supplied; skipping.")
        return []

    # Login
    print(f"[authenticated_scan] Attempting login to {target} ...")
    auth_session, status = login_and_get_session(
        target,
        login_url=login_url,
        username=username,
        password=password,
        session_cookie=session_cookie,
        auth_header=auth_header,
        timeout=timeout,
    )

    if auth_session is None:
        print(f"[authenticated_scan] Login failed: {status}")
        alerts.append(make_alert(
            risk="Informational",
            alert_name="Authenticated Scanning Skipped - Login Failed",
            url=target,
            description=f"Could not establish an authenticated session: {status}",
            solution="Verify the login credentials and login URL are correct.",
        ))
        audit_log("AUTH_SCAN_LOGIN_FAILED", target, "authenticated_scan", extra=status)
        return alerts

    print(f"[authenticated_scan] {status}")

    # Crawl
    print(f"[authenticated_scan] Crawling authenticated pages (max {max_pages}) ...")
    pages = crawl_authenticated(
        auth_session, target,
        seed_paths=seed_paths,
        max_pages=max_pages,
        timeout=timeout,
    )

    url_list = [p["url"] for p in pages]
    truncated = url_list[:25]
    extra = f"... and {len(url_list) - 25} more" if len(url_list) > 25 else ""
    evidence = "\n".join(truncated)
    if extra:
        evidence += f"\n{extra}"

    alerts.append(make_alert(
        risk="Informational",
        alert_name="Authenticated Attack Surface Discovered",
        url=target,
        description=f"Discovered {len(pages)} authenticated page(s).",
        solution="Review the authenticated attack surface for security issues.",
        evidence=evidence,
    ))
    print(f"[authenticated_scan] Discovered {len(pages)} page(s)")

    # Access control probes
    if probe_access_control and confirm:
        interactive_confirm(
            target,
            "Access Control & IDOR Testing",
            "WARNING: This will test access controls by:\n"
            "  1. Re-requesting authenticated pages without credentials\n"
            "  2. Probing adjacent resource IDs\n\n"
            "This WILL touch other users'/records' data via ID manipulation.\n"
            "Only proceed with authorisation to test business-logic access controls.",
        )

        print("[authenticated_scan] Testing horizontal access control ...")
        unauth = get_session(timeout=timeout)
        alerts.extend(test_horizontal_access_control(
            auth_session, unauth, pages, timeout=timeout,
        ))

        print("[authenticated_scan] Probing for IDOR ...")
        alerts.extend(test_idor_probe(auth_session, pages, timeout=timeout))

    audit_log(
        "AUTH_SCAN_COMPLETE", target, "authenticated_scan",
        extra=f"alerts={len(alerts)} pages={len(pages)}",
    )
    return alerts


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="authenticated_scan",
        description="Authenticated scanning for DORA Article 24 assessments.",
    )
    p.add_argument("--target", required=True, help="Target URL")
    p.add_argument("--auth-login-url", default=None, help="Login page path")
    p.add_argument("--auth-username", default=None, help="Login username")
    p.add_argument("--auth-password", default=None,
                   help="Password for authenticated scanning login. Prefer setting AUTH_PASSWORD env var instead.")
    p.add_argument("--session-cookie", default=None, help="Pre-authenticated session cookie (name=value)")
    p.add_argument("--auth-header", default=None, help="Auth header (Header-Name: value)")
    p.add_argument("--max-pages", type=int, default=50, help="Max pages to crawl (default: 50)")
    p.add_argument("--probe-access-control", action="store_true", help="Enable IDOR/ACL probes")
    p.add_argument("--confirm", action="store_true", help="Authorise active tests")
    p.add_argument("--timeout", type=int, default=15, help="HTTP timeout (default: 15)")
    p.add_argument("--dry-run", action="store_true", help="Print plan without executing")
    return p


def main() -> None:
    import os
    parser = build_parser()
    args = parser.parse_args()

    password = args.auth_password or os.environ.get("AUTH_PASSWORD", "")

    alerts = run_scan(
        args.target,
        login_url=args.auth_login_url,
        username=args.auth_username,
        password=password,
        session_cookie=args.session_cookie,
        auth_header=args.auth_header,
        max_pages=args.max_pages,
        probe_access_control=args.probe_access_control,
        confirm=args.confirm,
        timeout=args.timeout,
        dry_run=args.dry_run,
    )

    if alerts:
        print(f"\n{'='*60}")
        print(f"  {len(alerts)} alert(s) generated")
        print(f"{'='*60}")
        for a in alerts:
            print(f"  [{a['risk']}] {a['alert']}")
    else:
        print("\n[authenticated_scan] No alerts generated.")


if __name__ == "__main__":
    main()
