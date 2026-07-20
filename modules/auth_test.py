"""Credential and authentication testing module.

Discovers login endpoints on a target and probes for cleartext submission,
weak password policies, default credentials, and missing brute-force
protection.  Passive checks always run; active checks require --confirm.
"""

from __future__ import annotations

import argparse
import logging
import pathlib
import re
import sys
import time
import warnings
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
    extract_form_fields,
    refresh_form_fields,
    extract_meta_csrf_token,
    load_lines,
)

logger = logging.getLogger(__name__)

_PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent
_DEFAULT_LOGIN_PATHS = _PROJECT_ROOT / "wordlists" / "login_paths.txt"
_DEFAULT_CRED_WORDLIST = _PROJECT_ROOT / "wordlists" / "default_credentials.txt"

_MAX_ATTEMPTS_CAP = 50

# Indicators that a login attempt succeeded
_SUCCESS_INDICATORS = (
    "dashboard", "welcome", "logout", "sign out", "signout",
    "my account", "my profile", "control panel",
)

# Indicators that a login attempt failed
_FAILURE_INDICATORS = (
    "invalid", "incorrect", "wrong", "failed", "error",
    "bad credentials", "try again", "denied", "unauthorized",
    "not recognized", "does not match",
)

# Indicators of brute-force protection kicking in
_LOCKOUT_INDICATORS = (
    "locked", "lockout", "too many", "rate limit", "temporarily",
    "blocked", "captcha", "recaptcha", "hcaptcha", "try again later",
    "exceeded", "slow down",
)

# Password fields typically named one of these
_PASSWORD_FIELD_NAMES = ("password", "passwd", "pass", "pwd", "secret")
_USERNAME_FIELD_NAMES = ("username", "user", "login", "email", "userid", "user_id", "account")

_SPA_SHELL_MARKERS = (
    'id="root"', 'id="app"', 'ng-version', 'data-reactroot',
    '__next', 'data-server-rendered', 'ng-app',
)


def _looks_like_spa_shell(html: str) -> bool:
    lower = html.lower()
    return '<form' not in lower and any(m.lower() in lower for m in _SPA_SHELL_MARKERS)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_load_lines = load_lines


def _normalise_url(base: str, action: str) -> str:
    """Resolve a form action URL against the base."""
    if not action:
        return base
    if action.startswith(("http://", "https://")):
        return action
    return urljoin(base, action)


def _has_password_field(form_element: Any) -> bool:
    """Return True if the form contains an <input type="password">."""
    for inp in form_element.find_all("input"):
        if (inp.get("type", "").lower() == "password"):
            return True
    return False


def _extract_form_fields(form_element: Any) -> list[dict[str, str]]:
    """Extract input fields from a form element. Delegates to common."""
    return extract_form_fields(form_element)


def _identify_field(fields: list[dict[str, str]], candidates: tuple[str, ...], field_type: str | None = None) -> str | None:
    """Find the first field whose name matches one of the candidates."""
    for f in fields:
        if field_type and f["type"] != field_type:
            continue
        if f["name"].lower() in candidates:
            return f["name"]
    # Fallback: partial match
    for f in fields:
        if field_type and f["type"] != field_type:
            continue
        for cand in candidates:
            if cand in f["name"].lower():
                return f["name"]
    return None


def _build_form_data(
    fields: list[dict[str, str]],
    username_field: str,
    password_field: str,
    username: str,
    password: str,
) -> dict[str, str]:
    """Build a form POST payload, preserving hidden fields."""
    data: dict[str, str] = {}
    for f in fields:
        if f["name"] == username_field:
            data[f["name"]] = username
        elif f["name"] == password_field:
            data[f["name"]] = password
        elif f["type"] == "hidden":
            data[f["name"]] = f["value"]
    return data


def _response_contains(text: str, indicators: tuple[str, ...]) -> bool:
    lower = text.lower()
    return any(ind in lower for ind in indicators)


# ---------------------------------------------------------------------------
# Check 1: Login Endpoint Discovery
# ---------------------------------------------------------------------------

def discover_login_endpoints(
    session: Any,
    target: str,
    login_paths_file: pathlib.Path | None = None,
    timeout: int = 15,
    *,
    use_browser: bool = False,
) -> list[dict[str, Any]]:
    """Find login forms on the target.

    Returns a list of dicts: {"url", "method", "action", "fields",
    "username_field", "password_field"}.
    """
    from modules.browser_render import is_playwright_available, BrowserUnavailableError

    paths_file = login_paths_file or _DEFAULT_LOGIN_PATHS
    candidate_paths = _load_lines(paths_file)

    endpoints: list[dict[str, Any]] = []
    seen_urls: set[str] = set()
    spa_candidates: list[tuple[str, str]] = []

    def _process_page(url: str, resp_text: str) -> None:
        soup = parse_html(resp_text)
        if soup is None:
            return
        for form in soup.find_all("form"):
            if not _has_password_field(form):
                continue
            action = _normalise_url(url, form.get("action", ""))
            method = (form.get("method", "POST")).upper()
            fields = _extract_form_fields(form)
            password_field = _identify_field(fields, _PASSWORD_FIELD_NAMES, field_type="password")
            if not password_field:
                password_field = _identify_field(fields, _PASSWORD_FIELD_NAMES)
            username_field = _identify_field(fields, _USERNAME_FIELD_NAMES)

            key = (action, method)
            if key in seen_urls:
                continue
            seen_urls.add(key)

            endpoints.append({
                "url": url,
                "method": method,
                "action": action,
                "fields": fields,
                "username_field": username_field,
                "password_field": password_field,
            })

    # Probe candidate paths
    for path in candidate_paths:
        url = urljoin(target.rstrip("/") + "/", path.lstrip("/"))
        resp, err = fetch_page(session, url, timeout=timeout)
        if resp is None:
            continue
        if resp.status_code in (200, 301, 302, 303, 307, 308):
            _process_page(url, resp.text)
            if use_browser and _looks_like_spa_shell(resp.text):
                spa_candidates.append((url, resp.text))

    # Also parse the target root page for login forms
    resp, err = fetch_page(session, target, timeout=timeout)
    if resp is not None and resp.status_code == 200:
        _process_page(target, resp.text)
        if use_browser and _looks_like_spa_shell(resp.text):
            spa_candidates.append((target, resp.text))

    # Browser-based rendering for SPA shells
    if use_browser and spa_candidates:
        if not is_playwright_available():
            print(
                "[auth_test] --use-browser requested but Playwright is not "
                "installed/configured; falling back to static HTML discovery. "
                "Run: pip install playwright && playwright install chromium"
            )
        else:
            try:
                from modules.browser_render import BrowserSession
                with BrowserSession() as browser:
                    for url, _ in spa_candidates:
                        rendered = browser.render(
                            url,
                            wait_for_selector="input[type=password]",
                        )
                        _process_page(url, rendered.html)
            except BrowserUnavailableError as exc:
                print(f"[auth_test] Browser rendering failed: {exc}")
    elif use_browser and not endpoints:
        if is_playwright_available():
            try:
                from modules.browser_render import BrowserSession
                with BrowserSession() as browser:
                    rendered = browser.render(
                        target,
                        wait_for_selector="input[type=password]",
                    )
                    _process_page(target, rendered.html)
            except BrowserUnavailableError as exc:
                print(f"[auth_test] Browser rendering failed: {exc}")
        else:
            print(
                "[auth_test] --use-browser requested but Playwright is not "
                "installed/configured; falling back to static HTML discovery. "
                "Run: pip install playwright && playwright install chromium"
            )

    audit_log("LOGIN_DISCOVERY", target, "auth_test", extra=f"endpoints={len(endpoints)}")
    for ep in endpoints:
        logger.info("  Login form: %s -> %s [%s]", ep["url"], ep["action"], ep["method"])
    return endpoints


_CSRF_FIELD_RE = re.compile(r"csrf|token|_token|authenticity", re.I)


# ---------------------------------------------------------------------------
# Check 1b: CSRF Token Rotation (passive)
# ---------------------------------------------------------------------------

def check_csrf_protection(
    session: Any,
    endpoints: list[dict[str, Any]],
    timeout: int = 15,
) -> list[dict[str, Any]]:
    """Check whether CSRF tokens rotate between fetches (passive, no --confirm)."""
    alerts: list[dict[str, Any]] = []
    for ep in endpoints:
        page_url = ep["url"]
        resp1, err1 = fetch_page(session, page_url, timeout=timeout)
        if resp1 is None:
            continue

        time.sleep(2)
        resp2, err2 = fetch_page(session, page_url, timeout=timeout)
        if resp2 is None:
            continue

        soup1 = parse_html(resp1.text)
        soup2 = parse_html(resp2.text)

        for form1 in soup1.find_all("form"):
            for inp in form1.find_all("input", attrs={"type": "hidden"}):
                name = inp.get("name", "")
                if not _CSRF_FIELD_RE.search(name):
                    continue
                val1 = inp.get("value", "")
                if not val1:
                    continue
                val2 = None
                for form2 in soup2.find_all("form"):
                    inp2 = form2.find("input", attrs={"name": name, "type": "hidden"})
                    if inp2:
                        val2 = inp2.get("value", "")
                        break
                if val2 is not None and val1 == val2:
                    alerts.append(make_alert(
                        risk="Informational",
                        alert_name="Static/Non-Rotating CSRF Token Detected",
                        url=page_url,
                        description=(
                            f"The CSRF token field '{name}' at {page_url} returned "
                            f"identical values across two separate requests. Non-rotating "
                            f"tokens are weaker against replay and fixation attacks."
                        ),
                        solution=(
                            "Implement per-request CSRF token rotation. Each form "
                            "render should produce a unique, unpredictable token "
                            "that is validated and consumed server-side."
                        ),
                        cweid="352",
                        reference="https://cwe.mitre.org/data/definitions/352.html",
                    ))
                    break
            break
    return alerts


# ---------------------------------------------------------------------------
# Check 2: Login Over Cleartext HTTP
# ---------------------------------------------------------------------------

def check_cleartext_login(endpoints: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Flag login forms that submit credentials over HTTP (not HTTPS)."""
    alerts: list[dict[str, Any]] = []
    for ep in endpoints:
        action_url = ep.get("action", ep["url"])
        parsed = urlparse(action_url)
        if parsed.scheme == "http":
            alerts.append(make_alert(
                risk="High",
                alert_name="Login Form Submits Over Cleartext HTTP",
                url=ep["url"],
                description=(
                    f"A login form at {ep['url']} submits credentials to "
                    f"{action_url} over unencrypted HTTP. An attacker on the "
                    "network path can intercept usernames and passwords in "
                    "plaintext via passive eavesdropping or an active "
                    "man-in-the-middle attack."
                ),
                solution=(
                    "Ensure all login form actions use HTTPS. Redirect all "
                    "HTTP traffic to HTTPS and set the HSTS header."
                ),
                cweid="319",
                wascid="4",
                reference="https://cwe.mitre.org/data/definitions/319.html",
            ))
    return alerts


# ---------------------------------------------------------------------------
# Check 3: Password Policy Probe
# ---------------------------------------------------------------------------

_WEAK_PASSWORDS = ("1", "1234", "password", "a")

_REGISTRATION_PATHS = (
    "/register", "/signup", "/sign-up", "/create-account",
    "/account/create", "/user/register", "/join",
)

_PASSWORD_CHANGE_PATHS = (
    "/change-password", "/password/change", "/account/password",
    "/user/password", "/settings/password", "/profile/password",
)


def _find_password_form(
    session: Any,
    target: str,
    paths: tuple[str, ...],
    timeout: int = 15,
) -> dict[str, Any] | None:
    """Look for a registration or password-change form."""
    for path in paths:
        url = urljoin(target.rstrip("/") + "/", path.lstrip("/"))
        resp, err = fetch_page(session, url, timeout=timeout)
        if resp is None or resp.status_code not in (200, 301, 302, 303):
            continue
        soup = parse_html(resp.text)
        if soup is None:
            continue
        for form in soup.find_all("form"):
            if not _has_password_field(form):
                continue
            fields = _extract_form_fields(form)
            pw_field = _identify_field(fields, _PASSWORD_FIELD_NAMES, field_type="password")
            if pw_field:
                action = _normalise_url(url, form.get("action", ""))
                method = form.get("method", "POST").upper()
                return {
                    "url": url,
                    "action": action,
                    "method": method,
                    "fields": fields,
                    "password_field": pw_field,
                }
    return None


def test_password_policy(
    session: Any,
    endpoints: list[dict[str, Any]],
    timeout: int = 15,
) -> list[dict[str, Any]]:
    """Test whether trivially weak passwords are accepted."""
    alerts: list[dict[str, Any]] = []

    # Derive target from the first endpoint
    if not endpoints:
        return alerts
    first_url = endpoints[0]["url"]
    parsed = urlparse(first_url)
    target = f"{parsed.scheme}://{parsed.netloc}"

    # Look for a registration or password-change form
    form = _find_password_form(session, target, _REGISTRATION_PATHS, timeout=timeout)
    if form is None:
        form = _find_password_form(session, target, _PASSWORD_CHANGE_PATHS, timeout=timeout)
    if form is None:
        logger.info("No registration or password-change form found; skipping password policy test")
        return alerts

    accepted: list[str] = []
    for weak_pw in _WEAK_PASSWORDS:
        data: dict[str, str] = {}
        for f in form["fields"]:
            if f["name"] == form["password_field"]:
                data[f["name"]] = weak_pw
            elif f["type"] == "hidden":
                data[f["name"]] = f["value"]
            else:
                # Fill other fields with plausible data
                data[f["name"]] = f"testuser_{int(time.time())}" if "user" in f["name"].lower() or "email" in f["name"].lower() else f["value"]

        try:
            if form["method"] == "POST":
                resp = session.post(form["action"], data=data, timeout=timeout, allow_redirects=True)
            else:
                resp = session.get(form["action"], params=data, timeout=timeout, allow_redirects=True)
        except Exception as exc:
            logger.debug("Password policy probe failed for '%s': %s", weak_pw, exc)
            continue

        body = resp.text.lower()
        # If no error indicators present, the password was probably accepted
        if not _response_contains(body, _FAILURE_INDICATORS):
            accepted.append(weak_pw)

        time.sleep(1)

    if accepted:
        alerts.append(make_alert(
            risk="Medium",
            alert_name="Weak Password Policy Enforcement",
            url=form["url"],
            description=(
                f"The application at {form['url']} accepted trivially weak "
                f"passwords: {', '.join(repr(p) for p in accepted)}. "
                "This indicates the password policy either does not exist or "
                "does not enforce minimum complexity requirements."
            ),
            solution=(
                "Enforce a password policy that requires a minimum length "
                "(at least 8 characters), a mix of character types, and "
                "rejects common/breached passwords. Consider integrating "
                "with a breached-password API such as HIBP."
            ),
            cweid="521",
            reference="https://cwe.mitre.org/data/definitions/521.html",
        ))
    return alerts


# ---------------------------------------------------------------------------
# Check 4: Default/Weak Credential Testing
# ---------------------------------------------------------------------------

def test_default_credentials(
    session: Any,
    endpoints: list[dict[str, Any]],
    wordlist_path: pathlib.Path | None = None,
    timeout: int = 15,
) -> list[dict[str, Any]]:
    """Test a curated list of default credentials against login forms."""
    alerts: list[dict[str, Any]] = []
    wl = wordlist_path or _DEFAULT_CRED_WORDLIST
    cred_lines = _load_lines(wl)
    if not cred_lines:
        logger.warning("No credentials loaded from %s", wl)
        return alerts

    credentials = []
    for line in cred_lines:
        if ":" not in line:
            continue
        user, pw = line.split(":", 1)
        credentials.append((user.strip(), pw.strip()))

    usable_endpoints = [
        ep for ep in endpoints
        if ep.get("username_field") and ep.get("password_field")
    ]
    if not usable_endpoints:
        logger.info("No login forms with identifiable username+password fields; skipping default credential test")
        return alerts

    for ep in usable_endpoints:
        for username, password in credentials:
            data = _build_form_data(
                ep["fields"],
                ep["username_field"],
                ep["password_field"],
                username,
                password,
            )
            try:
                if ep["method"] == "POST":
                    resp = session.post(
                        ep["action"], data=data, timeout=timeout,
                        allow_redirects=True,
                    )
                else:
                    resp = session.get(
                        ep["action"], params=data, timeout=timeout,
                        allow_redirects=True,
                    )
            except Exception as exc:
                logger.debug("Credential test %s:%s failed: %s", username, password, exc)
                time.sleep(1)
                continue

            body = resp.text

            # Check for success indicators
            login_succeeded = False
            if _response_contains(body, _SUCCESS_INDICATORS):
                login_succeeded = True
            # Session cookie set after login
            if not login_succeeded:
                for cookie in resp.cookies:
                    if any(tok in cookie.name.lower() for tok in ("session", "auth", "token", "sid")):
                        login_succeeded = True
                        break
            # Redirect to dashboard-like page
            if not login_succeeded and resp.history:
                final_path = urlparse(resp.url).path.lower()
                if any(p in final_path for p in ("dashboard", "home", "portal", "panel", "admin")):
                    login_succeeded = True

            if login_succeeded:
                alerts.append(make_alert(
                    risk="Critical",
                    alert_name="Default/Weak Credentials Accepted",
                    url=ep["url"],
                    description=(
                        f"The login form at {ep['url']} accepted the default "
                        f"credential pair {username}:{password}. An attacker "
                        "can use these well-known credentials to gain "
                        "unauthorised access to the application."
                    ),
                    solution=(
                        "Change all default credentials immediately. Enforce "
                        "a first-login password change policy. Remove or "
                        "disable default accounts that are not needed. "
                        "Implement account lockout and monitoring."
                    ),
                    cweid="521",
                    reference="https://cwe.mitre.org/data/definitions/521.html",
                ))
                audit_log(
                    "DEFAULT_CRED_ACCEPTED", ep["url"], "auth_test",
                    extra=f"username={username}",
                )
                # One alert per endpoint is enough; move on
                break

            # Rate-limit: 1-2 second delay between attempts
            time.sleep(1.5)

    return alerts


# ---------------------------------------------------------------------------
# Check 5: Brute-Force/Lockout Detection
# ---------------------------------------------------------------------------

def test_brute_force_protection(
    session: Any,
    endpoints: list[dict[str, Any]],
    attempts: int = 10,
    test_username: str | None = None,
    timeout: int = 15,
) -> list[dict[str, Any]]:
    """Submit repeated invalid logins to detect brute-force protections."""
    alerts: list[dict[str, Any]] = []
    attempts = min(attempts, _MAX_ATTEMPTS_CAP)
    username = test_username or "bf_test_user_nonexistent"

    usable_endpoints = [
        ep for ep in endpoints
        if ep.get("username_field") and ep.get("password_field")
    ]
    if not usable_endpoints:
        logger.info("No login forms with identifiable fields; skipping brute-force test")
        return alerts

    for ep in usable_endpoints:
        protection_detected = False
        response_times: list[float] = []

        for i in range(1, attempts + 1):
            fake_password = f"invalid_pw_{i}_{int(time.time())}"
            data = _build_form_data(
                ep["fields"],
                ep["username_field"],
                ep["password_field"],
                username,
                fake_password,
            )

            try:
                start = time.monotonic()
                if ep["method"] == "POST":
                    resp = session.post(
                        ep["action"], data=data, timeout=timeout,
                        allow_redirects=True,
                    )
                else:
                    resp = session.get(
                        ep["action"], params=data, timeout=timeout,
                        allow_redirects=True,
                    )
                elapsed = time.monotonic() - start
                response_times.append(elapsed)
            except Exception as exc:
                logger.debug("Brute-force attempt %d failed: %s", i, exc)
                time.sleep(1)
                continue

            # HTTP 429 Too Many Requests
            if resp.status_code == 429:
                protection_detected = True
                logger.info("Brute-force protection detected: HTTP 429 after %d attempts", i)
                break

            body = resp.text
            if _response_contains(body, _LOCKOUT_INDICATORS):
                protection_detected = True
                logger.info("Brute-force protection detected: lockout indicator after %d attempts", i)
                break

            # Detect increasing response times (possible rate limiting)
            if len(response_times) >= 5:
                recent = response_times[-3:]
                early = response_times[:3]
                avg_recent = sum(recent) / len(recent)
                avg_early = sum(early) / len(early)
                if avg_early > 0 and avg_recent / avg_early > 3.0:
                    protection_detected = True
                    logger.info("Brute-force protection detected: response time increase after %d attempts", i)
                    break

            time.sleep(1)

        if not protection_detected:
            alerts.append(make_alert(
                risk="High",
                alert_name="Missing Brute-Force Protection",
                url=ep["url"],
                description=(
                    f"The login form at {ep['url']} accepted {attempts} "
                    "consecutive failed login attempts for the same username "
                    "without triggering any observable brute-force protection "
                    "mechanism (no account lockout, CAPTCHA, HTTP 429, or "
                    "rate limiting detected)."
                ),
                solution=(
                    "Implement brute-force protection: account lockout after "
                    "a threshold of failed attempts (e.g. 5-10), progressive "
                    "delays, CAPTCHA challenges, or rate limiting (HTTP 429). "
                    "Log and alert on repeated failed authentication attempts."
                ),
                cweid="307",
                reference="https://cwe.mitre.org/data/definitions/307.html",
            ))

    return alerts


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def run_scan(
    target: str,
    *,
    confirm: bool = False,
    attempts: int = 10,
    credential_wordlist: pathlib.Path | None = None,
    login_path: str | None = None,
    test_username: str | None = None,
    timeout: int = 15,
    dry_run: bool = False,
    use_browser: bool = False,
    csrf_aware: bool = True,
    session_override: Any | None = None,
) -> list[dict[str, Any]]:
    """Run the authentication test suite. Returns alerts in zap_scan format."""
    if dry_run:
        checks = [
            "Login endpoint discovery (passive)",
            "Cleartext login check (passive)",
            "CSRF token rotation check (passive)",
        ]
        if use_browser:
            checks.append("JS-rendered login discovery (Playwright)")
        if csrf_aware and confirm:
            checks.append("CSRF token refresh before each active submission (csrf_aware=True)")
        if confirm:
            checks.extend([
                "Password policy probe (active)",
                "Default credential testing (active)",
                f"Brute-force protection test ({attempts} attempts, active)",
            ])
        else:
            checks.append("Active checks skipped (--confirm not set)")
        print_dry_run(
            "auth_test", target, checks,
            attempts=attempts,
            credential_wordlist=str(credential_wordlist or _DEFAULT_CRED_WORDLIST),
            test_username=test_username or "(auto-generated)",
        )
        return []

    attempts = min(attempts, _MAX_ATTEMPTS_CAP)
    session = session_override or get_session()
    all_alerts: list[dict[str, Any]] = []

    # Override login paths file if a single path was given via CLI
    login_paths_file = None
    if login_path:
        pass

    # --- Passive checks (always run) ---
    print(f"[auth_test] Discovering login endpoints on {target} ...")
    endpoints = discover_login_endpoints(session, target, timeout=timeout, use_browser=use_browser)

    # If --login-path was given, also probe that specific path
    if login_path:
        manual_url = urljoin(target.rstrip("/") + "/", login_path.lstrip("/"))
        resp, err = fetch_page(session, manual_url, timeout=timeout)
        if resp is not None and resp.status_code in (200, 301, 302, 303):
            soup = parse_html(resp.text)
            if soup:
                for form in soup.find_all("form"):
                    if _has_password_field(form):
                        fields = _extract_form_fields(form)
                        pw_field = _identify_field(fields, _PASSWORD_FIELD_NAMES, field_type="password")
                        usr_field = _identify_field(fields, _USERNAME_FIELD_NAMES)
                        action = _normalise_url(manual_url, form.get("action", ""))
                        already_found = any(
                            e["action"] == action and e["method"] == form.get("method", "POST").upper()
                            for e in endpoints
                        )
                        if not already_found:
                            endpoints.append({
                                "url": manual_url,
                                "method": form.get("method", "POST").upper(),
                                "action": action,
                                "fields": fields,
                                "username_field": usr_field,
                                "password_field": pw_field,
                            })

    if not endpoints:
        print("[auth_test] No login endpoints discovered.")
        audit_log("NO_LOGIN_ENDPOINTS", target, "auth_test")
        return all_alerts

    print(f"[auth_test] Found {len(endpoints)} login endpoint(s).")

    print("[auth_test] Checking for cleartext HTTP login ...")
    all_alerts.extend(check_cleartext_login(endpoints))

    print("[auth_test] Checking CSRF token rotation ...")
    all_alerts.extend(check_csrf_protection(session, endpoints, timeout=timeout))

    # --- Active checks (require --confirm) ---
    if not confirm:
        print("[auth_test] Active checks skipped (pass --confirm to enable).")
        return all_alerts

    interactive_confirm(
        target,
        "Credential/Auth Active Testing",
        "This will perform active authentication tests:\n"
        "  1. Password policy probe (submits weak passwords)\n"
        "  2. Default credential testing (tries known user:pass pairs)\n"
        f"  3. Brute-force protection test ({attempts} invalid login attempts)\n\n"
        f"  Endpoints under test: {len(endpoints)}\n\n"
        "These tests may lock out accounts or trigger security alerts.\n"
        "Only proceed with explicit authorisation to test this target.",
    )

    # Check 3: Password policy
    print("[auth_test] Testing password policy enforcement ...")
    all_alerts.extend(test_password_policy(session, endpoints, timeout=timeout))

    # Check 4: Default credentials
    print("[auth_test] Testing default/weak credentials (rate-limited) ...")
    all_alerts.extend(test_default_credentials(
        session, endpoints,
        wordlist_path=credential_wordlist,
        timeout=timeout,
    ))

    # Check 5: Brute-force protection
    print(f"[auth_test] Testing brute-force protection ({attempts} attempts) ...")
    all_alerts.extend(test_brute_force_protection(
        session, endpoints,
        attempts=attempts,
        test_username=test_username,
        timeout=timeout,
    ))

    audit_log("AUTH_TEST_COMPLETE", target, "auth_test", extra=f"alerts={len(all_alerts)}")
    return all_alerts


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _build_cli_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="python -m modules.auth_test",
        description="Credential and authentication testing for DORA Article 24 assessments.",
    )
    p.add_argument("--target", required=True, help="Target URL (e.g. https://example.com)")
    p.add_argument("--confirm", action="store_true", help="Enable active tests (password policy, default creds, brute force)")
    p.add_argument("--attempts", type=int, default=10, help="Number of brute-force attempts (default: 10, max: 50)")
    p.add_argument("--login-path", default=None, help="Specific login path to test (e.g. /login)")
    p.add_argument("--credential-wordlist", type=pathlib.Path, default=None, help="Custom credential wordlist (user:pass per line)")
    p.add_argument("--test-username", default=None, help="Username for brute-force test (default: auto-generated)")
    p.add_argument("--timeout", type=int, default=15, help="HTTP request timeout in seconds (default: 15)")
    p.add_argument("--dry-run", action="store_true", help="Show what would run without making requests")
    p.add_argument("--use-browser", action="store_true", help="Use Playwright for JS-rendered login discovery")
    p.add_argument("--no-csrf-aware", action="store_false", dest="csrf_aware",
                   help="Disable CSRF token refresh before each active submission")
    return p


def main() -> None:
    parser = _build_cli_parser()
    args = parser.parse_args()

    if args.attempts > _MAX_ATTEMPTS_CAP:
        print(f"[auth_test] Capping --attempts to {_MAX_ATTEMPTS_CAP} (requested {args.attempts})")
        args.attempts = _MAX_ATTEMPTS_CAP

    alerts = run_scan(
        args.target,
        confirm=args.confirm,
        attempts=args.attempts,
        credential_wordlist=args.credential_wordlist,
        login_path=args.login_path,
        test_username=args.test_username,
        timeout=args.timeout,
        dry_run=args.dry_run,
        use_browser=args.use_browser,
        csrf_aware=args.csrf_aware,
    )

    if alerts:
        print(f"\n{'='*60}")
        print(f"  {len(alerts)} alert(s) generated")
        print(f"{'='*60}\n")
        for a in alerts:
            print(f"  [{a['risk']}] {a['alert']}")
            print(f"    URL: {a['url']}")
            print(f"    CWE: {a.get('cweid', 'N/A')}")
            print()
    else:
        print("\n[auth_test] No alerts generated.")


if __name__ == "__main__":
    main()
