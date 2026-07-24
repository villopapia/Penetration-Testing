"""Tests for modules.auth_test."""
from __future__ import annotations

import pytest
import requests
from tests.conftest import FakeResponse, FakeSession, SAMPLE_LOGIN_HTML

from modules.auth_test import (
    discover_login_endpoints,
    check_cleartext_login,
    _identify_field,
    _build_form_data,
    _extract_form_fields,
    run_scan,
)
from modules.common import parse_html


# HTML with two forms: a search form FIRST (no CSRF field) followed by a login
# form that carries a static CSRF token. Exercises fix #1 -- before the fix, the
# unconditional outer `break` stopped after the first (CSRF-less) form and the
# login form's static token was never checked.
MULTI_FORM_STATIC_CSRF_HTML = """\
<!DOCTYPE html>
<html><head><title>Home</title></head>
<body>
<form method="GET" action="/search">
  <input type="text" name="q">
  <button type="submit">Search</button>
</form>
<form method="POST" action="/auth/login">
  <input type="hidden" name="csrf_token" value="static-tok-123">
  <input type="text" name="username">
  <input type="password" name="password">
  <button type="submit">Log In</button>
</form>
</body></html>
"""


class SequencedSession(FakeSession):
    """FakeSession that returns/raises a preset sequence of items in order.

    Each item is either a FakeResponse (returned) or an Exception instance
    (raised). Once the sequence is exhausted, the last item repeats.
    """

    def __init__(self, sequence):
        super().__init__({})
        self._seq = list(sequence)
        self._idx = 0

    def _next(self, method, url, kwargs):
        self.call_log.append({"method": method, "url": url, "kwargs": kwargs})
        item = self._seq[self._idx] if self._idx < len(self._seq) else self._seq[-1]
        self._idx += 1
        if isinstance(item, BaseException):
            raise item
        return item

    def post(self, url, **kwargs):
        return self._next("POST", url, kwargs)

    def get(self, url, **kwargs):
        return self._next("GET", url, kwargs)


def _bf_endpoint():
    """A login endpoint usable by test_brute_force_protection."""
    return {
        "url": "https://example.com/login",
        "action": "https://example.com/auth/login",
        "method": "POST",
        "fields": [
            {"name": "username", "type": "text", "value": ""},
            {"name": "password", "type": "password", "value": ""},
        ],
        "username_field": "username",
        "password_field": "password",
    }


class TestDiscoverLoginEndpoints:
    def test_finds_login_form(self, sample_login_html):
        session = FakeSession({
            "example.com": FakeResponse(200, sample_login_html),
        })
        eps = discover_login_endpoints(session, "https://example.com", timeout=5)
        assert len(eps) >= 1
        ep = eps[0]
        assert ep["password_field"] == "password"
        assert ep["username_field"] == "username"

    def test_no_forms(self):
        session = FakeSession({
            "example.com": FakeResponse(200, "<html><body>No forms</body></html>"),
        })
        eps = discover_login_endpoints(session, "https://example.com", timeout=5)
        assert eps == []


class TestCheckCleartextLogin:
    def test_flags_http_action(self):
        endpoints = [{"url": "http://x.com/login", "action": "http://x.com/auth", "method": "POST"}]
        alerts = check_cleartext_login(endpoints)
        assert len(alerts) == 1
        assert alerts[0]["risk"] == "High"

    def test_no_alert_for_https(self):
        endpoints = [{"url": "https://x.com/login", "action": "https://x.com/auth", "method": "POST"}]
        alerts = check_cleartext_login(endpoints)
        assert alerts == []


class TestIdentifyField:
    def test_exact_match(self):
        fields = [
            {"name": "username", "type": "text", "value": ""},
            {"name": "password", "type": "password", "value": ""},
        ]
        assert _identify_field(fields, ("password",), field_type="password") == "password"

    def test_partial_match(self):
        fields = [{"name": "user_email", "type": "text", "value": ""}]
        assert _identify_field(fields, ("email",)) == "user_email"

    def test_no_match(self):
        fields = [{"name": "foo", "type": "text", "value": ""}]
        assert _identify_field(fields, ("bar",)) is None


class TestBuildFormData:
    def test_preserves_hidden_fields(self):
        fields = [
            {"name": "csrf_token", "type": "hidden", "value": "tok"},
            {"name": "username", "type": "text", "value": ""},
            {"name": "password", "type": "password", "value": ""},
        ]
        data = _build_form_data(fields, "username", "password", "admin", "pass123")
        assert data["csrf_token"] == "tok"
        assert data["username"] == "admin"
        assert data["password"] == "pass123"


class TestCheckCsrfProtection:
    def test_static_token_flagged(self, monkeypatch):
        """When both GETs return the same CSRF token value, an alert is raised."""
        from modules.auth_test import check_csrf_protection
        import modules.auth_test as at
        monkeypatch.setattr(at.time, "sleep", lambda _: None)

        # Same token in both responses -> "Static CSRF Token"
        session = FakeSession({
            "example.com": FakeResponse(200, SAMPLE_LOGIN_HTML),
        })
        endpoints = [{
            "url": "https://example.com/login",
            "action": "https://example.com/auth/login",
            "method": "POST",
            "password_field": "password",
            "username_field": "username",
        }]
        alerts = check_csrf_protection(session, endpoints, timeout=5)
        assert len(alerts) == 1
        assert "static" in alerts[0]["alert"].lower() or "non-rotating" in alerts[0]["alert"].lower()

    def test_rotating_token_no_alert(self, monkeypatch):
        """When each GET returns a different CSRF token, no static-token alert fires."""
        from modules.auth_test import check_csrf_protection
        from tests.conftest import SAMPLE_LOGIN_HTML_ROTATED_CSRF
        import modules.auth_test as at
        monkeypatch.setattr(at.time, "sleep", lambda _: None)

        # Return different HTML on successive calls
        call_count = {"n": 0}
        first = FakeResponse(200, SAMPLE_LOGIN_HTML)
        second = FakeResponse(200, SAMPLE_LOGIN_HTML_ROTATED_CSRF)

        class RotatingSession(FakeSession):
            def get(self, url, **kwargs):
                self.call_log.append({"method": "GET", "url": url, "kwargs": kwargs})
                call_count["n"] += 1
                return first if call_count["n"] <= 1 else second

        session = RotatingSession({})
        endpoints = [{
            "url": "https://example.com/login",
            "action": "https://example.com/auth/login",
            "method": "POST",
            "password_field": "password",
            "username_field": "username",
        }]
        alerts = check_csrf_protection(session, endpoints, timeout=5)
        assert alerts == []

    def test_no_endpoints(self):
        from modules.auth_test import check_csrf_protection

        session = FakeSession({})
        alerts = check_csrf_protection(session, [], timeout=5)
        assert alerts == []

    def test_static_token_in_later_form_flagged(self, monkeypatch):
        """Fix #1: page with a CSRF-less form FIRST and a static-token login
        form LATER must still be flagged (the earlier unconditional outer break
        would have skipped the login form entirely)."""
        from modules.auth_test import check_csrf_protection
        import modules.auth_test as at
        monkeypatch.setattr(at.time, "sleep", lambda *a, **k: None)

        # Same HTML on both fetches -> the login form's csrf_token is static.
        session = FakeSession({
            "example.com": FakeResponse(200, MULTI_FORM_STATIC_CSRF_HTML),
        })
        endpoints = [{
            "url": "https://example.com/login",
            "action": "https://example.com/auth/login",
            "method": "POST",
            "password_field": "password",
            "username_field": "username",
        }]
        alerts = check_csrf_protection(session, endpoints, timeout=5)
        assert len(alerts) == 1
        assert "static" in alerts[0]["alert"].lower() or "non-rotating" in alerts[0]["alert"].lower()


class TestBruteForceProtection:
    def test_three_consecutive_connection_errors_trip_protection(self, monkeypatch):
        """Fix #3a: 3 consecutive ConnectionErrors count as a protection signal;
        the loop exits early and NO 'Missing Brute-Force Protection' alert fires."""
        from modules.auth_test import test_brute_force_protection
        import modules.auth_test as at
        monkeypatch.setattr(at.time, "sleep", lambda *a, **k: None)
        monkeypatch.setattr(at.time, "monotonic", lambda: 0.0)

        session = SequencedSession([
            requests.exceptions.ConnectionError("reset"),
            requests.exceptions.ConnectionError("reset"),
            requests.exceptions.ConnectionError("reset"),
        ])

        alerts = test_brute_force_protection(
            session, [_bf_endpoint()], attempts=10, timeout=1,
        )

        # protection_detected -> no "missing protection" alert
        assert alerts == []
        # early exit at the 3rd consecutive error, not all 10 attempts
        assert len(session.call_log) == 3

    def test_alternating_errors_do_not_trip_protection(self, monkeypatch):
        """Fix #3b: connection errors interspersed with normal responses never
        reach 3 CONSECUTIVE errors (the counter resets on each success), so
        protection is NOT detected and the missing-protection alert IS raised."""
        from modules.auth_test import test_brute_force_protection
        import modules.auth_test as at
        monkeypatch.setattr(at.time, "sleep", lambda *a, **k: None)
        monkeypatch.setattr(at.time, "monotonic", lambda: 0.0)

        # err, ok, err, ok, ... for 10 attempts: 5 total errors, never 3 in a row.
        ok = FakeResponse(200, "Invalid username or password.")
        err = requests.exceptions.ConnectionError("reset")
        session = SequencedSession([err, ok, err, ok, err, ok, err, ok, err, ok])

        alerts = test_brute_force_protection(
            session, [_bf_endpoint()], attempts=10, timeout=1,
        )

        # No consecutive-error trip -> the endpoint is reported as unprotected.
        assert len(alerts) == 1
        assert alerts[0]["risk"] == "High"
        assert "brute-force" in alerts[0]["alert"].lower()
        # All 10 attempts ran (no early exit).
        assert len(session.call_log) == 10


class TestRunScanPassiveOnly:
    def test_confirm_false_no_post(self, sample_login_html):
        session = FakeSession({
            "example.com": FakeResponse(200, sample_login_html),
        })
        import modules.auth_test as at
        original_get_session = at.get_session
        at.get_session = lambda **kw: session
        try:
            alerts = run_scan(
                "https://example.com",
                confirm=False,
                timeout=5,
            )
        finally:
            at.get_session = original_get_session
        post_calls = [c for c in session.call_log if c["method"] == "POST"]
        assert post_calls == []
