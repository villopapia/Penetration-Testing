"""Tests for modules.auth_test."""
from __future__ import annotations

import pytest
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
