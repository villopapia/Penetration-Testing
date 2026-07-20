"""Tests for modules.ransomware_readiness."""
from __future__ import annotations

import pytest
from tests.conftest import FakeResponse, FakeSession

from modules.ransomware_readiness import (
    check_security_headers,
    compute_readiness_score,
    _is_soft_404,
    SECURITY_HEADERS,
)
from modules.common import make_alert, parse_html


class TestCheckSecurityHeaders:
    def test_all_headers_present(self):
        headers = {
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Permissions-Policy": "camera=()",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "X-XSS-Protection": "1; mode=block",
        }
        session = FakeSession({
            "example.com": FakeResponse(200, "<html></html>", headers=headers),
        })
        alerts, details = check_security_headers(session, "https://example.com", timeout=5)
        assert alerts == []
        assert details["score"] > 0
        assert len(details["missing"]) == 0

    def test_all_headers_missing(self):
        session = FakeSession({
            "example.com": FakeResponse(200, "<html></html>", headers={}),
        })
        alerts, details = check_security_headers(session, "https://example.com", timeout=5)
        assert len(alerts) == len(SECURITY_HEADERS)
        assert details["score"] == 0


class TestComputeReadinessScore:
    def test_perfect_score(self):
        result = compute_readiness_score([])
        assert result["score"] == 100
        assert result["grade"] == "A"

    def test_admin_panel_reduces_score(self):
        alerts = [
            make_alert(risk="Medium", alert_name="Exposed Administrative Interface: /admin",
                       url="https://x.com/admin", description="", solution=""),
        ]
        result = compute_readiness_score(alerts)
        assert result["score"] < 100

    def test_missing_headers_reduce_score(self):
        alerts = [
            make_alert(risk="Low", alert_name="Missing Security Header: Strict-Transport-Security",
                       url="https://x.com", description="", solution=""),
            make_alert(risk="Low", alert_name="Missing Security Header: Content-Security-Policy",
                       url="https://x.com", description="", solution=""),
        ]
        result = compute_readiness_score(alerts)
        assert result["score"] < 100
        assert result["breakdown"]["strong_config"]["earned"] == 0

    def test_grade_f(self):
        alerts = [
            make_alert(risk="Medium", alert_name="Exposed Administrative Interface: /admin",
                       url="u", description="", solution=""),
            make_alert(risk="High", alert_name="Exposed Sensitive File: /backup.sql",
                       url="u", description="", solution=""),
            make_alert(risk="Critical", alert_name="Exposed Service Port: RDP (3389)",
                       url="u", description="", solution=""),
            make_alert(risk="Low", alert_name="Missing Security Header: Strict-Transport-Security",
                       url="u", description="", solution=""),
            make_alert(risk="Low", alert_name="Missing Security Header: Content-Security-Policy",
                       url="u", description="", solution=""),
            make_alert(risk="Low", alert_name="Directory Listing Enabled: /uploads/",
                       url="u", description="", solution=""),
        ]
        result = compute_readiness_score(alerts)
        assert result["grade"] == "F"


class TestIsSoft404:
    def test_detects_soft_404_by_title(self):
        html = "<html><head><title>404 Not Found</title></head><body>sorry</body></html>"
        soup = parse_html(html)
        assert _is_soft_404(html, soup) is True

    def test_normal_page(self):
        html = "<html><head><title>Welcome</title></head><body>Hello world</body></html>"
        soup = parse_html(html)
        assert _is_soft_404(html, soup) is False

    def test_detects_repeated_not_found(self):
        html = "<html><body>Page not found. The resource was not found.</body></html>"
        soup = parse_html(html)
        assert _is_soft_404(html, soup) is True
