"""Tests for modules.tls_check."""
from __future__ import annotations

import pytest
from modules.tls_check import (
    _get_host_port,
    build_cert_alerts,
    build_protocol_alerts,
    build_cipher_alerts,
    check_hsts,
)


class TestGetHostPort:
    def test_https_default_port(self):
        host, port, is_https = _get_host_port("https://example.com/path")
        assert host == "example.com"
        assert port == 443
        assert is_https is True

    def test_http_default_port(self):
        host, port, is_https = _get_host_port("http://example.com/path")
        assert host == "example.com"
        assert port == 80
        assert is_https is False

    def test_custom_port(self):
        host, port, is_https = _get_host_port("https://example.com:8443/path")
        assert host == "example.com"
        assert port == 8443
        assert is_https is True


class TestBuildCertAlerts:
    def test_no_cert_with_error(self):
        result = {
            "cert": None,
            "trusted": False,
            "trust_error": "Connection refused",
            "self_signed": False,
            "expired": False,
            "not_yet_valid": False,
            "hostname_mismatch": False,
        }
        alerts = build_cert_alerts("example.com", 443, "https://example.com", result)
        assert len(alerts) == 1
        assert alerts[0]["risk"] == "High"

    def test_self_signed_cert(self):
        result = {
            "cert": {"subject": (), "issuer": ()},
            "trusted": False,
            "trust_error": "self-signed certificate",
            "self_signed": True,
            "expired": False,
            "not_yet_valid": False,
            "hostname_mismatch": False,
            "days_until_expiry": 365,
            "issuer": "CN=self",
        }
        alerts = build_cert_alerts("example.com", 443, "https://example.com", result)
        assert any("self-signed" in a["alert"].lower() for a in alerts)

    def test_expired_cert(self):
        import datetime as dt
        result = {
            "cert": {"subject": (), "issuer": ()},
            "trusted": True,
            "trust_error": "",
            "self_signed": False,
            "expired": True,
            "not_yet_valid": False,
            "hostname_mismatch": False,
            "days_until_expiry": -5,
            "not_after": dt.datetime(2024, 1, 1, tzinfo=dt.timezone.utc),
        }
        alerts = build_cert_alerts("example.com", 443, "https://example.com", result)
        assert any(a["risk"] == "Critical" for a in alerts)

    def test_nearing_expiry(self):
        import datetime as dt
        result = {
            "cert": {"subject": (), "issuer": ()},
            "trusted": True,
            "trust_error": "",
            "self_signed": False,
            "expired": False,
            "not_yet_valid": False,
            "hostname_mismatch": False,
            "days_until_expiry": 15,
            "not_after": dt.datetime.now(dt.timezone.utc),
        }
        alerts = build_cert_alerts("example.com", 443, "https://example.com", result)
        assert any("nearing expiry" in a["alert"].lower() for a in alerts)

    def test_trusted_valid_cert_no_alerts(self):
        result = {
            "cert": {"subject": (), "issuer": ()},
            "trusted": True,
            "trust_error": "",
            "self_signed": False,
            "expired": False,
            "not_yet_valid": False,
            "hostname_mismatch": False,
            "days_until_expiry": 365,
        }
        alerts = build_cert_alerts("example.com", 443, "https://example.com", result)
        assert len(alerts) == 0


class TestBuildProtocolAlerts:
    def test_deprecated_tls_versions(self):
        status = {"TLSv1": "supported", "TLSv1.1": "supported", "TLSv1.2": "supported", "TLSv1.3": "supported"}
        alerts = build_protocol_alerts("https://example.com", status)
        high_alerts = [a for a in alerts if a["risk"] == "High"]
        assert len(high_alerts) == 2  # TLSv1 and TLSv1.1

    def test_modern_only_no_high_alerts(self):
        status = {"TLSv1": "unsupported", "TLSv1.1": "unsupported", "TLSv1.2": "supported", "TLSv1.3": "supported"}
        alerts = build_protocol_alerts("https://example.com", status)
        high_alerts = [a for a in alerts if a["risk"] == "High"]
        assert len(high_alerts) == 0

    def test_informational_summary(self):
        status = {"TLSv1.2": "supported"}
        alerts = build_protocol_alerts("https://example.com", status)
        info = [a for a in alerts if a["risk"] == "Informational"]
        assert len(info) == 1


class TestBuildCipherAlerts:
    def test_weak_cipher_flagged(self):
        alerts = build_cipher_alerts("https://example.com", ["RC4-SHA"])
        assert len(alerts) == 1
        assert alerts[0]["risk"] == "High"

    def test_no_weak_ciphers(self):
        alerts = build_cipher_alerts("https://example.com", [])
        assert len(alerts) == 0


class TestCheckHsts:
    def test_missing_hsts(self):
        alerts = check_hsts("https://example.com", {})
        assert len(alerts) == 1
        assert "missing" in alerts[0]["alert"].lower()

    def test_hsts_present_with_subdomains(self):
        headers = {"Strict-Transport-Security": "max-age=31536000; includeSubDomains"}
        alerts = check_hsts("https://example.com", headers)
        assert len(alerts) == 0

    def test_hsts_short_max_age(self):
        headers = {"Strict-Transport-Security": "max-age=3600; includeSubDomains"}
        alerts = check_hsts("https://example.com", headers)
        assert any("max-age" in a["alert"].lower() for a in alerts)

    def test_hsts_missing_subdomains(self):
        headers = {"Strict-Transport-Security": "max-age=31536000"}
        alerts = check_hsts("https://example.com", headers)
        assert any("subdomain" in a["alert"].lower() for a in alerts)
