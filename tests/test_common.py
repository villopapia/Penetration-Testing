"""Tests for modules.common helpers."""
from __future__ import annotations

import pytest
from tests.conftest import FakeResponse, FakeSession

from modules.common import (
    make_alert,
    is_same_origin,
    resolve_url,
    fetch_page,
    load_lines,
    extract_script_sources,
    extract_form_fields,
    extract_meta_csrf_token,
    RISK_CODE_MAP,
)


class TestMakeAlert:
    def test_all_keys_present(self):
        alert = make_alert(
            risk="High",
            alert_name="Test Alert",
            url="https://example.com",
            description="desc",
            solution="fix it",
        )
        expected_keys = {
            "riskcode", "risk", "alert", "name", "url",
            "description", "solution", "cweid", "wascid",
            "reference", "evidence",
        }
        assert set(alert.keys()) == expected_keys

    @pytest.mark.parametrize("risk,code", [
        ("Critical", "4"),
        ("High", "3"),
        ("Medium", "2"),
        ("Low", "1"),
        ("Informational", "0"),
    ])
    def test_riskcode_mapping(self, risk, code):
        alert = make_alert(
            risk=risk, alert_name="t", url="u", description="d", solution="s",
        )
        assert alert["riskcode"] == code

    def test_alert_and_name_match(self):
        alert = make_alert(
            risk="Low", alert_name="My Alert", url="u", description="d", solution="s",
        )
        assert alert["alert"] == alert["name"] == "My Alert"


class TestIsSameOrigin:
    def test_same_origin(self):
        assert is_same_origin("https://a.com/page", "https://a.com/other") is True

    def test_different_origin(self):
        assert is_same_origin("https://a.com", "https://b.com/x") is False

    def test_relative_url_is_same_origin(self):
        assert is_same_origin("https://a.com", "/path") is True

    def test_different_port(self):
        assert is_same_origin("https://a.com:443", "https://a.com:8080/x") is False


class TestResolveUrl:
    def test_absolute(self):
        assert resolve_url("https://a.com/base", "https://b.com/page") == "https://b.com/page"

    def test_relative(self):
        assert resolve_url("https://a.com/base/", "other") == "https://a.com/base/other"

    def test_root_relative(self):
        assert resolve_url("https://a.com/base/page", "/root") == "https://a.com/root"


class TestFetchPage:
    def test_success(self):
        session = FakeSession({"example.com": FakeResponse(200, "OK")})
        resp, err = fetch_page(session, "https://example.com", timeout=5)
        assert resp is not None
        assert resp.status_code == 200
        assert err == ""

    def test_request_exception(self, monkeypatch):
        import requests

        session = FakeSession()
        def _raise(*a, **kw):
            raise requests.RequestException("fail")
        monkeypatch.setattr(session, "get", _raise)

        resp, err = fetch_page(session, "https://example.com")
        assert resp is None
        assert "fail" in err


class TestLoadLines:
    def test_loads_valid_file(self, tmp_path):
        f = tmp_path / "test.txt"
        f.write_text("line1\n# comment\n\nline2\n", encoding="utf-8")
        lines = load_lines(f)
        assert lines == ["line1", "line2"]

    def test_missing_file(self, tmp_path):
        f = tmp_path / "missing.txt"
        with pytest.warns(UserWarning, match="not found"):
            lines = load_lines(f)
        assert lines == []


class TestExtractScriptSources:
    def test_extracts_scripts_and_links(self):
        html = '''
        <html>
        <head><link rel="stylesheet" href="/style.css" integrity="sha256-abc"></head>
        <body><script src="/app.js"></script></body>
        </html>
        '''
        resources = extract_script_sources(html, "https://example.com")
        assert len(resources) == 2
        tags = {r["tag"] for r in resources}
        assert tags == {"script", "link"}


class TestExtractFormFields:
    def test_extracts_fields(self):
        from modules.common import parse_html
        html = '<form><input name="user" type="text"><input name="pass" type="password"></form>'
        soup = parse_html(html)
        form = soup.find("form")
        fields = extract_form_fields(form)
        assert len(fields) == 2
        names = {f["name"] for f in fields}
        assert names == {"user", "pass"}


class TestExtractMetaCsrfToken:
    def test_finds_token(self):
        html = '<html><meta name="csrf-token" content="tok123"></html>'
        assert extract_meta_csrf_token(html) == "tok123"

    def test_no_token(self):
        html = '<html><meta name="description" content="page"></html>'
        assert extract_meta_csrf_token(html) is None
