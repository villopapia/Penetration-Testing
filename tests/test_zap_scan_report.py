"""Tests for zap_scan.py report-pipeline pure functions."""
from __future__ import annotations

import pathlib
import tempfile

import pytest

from zap_scan import (
    _parse_alerts,
    _dedupe_findings,
    _map_dora_article,
    _is_third_party_finding,
    _severity_counts,
    _compliance_verdict,
    _merge_findings,
    _report_md,
    _map_finding_to_dora_category,
    DORA_ARTICLE_TEXT,
)


def _raw(risk="Medium", riskcode="2", alert="Test", url="https://x.com", **kw):
    base = {
        "riskcode": riskcode,
        "risk": risk,
        "alert": alert,
        "name": alert,
        "url": url,
        "description": kw.get("description", ""),
        "solution": kw.get("solution", ""),
        "cweid": kw.get("cweid", ""),
        "wascid": kw.get("wascid", ""),
        "reference": kw.get("reference", ""),
    }
    base.update(kw)
    return base


class TestParseAlerts:
    def test_normalises_risk(self):
        parsed = _parse_alerts([_raw(riskcode="3")])
        assert parsed[0]["severity"] == "High"

    def test_sorted_by_severity(self):
        alerts = [_raw(riskcode="1"), _raw(riskcode="3"), _raw(riskcode="2")]
        parsed = _parse_alerts(alerts)
        assert [a["severity"] for a in parsed] == ["High", "Medium", "Low"]

    def test_empty_list(self):
        assert _parse_alerts([]) == []


class TestDedupeFindings:
    def test_groups_by_alert_name(self):
        parsed = _parse_alerts([
            _raw(alert="A", url="https://x.com/1"),
            _raw(alert="A", url="https://x.com/2"),
            _raw(alert="B", url="https://x.com/3"),
        ])
        deduped = _dedupe_findings(parsed)
        names = [d["alert"] for d in deduped]
        assert "A" in names
        assert "B" in names
        a_entry = next(d for d in deduped if d["alert"] == "A")
        assert a_entry["instance_count"] == 2


class TestDoraMapping:
    def test_brute_force_maps_to_24_1_a(self):
        finding = {"alert": "Missing Brute-Force Protection", "description": ""}
        result = _map_dora_article(finding)
        assert "24(1)(a)" in result

    def test_vulnerable_js_maps_to_24_1_b(self):
        finding = {"alert": "Vulnerable JS Library: jQuery 1.2", "description": ""}
        result = _map_dora_article(finding)
        assert "24(1)(b)" in result

    def test_prompt_injection_maps_to_24_1_c(self):
        finding = {"alert": "Direct Prompt Injection Successful", "description": "prompt injection"}
        result = _map_dora_article(finding)
        assert "24(1)(c)" in result

    def test_admin_panel_maps_to_9_4(self):
        finding = {"alert": "Exposed Administrative Interface: /admin", "description": ""}
        result = _map_dora_article(finding)
        assert "9(4)" in result

    def test_csrf_alert_maps_to_24_1_a(self):
        finding = {"alert": "Static/Non-Rotating CSRF Token Detected", "description": "csrf"}
        result = _map_dora_article(finding)
        assert "24(1)(a)" in result

    def test_default_mapping(self):
        finding = {"alert": "Something Unknown", "description": "nothing special"}
        result = _map_dora_article(finding)
        assert "24(1)(a)" in result


class TestThirdPartyFinding:
    def test_sri_is_third_party(self):
        assert _is_third_party_finding({"alert": "Missing Subresource Integrity", "description": ""}) is True

    def test_vulnerable_js_is_third_party(self):
        assert _is_third_party_finding({"alert": "Vulnerable JS Library: x", "description": ""}) is True

    def test_unrelated_is_not_third_party(self):
        assert _is_third_party_finding({"alert": "Missing Header", "description": "no header"}) is False


class TestSeverityCounts:
    def test_counts(self):
        findings = [
            {"severity": "High"},
            {"severity": "High"},
            {"severity": "Medium"},
            {"severity": "Informational"},
        ]
        counts = _severity_counts(findings)
        assert counts["High"] == 2
        assert counts["Medium"] == 1
        assert counts["Informational"] == 1
        assert counts["Low"] == 0


class TestComplianceVerdict:
    def test_non_compliant(self):
        v = _compliance_verdict({"High": 1, "Medium": 0, "Low": 0})
        assert v["verdict"] == "Non-Compliant"

    def test_partially_compliant(self):
        v = _compliance_verdict({"High": 0, "Medium": 2, "Low": 0})
        assert v["verdict"] == "Partially Compliant"

    def test_compliant(self):
        v = _compliance_verdict({"High": 0, "Medium": 0, "Low": 3})
        assert v["verdict"] == "Compliant"


class TestMergeFindings:
    def test_merge_automated_and_manual(self):
        auto = [{"alert": "A", "severity": "High", "category": "A", "urls": [], "instance_count": 0,
                 "description": "", "solution": "", "cweid": "", "wascid": "", "reference": ""}]
        manual = [{"title": "B", "severity": "Medium", "category": "B", "description": "",
                   "affected_component": "/api", "recommendation": "", "proof_of_concept": "",
                   "business_impact": ""}]
        merged = _merge_findings(auto, manual)
        names = [m["alert"] for m in merged]
        assert "A" in names
        assert "B" in names

    def test_dedup_by_title(self):
        auto = [{"alert": "Same", "severity": "High", "category": "cat", "urls": [],
                 "instance_count": 0, "description": "", "solution": "", "cweid": "",
                 "wascid": "", "reference": ""}]
        manual = [{"title": "Same", "severity": "Medium", "category": "cat",
                   "description": "", "affected_component": "", "recommendation": "",
                   "proof_of_concept": "", "business_impact": ""}]
        merged = _merge_findings(auto, manual)
        assert len(merged) == 1


class TestReportMd:
    def test_report_contains_sections(self, tmp_path):
        alerts = _parse_alerts([_raw(riskcode="2", alert="Test Finding")])
        out = tmp_path / "report.md"
        _report_md(
            "https://example.com", "baseline", alerts, out,
            entity_name="TestCo", entity_lei="LEI123",
            assessor_name="tester", assessment_date="2025-01-01",
            regulatory_framework="dora", exclude_urls=None,
            manual_findings=None, business_context=None,
        )
        content = out.read_text(encoding="utf-8")
        assert "## 1. Executive Summary" in content
        assert "## 2. Risk Categorization" in content
        assert "## 3. Technical Findings" in content
        assert "## 4. Recommendations" in content
        assert "## 5. Testing Scope" in content
        assert "## 6. Regulatory Alignment" in content
        assert "## 7. Disclaimer" in content


class TestNoZapModeLabeling:
    """The standalone no-ZAP mode (scan_type='modules') must be labelled so a
    reader cannot mistake 'ZAP was not run' for 'ZAP ran and found nothing'."""

    def _modules_report(self, tmp_path, modules_run):
        alerts = _parse_alerts([_raw(alert="Missing Security Header", cweid="693")])
        out = tmp_path / "modules.md"
        _report_md(
            "https://x.com", "modules", alerts, out,
            assessor_name="tester", assessment_date="2026-07-24",
            regulatory_framework="dora", modules_run=modules_run,
        )
        return out.read_text(encoding="utf-8")

    def test_exec_summary_states_zap_not_run(self, tmp_path):
        content = self._modules_report(tmp_path, ["tls", "api-discovery"])
        assert "OWASP ZAP active scan NOT performed" in content
        assert "Reduced-scope assessment" in content
        assert "Custom modules only (no OWASP ZAP scan)" in content

    def test_scope_lists_modules_run_and_omits_zap_tool(self, tmp_path):
        content = self._modules_report(tmp_path, ["tls", "api-discovery"])
        # Tools Used must NOT claim ZAP was the scanner
        assert "OWASP ZAP (automated vulnerability scanner)" not in content
        assert "OWASP ZAP was **NOT** used" in content
        # The specific modules run are listed by their display names
        assert "TLS/certificate checks" in content
        assert "API surface discovery" in content
        # Missing active/injection scan is explicit
        assert "No generalized injection testing" in content

    def test_dora_section_has_scope_limitation(self, tmp_path):
        content = self._modules_report(tmp_path, ["tls"])
        assert "Scope limitation for this mapping" in content

    def test_authenticated_scan_login_failure_qualified(self, tmp_path):
        """A failed-login authenticated-scan run must be listed under Test Types
        Performed WITH an explicit note, not identically to a successful run."""
        # The login-failure signal is the alert authenticated_scan emits.
        alerts = _parse_alerts([_raw(
            risk="Informational", riskcode="0",
            alert="Authenticated Scanning Skipped - Login Failed",
        )])
        out = tmp_path / "authfail.md"
        _report_md(
            "https://x.com", "modules", alerts, out,
            assessor_name="tester", assessment_date="2026-07-24",
            regulatory_framework="none",
            modules_run=["authenticated-scan", "tls"],
        )
        content = out.read_text(encoding="utf-8")
        assert "login failed, authenticated crawl NOT performed" in content

    def test_authenticated_scan_login_success_unqualified(self, tmp_path):
        """A successful authenticated-scan run (no login-failure alert) must NOT
        carry the failure qualifier."""
        alerts = _parse_alerts([_raw(
            risk="Informational", riskcode="0",
            alert="Authenticated Attack Surface Discovered",
        )])
        out = tmp_path / "authok.md"
        _report_md(
            "https://x.com", "modules", alerts, out,
            assessor_name="tester", assessment_date="2026-07-24",
            regulatory_framework="none",
            modules_run=["authenticated-scan", "tls"],
        )
        content = out.read_text(encoding="utf-8")
        assert "login failed, authenticated crawl NOT performed" not in content
        # but the module is still listed as performed
        assert "Authenticated crawl with broken-access-control" in content

    def test_full_zap_path_unchanged(self, tmp_path):
        """Guard: the ZAP-backed path must NOT gain the no-ZAP banner/labels."""
        alerts = _parse_alerts([_raw(alert="Missing Security Header", cweid="693")])
        out = tmp_path / "full.md"
        _report_md(
            "https://x.com", "full", alerts, out,
            assessor_name="tester", assessment_date="2026-07-24",
            regulatory_framework="dora",
        )
        content = out.read_text(encoding="utf-8")
        assert "- **Methodology**: Automated (OWASP ZAP)" in content
        assert "OWASP ZAP (automated vulnerability scanner)" in content
        assert "Reduced-scope assessment" not in content
        assert "Scope limitation for this mapping" not in content


class TestHtmlPrintFriendliness:
    """The HTML report must carry print CSS so a browser 'Save as PDF' looks
    intentional: colours preserved, findings/tables kept whole, wide values wrap."""

    def _html(self, tmp_path):
        from zap_scan import _report_html
        alerts = _parse_alerts([
            _raw(risk="High", riskcode="3", alert="Default Credentials Accepted", cweid="521"),
            _raw(risk="Medium", riskcode="2", alert="Missing Security Header", cweid="693"),
        ])
        out = tmp_path / "report.html"
        _report_html(
            "https://example.com", "modules", alerts, out,
            assessor_name="tester", assessment_date="2026-07-24",
            regulatory_framework="dora", modules_run=["auth", "tls"],
        )
        return out.read_text(encoding="utf-8")

    def test_template_formats_without_brace_leak(self, tmp_path):
        html = self._html(tmp_path)
        # A stray single brace in the CSS would raise in str.format; doubled
        # braces would leak literally. Neither should appear.
        assert "{{" not in html and "}}" not in html

    def test_has_print_color_adjust(self, tmp_path):
        html = self._html(tmp_path)
        assert "print-color-adjust: exact" in html
        assert "-webkit-print-color-adjust: exact" in html

    def test_has_page_and_break_rules(self, tmp_path):
        html = self._html(tmp_path)
        assert "@media print" in html
        assert "@page" in html
        assert "break-inside: avoid" in html
        assert "break-after: avoid" in html
        assert "overflow-wrap: anywhere" in html

    def test_findings_wrapped_for_atomic_pagination(self, tmp_path):
        html = self._html(tmp_path)
        # Each technical finding is wrapped so print CSS can keep it whole.
        assert html.count('<div class="finding">') == 2
        # Wrappers are balanced (only finding divs are emitted).
        assert html.count("<div") == html.count("</div>")


class TestMapFindingToDoraCategory:
    def test_ict_risk(self):
        assert _map_finding_to_dora_category({"alert": "CSRF issue", "description": ""}) == "ict_risk_management"

    def test_resilience(self):
        assert _map_finding_to_dora_category(
            {"alert": "Vulnerable JavaScript Library", "description": "third-party dependency"}
        ) == "resilience_testing"
