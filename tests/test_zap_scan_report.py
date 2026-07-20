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


class TestMapFindingToDoraCategory:
    def test_ict_risk(self):
        assert _map_finding_to_dora_category({"alert": "CSRF issue", "description": ""}) == "ict_risk_management"

    def test_resilience(self):
        assert _map_finding_to_dora_category(
            {"alert": "Vulnerable JavaScript Library", "description": "third-party dependency"}
        ) == "resilience_testing"
