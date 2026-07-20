"""Integration tests for run_modules.py dispatch and module registry."""
from __future__ import annotations

import pytest
from unittest.mock import patch, MagicMock

import run_modules


class TestModuleRegistry:
    def test_all_modules_tuple(self):
        assert isinstance(run_modules.ALL_MODULES, tuple)
        assert "auth" in run_modules.ALL_MODULES
        assert "supply-chain" in run_modules.ALL_MODULES
        assert "prompt-injection" in run_modules.ALL_MODULES
        assert "ransomware" in run_modules.ALL_MODULES
        assert "authenticated-scan" in run_modules.ALL_MODULES
        assert "tls" in run_modules.ALL_MODULES
        assert "api-discovery" in run_modules.ALL_MODULES

    def test_active_modules_subset(self):
        for m in run_modules._ACTIVE_MODULES:
            assert m in run_modules.ALL_MODULES


class TestDispatch:
    def test_unknown_module_returns_empty(self):
        result = run_modules._run_module(
            "nonexistent",
            "https://example.com",
            confirm=False,
            timeout=5,
            dry_run=True,
            extra_args={},
        )
        assert result == []

    @pytest.mark.parametrize("module_name", list(run_modules.ALL_MODULES))
    def test_dry_run_returns_empty(self, module_name):
        result = run_modules._run_module(
            module_name,
            "https://example.com",
            confirm=False,
            timeout=5,
            dry_run=True,
            extra_args={},
        )
        assert isinstance(result, list)
        assert result == []

    def test_run_selected_modules_dry_run(self):
        alerts = run_modules.run_selected_modules(
            "https://example.com",
            modules=["tls", "api-discovery"],
            confirm=False,
            timeout=5,
            dry_run=True,
        )
        assert isinstance(alerts, list)
        assert alerts == []

    def test_run_all_modules_dry_run(self):
        alerts = run_modules.run_selected_modules(
            "https://example.com",
            modules=["all"],
            confirm=False,
            timeout=5,
            dry_run=True,
        )
        assert isinstance(alerts, list)
        assert alerts == []


class TestDoraKeywordMappings:
    """Verify new alert names map to DORA articles correctly."""

    def test_tls_alert_maps_to_dora(self):
        from zap_scan import _map_dora_article, DORA_ARTICLE_TEXT

        finding = {"alert": "Deprecated TLS Version Supported: TLSv1", "description": ""}
        result = _map_dora_article(finding)
        assert result == DORA_ARTICLE_TEXT["24_1_a"]

    def test_idor_alert_maps_to_dora(self):
        from zap_scan import _map_dora_article, DORA_ARTICLE_TEXT

        finding = {"alert": "Potential Insecure Direct Object Reference (IDOR)", "description": ""}
        result = _map_dora_article(finding)
        assert result == DORA_ARTICLE_TEXT["24_1_a"]

    def test_broken_access_control_maps_to_dora(self):
        from zap_scan import _map_dora_article, DORA_ARTICLE_TEXT

        finding = {"alert": "Broken Access Control: Page Accessible Without Authentication", "description": ""}
        result = _map_dora_article(finding)
        assert result == DORA_ARTICLE_TEXT["24_1_a"]

    def test_graphql_introspection_maps_to_dora(self):
        from zap_scan import _map_dora_article, DORA_ARTICLE_TEXT

        finding = {"alert": "GraphQL Introspection Enabled", "description": ""}
        result = _map_dora_article(finding)
        assert result == DORA_ARTICLE_TEXT["24_1_a"]

    def test_openapi_maps_to_dora(self):
        from zap_scan import _map_dora_article, DORA_ARTICLE_TEXT

        finding = {"alert": "OpenAPI/Swagger Specification Publicly Accessible", "description": ""}
        result = _map_dora_article(finding)
        assert result == DORA_ARTICLE_TEXT["24_1_a"]

    def test_hsts_maps_to_dora(self):
        from zap_scan import _map_dora_article, DORA_ARTICLE_TEXT

        finding = {"alert": "TLS: Missing HTTP Strict Transport Security (HSTS)", "description": ""}
        result = _map_dora_article(finding)
        assert result == DORA_ARTICLE_TEXT["24_1_a"]

    def test_self_signed_cert_maps_to_dora(self):
        from zap_scan import _map_dora_article, DORA_ARTICLE_TEXT

        finding = {"alert": "Self-Signed Certificate", "description": "TLS certificate"}
        result = _map_dora_article(finding)
        assert result == DORA_ARTICLE_TEXT["24_1_a"]
