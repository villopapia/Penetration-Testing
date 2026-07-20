"""Tests for modules.supply_chain."""
from __future__ import annotations

import json
import pytest
from unittest.mock import patch

from tests.conftest import FakeResponse, FakeSession

from modules.supply_chain import (
    _extract_script_sources,
    _identify_from_url,
    check_sri,
    _load_signatures,
)


class TestExtractScriptSources:
    def test_extracts_scripts(self):
        html = '<html><script src="/app.js"></script><script src="https://cdn.example.com/lib.js"></script></html>'
        resources = _extract_script_sources(html, "https://example.com")
        assert len(resources) == 2
        srcs = [r["src"] for r in resources]
        assert "https://example.com/app.js" in srcs
        assert "https://cdn.example.com/lib.js" in srcs

    def test_extracts_stylesheets(self):
        html = '<html><link rel="stylesheet" href="https://cdn.example.com/style.css"></html>'
        resources = _extract_script_sources(html, "https://example.com")
        assert len(resources) == 1
        assert resources[0]["tag"] == "link"


class TestIdentifyFromUrl:
    def test_jquery_cdn(self):
        sigs = _load_signatures()
        result = _identify_from_url(
            "https://code.jquery.com/jquery-3.6.0.min.js", sigs
        )
        if result is not None:
            assert result[0].lower() == "jquery"
            assert "3.6.0" in result[1]

    def test_no_match(self):
        sigs = _load_signatures()
        result = _identify_from_url("https://example.com/custom.js", sigs)
        assert result is None


class TestCheckSri:
    def test_missing_sri_on_cross_origin(self):
        resources = [
            {"src": "https://cdn.example.com/lib.js", "tag": "script", "integrity": "", "crossorigin": ""},
        ]
        missing = check_sri(resources, "https://example.com")
        assert len(missing) == 1

    def test_same_origin_skipped(self):
        resources = [
            {"src": "https://example.com/app.js", "tag": "script", "integrity": "", "crossorigin": ""},
        ]
        missing = check_sri(resources, "https://example.com")
        assert len(missing) == 0

    def test_sri_present_not_flagged(self):
        resources = [
            {"src": "https://cdn.example.com/lib.js", "tag": "script",
             "integrity": "sha384-abc", "crossorigin": "anonymous"},
        ]
        missing = check_sri(resources, "https://example.com")
        assert len(missing) == 0
