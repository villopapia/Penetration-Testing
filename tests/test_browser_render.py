"""Tests for modules.browser_render (no Playwright required)."""
from __future__ import annotations

import pytest

from modules.browser_render import (
    RenderedPage,
    BrowserUnavailableError,
    is_playwright_available,
)


def test_rendered_page_dataclass():
    rp = RenderedPage(
        html="<html></html>",
        final_url="https://example.com",
        status=200,
        requests=["https://example.com/app.js"],
        console_errors=[],
    )
    assert rp.html == "<html></html>"
    assert rp.status == 200
    assert len(rp.requests) == 1


def test_browser_unavailable_error_is_runtime_error():
    assert issubclass(BrowserUnavailableError, RuntimeError)


def test_is_playwright_available_returns_bool():
    result = is_playwright_available()
    assert isinstance(result, bool)
