"""Shared Playwright-based headless browser rendering helper.

Provides a reusable ``BrowserSession`` context manager for rendering
JS-heavy pages.  Falls back gracefully when Playwright is not installed
or browser binaries are missing.
"""

from __future__ import annotations

import dataclasses
import time
from typing import Any


@dataclasses.dataclass
class RenderedPage:
    html: str
    final_url: str
    status: int | None
    requests: list[str]
    console_errors: list[str]


def is_playwright_available() -> bool:
    try:
        import playwright.sync_api  # noqa: F401
        return True
    except ImportError:
        return False


class BrowserUnavailableError(RuntimeError):
    pass


class BrowserSession:
    """Reusable headless Chromium session.  One instance per run_scan() call."""

    def __init__(
        self,
        *,
        headless: bool = True,
        nav_timeout_ms: int = 30000,
        user_agent: str = (
            "DORA-Art24-SecurityAssessment/1.0 "
            "(Authorised Regulatory Assessment Tool)"
        ),
    ):
        self._headless = headless
        self._nav_timeout_ms = nav_timeout_ms
        self._user_agent = user_agent
        self._playwright: Any = None
        self._browser: Any = None
        self._context: Any = None

    def __enter__(self) -> "BrowserSession":
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            raise BrowserUnavailableError(
                "Playwright is not installed. "
                "Run: pip install playwright && playwright install chromium"
            )

        try:
            self._playwright = sync_playwright().start()
            self._browser = self._playwright.chromium.launch(headless=self._headless)
            self._context = self._browser.new_context(user_agent=self._user_agent)
            self._context.set_default_timeout(self._nav_timeout_ms)
        except Exception as exc:
            self._cleanup()
            raise BrowserUnavailableError(
                f"Failed to launch Chromium: {exc}. "
                "Run: playwright install chromium"
            ) from exc

        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self._cleanup()

    def _cleanup(self) -> None:
        try:
            if self._context is not None:
                self._context.close()
        except Exception:
            pass
        try:
            if self._browser is not None:
                self._browser.close()
        except Exception:
            pass
        try:
            if self._playwright is not None:
                self._playwright.stop()
        except Exception:
            pass
        self._context = None
        self._browser = None
        self._playwright = None

    def render(
        self,
        url: str,
        *,
        wait_for_selector: str | None = None,
        wait_until: str = "networkidle",
        extra_wait_ms: int = 1500,
        cookies: list[dict] | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> RenderedPage:
        if self._context is None:
            raise BrowserUnavailableError("BrowserSession not entered (use 'with' statement)")

        if cookies:
            self._context.add_cookies(cookies)

        page = self._context.new_page()
        if extra_headers:
            page.set_extra_http_headers(extra_headers)

        collected_requests: list[str] = []
        console_errors: list[str] = []

        page.on("request", lambda req: collected_requests.append(req.url))
        page.on("console", lambda msg: (
            console_errors.append(msg.text) if msg.type == "error" else None
        ))

        response = page.goto(url, wait_until=wait_until)
        status = response.status if response else None

        if wait_for_selector:
            try:
                page.wait_for_selector(wait_for_selector, timeout=5000)
            except Exception:
                pass

        if extra_wait_ms > 0:
            page.wait_for_timeout(extra_wait_ms)

        html = page.content()
        final_url = page.url

        page.close()

        return RenderedPage(
            html=html,
            final_url=final_url,
            status=status,
            requests=collected_requests,
            console_errors=console_errors,
        )
