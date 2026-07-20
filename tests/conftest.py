"""Shared test fixtures: FakeSession, sample HTML, audit log redirection."""
from __future__ import annotations

import types
from typing import Any
from unittest.mock import MagicMock

import pytest


class FakeResponse:
    """Minimal duck-type for requests.Response."""

    def __init__(
        self,
        status_code: int = 200,
        text: str = "",
        headers: dict[str, str] | None = None,
        url: str = "",
        cookies: Any = None,
        history: list | None = None,
    ):
        self.status_code = status_code
        self.text = text
        self.content = text.encode("utf-8", errors="replace")
        self.headers = headers or {}
        self.url = url
        self.cookies = cookies if cookies is not None else {}
        self.history = history or []

    def json(self) -> Any:
        import json
        return json.loads(self.text)

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            import requests
            raise requests.HTTPError(response=self)


class FakeCookieJar:
    """Minimal duck-type for requests cookies."""

    def __init__(self):
        self._cookies: dict[str, str] = {}

    def set(self, name: str, value: str, **kwargs: Any) -> None:
        self._cookies[name] = value

    def __iter__(self):
        for name, value in self._cookies.items():
            yield types.SimpleNamespace(name=name, value=value)


class FakeSession:
    """Fake requests.Session that routes by URL substring match."""

    def __init__(self, responses: dict[str, FakeResponse] | None = None):
        self._responses = responses or {}
        self.headers: dict[str, str] = {}
        self.cookies = FakeCookieJar()
        self.verify = True
        self.call_log: list[dict[str, Any]] = []

    def _resolve(self, url: str) -> FakeResponse:
        for pattern, resp in self._responses.items():
            if pattern in url:
                return resp
        return FakeResponse(status_code=404, text="Not Found")

    def get(self, url: str, **kwargs: Any) -> FakeResponse:
        self.call_log.append({"method": "GET", "url": url, "kwargs": kwargs})
        return self._resolve(url)

    def post(self, url: str, **kwargs: Any) -> FakeResponse:
        self.call_log.append({"method": "POST", "url": url, "kwargs": kwargs})
        return self._resolve(url)

    def request(self, method: str, url: str, **kwargs: Any) -> FakeResponse:
        self.call_log.append({"method": method, "url": url, "kwargs": kwargs})
        return self._resolve(url)


@pytest.fixture
def fake_session_factory():
    """Return a factory that builds FakeSession instances."""
    def _factory(responses: dict[str, FakeResponse] | None = None) -> FakeSession:
        return FakeSession(responses)
    return _factory


SAMPLE_LOGIN_HTML = """\
<!DOCTYPE html>
<html>
<head><title>Login</title></head>
<body>
<form method="POST" action="/auth/login">
  <input type="hidden" name="csrf_token" value="abc123">
  <label>Username</label>
  <input type="text" name="username">
  <label>Password</label>
  <input type="password" name="password">
  <button type="submit">Log In</button>
</form>
</body>
</html>
"""

SAMPLE_LOGIN_HTML_ROTATED_CSRF = """\
<!DOCTYPE html>
<html>
<head><title>Login</title></head>
<body>
<form method="POST" action="/auth/login">
  <input type="hidden" name="csrf_token" value="xyz789">
  <label>Username</label>
  <input type="text" name="username">
  <label>Password</label>
  <input type="password" name="password">
  <button type="submit">Log In</button>
</form>
</body>
</html>
"""


@pytest.fixture
def sample_login_html():
    return SAMPLE_LOGIN_HTML


@pytest.fixture
def sample_login_html_rotated_csrf():
    return SAMPLE_LOGIN_HTML_ROTATED_CSRF


@pytest.fixture(autouse=True)
def tmp_audit_log(monkeypatch):
    """Redirect audit logging to a no-op so tests never write scan_audit.log."""
    import zap_scan
    monkeypatch.setattr(zap_scan, "_audit", lambda msg: None)
