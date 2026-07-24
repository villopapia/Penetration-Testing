"""Tests for modules.authenticated_scan."""
from __future__ import annotations

import pytest
from tests.conftest import FakeCookieJar, FakeResponse, FakeSession


# Login page carrying a password form, used by the Strategy 3 (form login) tests.
_FORM_LOGIN_PAGE = """\
<html><body>
<form method="POST" action="/auth/login">
  <input type="text" name="username">
  <input type="password" name="password">
  <button type="submit">Log In</button>
</form>
</body></html>
"""


class FormLoginSession(FakeSession):
    """Fake session for Strategy 3: every GET returns the login page (initial
    fetch + the CSRF refresh re-GET), and POST returns a configurable login
    response."""

    def __init__(self, post_response: FakeResponse):
        super().__init__({})
        self._login_page = FakeResponse(
            200, _FORM_LOGIN_PAGE, url="https://example.com/login",
        )
        self._post_response = post_response

    def get(self, url, **kwargs):
        self.call_log.append({"method": "GET", "url": url, "kwargs": kwargs})
        return self._login_page

    def post(self, url, **kwargs):
        self.call_log.append({"method": "POST", "url": url, "kwargs": kwargs})
        return self._post_response


class TestLoginAndGetSession:
    def test_session_cookie_strategy(self, monkeypatch):
        from modules import authenticated_scan as mod

        fake = FakeSession({
            "https://example.com": FakeResponse(200, "<html>Dashboard</html>", url="https://example.com/dashboard"),
        })
        monkeypatch.setattr(mod, "get_session", lambda **kw: fake)

        session, msg = mod.login_and_get_session(
            "https://example.com",
            session_cookie="sid=abc123",
        )
        assert session is not None
        assert "cookie" in msg.lower()

    def test_session_cookie_rejected_on_login_redirect(self, monkeypatch):
        from modules import authenticated_scan as mod

        fake = FakeSession({
            "https://example.com": FakeResponse(200, "Please login", url="https://example.com/login"),
        })
        monkeypatch.setattr(mod, "get_session", lambda **kw: fake)

        session, msg = mod.login_and_get_session(
            "https://example.com",
            session_cookie="sid=bad",
        )
        assert session is None
        assert "invalid" in msg.lower()

    def test_auth_header_strategy(self, monkeypatch):
        from modules import authenticated_scan as mod

        fake = FakeSession({
            "https://example.com": FakeResponse(200, "<html>OK</html>", url="https://example.com/"),
        })
        monkeypatch.setattr(mod, "get_session", lambda **kw: fake)

        session, msg = mod.login_and_get_session(
            "https://example.com",
            auth_header="Bearer token123",
        )
        assert session is not None
        assert "auth header" in msg.lower()
        assert fake.headers.get("Authorization") == "Bearer token123"

    def test_no_credentials_returns_none(self):
        from modules import authenticated_scan as mod

        session, msg = mod.login_and_get_session("https://example.com")
        assert session is None
        assert "no credentials" in msg.lower()


class TestFormLoginSuccessDetection:
    """Fix #2: Strategy 3 (username+password) must NOT treat a mere non-login
    redirect as success. Success requires a positive indicator or a new
    session/auth cookie."""

    def test_failure_redirect_without_indicator_returns_none(self, monkeypatch):
        """Failed login that redirects to a non-login-named path with no success
        indicator and no auth cookie must return None (the exact false positive
        the fix removed -- previously any redirect off /login counted as success)."""
        from modules import authenticated_scan as mod

        # Redirect to a dashboard-looking path, but the body carries NO success
        # indicator and NO auth cookie -> a genuine failure dressed as a redirect.
        post_resp = FakeResponse(
            200,
            "<html><body>Authentication failed. Please try again.</body></html>",
            url="https://example.com/dashboard?auth=failed",
            history=[FakeResponse(302, "", url="https://example.com/auth/login")],
            cookies={},
        )
        fake = FormLoginSession(post_resp)
        monkeypatch.setattr(mod, "get_session", lambda **kw: fake)

        session, msg = mod.login_and_get_session(
            "https://example.com",
            login_url="/login",
            username="user",
            password="pw",
        )
        assert session is None
        assert "success indicator" in msg.lower()

    def test_success_via_indicator_returns_session(self, monkeypatch):
        """Genuine success signalled by a success indicator in the body -> a
        valid session is returned (legitimate success path still works)."""
        from modules import authenticated_scan as mod

        post_resp = FakeResponse(
            200,
            "<html><body>Welcome! <a href='/logout'>Logout</a></body></html>",
            url="https://example.com/dashboard",
            cookies={},
        )
        fake = FormLoginSession(post_resp)
        monkeypatch.setattr(mod, "get_session", lambda **kw: fake)

        session, msg = mod.login_and_get_session(
            "https://example.com",
            login_url="/login",
            username="user",
            password="pw",
        )
        assert session is fake
        assert "logged in" in msg.lower()

    def test_success_via_session_cookie_returns_session(self, monkeypatch):
        """Genuine success signalled only by a new session cookie (no textual
        indicator) -> a valid session is returned."""
        from modules import authenticated_scan as mod

        jar = FakeCookieJar()
        jar.set("sessionid", "xyz789")
        post_resp = FakeResponse(
            200,
            "<html><body>OK</body></html>",  # no success indicator in text
            url="https://example.com/home",
            cookies=jar,
        )
        fake = FormLoginSession(post_resp)
        monkeypatch.setattr(mod, "get_session", lambda **kw: fake)

        session, msg = mod.login_and_get_session(
            "https://example.com",
            login_url="/login",
            username="user",
            password="pw",
        )
        assert session is fake
        assert "logged in" in msg.lower()


class TestCrawlAuthenticated:
    def test_basic_crawl(self, fake_session_factory):
        from modules.authenticated_scan import crawl_authenticated

        page_html = (
            '<html><head><title>Home</title></head><body>'
            '<a href="/about">About</a>'
            '<a href="/contact">Contact</a>'
            '</body></html>'
        )
        fake = fake_session_factory({
            "https://example.com": FakeResponse(
                200, page_html,
                headers={"content-type": "text/html"},
                url="https://example.com/",
            ),
            "/about": FakeResponse(
                200, "<html><head><title>About</title></head><body>About</body></html>",
                headers={"content-type": "text/html"},
                url="https://example.com/about",
            ),
            "/contact": FakeResponse(
                200, "<html><head><title>Contact</title></head><body>Contact</body></html>",
                headers={"content-type": "text/html"},
                url="https://example.com/contact",
            ),
        })

        results = crawl_authenticated(fake, "https://example.com", max_pages=10)
        urls = [r["url"] for r in results]
        assert "https://example.com" in urls
        # Verify the crawler followed links, not just visited the seed
        assert len(results) >= 2, f"Expected crawler to follow links, got only: {urls}"

    def test_respects_max_pages(self, fake_session_factory):
        from modules.authenticated_scan import crawl_authenticated

        fake = fake_session_factory({
            "example.com": FakeResponse(
                200,
                "<html><head><title>P</title></head><body>"
                '<a href="/p1">1</a><a href="/p2">2</a><a href="/p3">3</a>'
                "</body></html>",
                headers={"content-type": "text/html"},
                url="https://example.com/",
            ),
        })

        results = crawl_authenticated(fake, "https://example.com", max_pages=1)
        assert len(results) == 1

    def test_skips_logout(self, fake_session_factory):
        from modules.authenticated_scan import crawl_authenticated

        html = (
            '<html><head><title>Home</title></head><body>'
            '<a href="/logout">Logout</a>'
            '<a href="/safe">Safe</a>'
            '</body></html>'
        )
        fake = fake_session_factory({
            "example.com": FakeResponse(
                200, html,
                headers={"content-type": "text/html"},
                url="https://example.com/",
            ),
        })

        results = crawl_authenticated(fake, "https://example.com", max_pages=10)
        urls = [r["url"] for r in results]
        assert not any("logout" in u for u in urls)


class TestAccessControlProbes:
    def test_horizontal_access_control_detects_exposed_page(self, fake_session_factory):
        from modules.authenticated_scan import test_horizontal_access_control

        page_content = "<html><body>Secret dashboard content here</body></html>"
        auth_session = fake_session_factory({
            "/dashboard": FakeResponse(200, page_content, url="https://example.com/dashboard"),
        })
        unauth_session = fake_session_factory({
            "/dashboard": FakeResponse(200, page_content, url="https://example.com/dashboard"),
        })

        pages = [{"url": "https://example.com/dashboard", "status": 200, "title": "Dashboard"}]
        alerts = test_horizontal_access_control(auth_session, unauth_session, pages)
        assert len(alerts) >= 1
        assert "broken access control" in alerts[0]["alert"].lower()

    def test_horizontal_access_control_skips_login_pages(self, fake_session_factory):
        from modules.authenticated_scan import test_horizontal_access_control

        # Both responses are similar length so the size-ratio check passes,
        # but the unauth response contains a password field -> should be skipped
        auth_html = '<html><body>Admin panel with secret content here!</body></html>'
        login_html = '<html><body><input type="password" name="pass">Login</body></html>'
        # Pad login_html to match auth_html length so the length check doesn't filter it first
        login_html = login_html.ljust(len(auth_html))

        auth_session = fake_session_factory({
            "/admin": FakeResponse(200, auth_html, url="https://example.com/admin"),
        })
        unauth_session = fake_session_factory({
            "/admin": FakeResponse(200, login_html, url="https://example.com/admin"),
        })

        pages = [{"url": "https://example.com/admin", "status": 200, "title": "Admin"}]
        alerts = test_horizontal_access_control(auth_session, unauth_session, pages)
        assert len(alerts) == 0

    def test_similar_length_but_different_visible_text_not_flagged(self, fake_session_factory):
        """Fix #4: raw lengths are near-identical, but visible text differs
        substantively after stripping script/nav/footer chrome -> the text
        check must prevent a flag that raw-length-alone would have raised."""
        from modules.authenticated_scan import test_horizontal_access_control

        auth_html = (
            "<html><body><p>"
            + ("Secret account data row " * 12)
            + "</p></body></html>"
        )
        # Unauth: real content lives in <script> (stripped from visible text),
        # visible body is just a tiny prompt. Pad the script so the RAW length
        # matches auth_html exactly -> length_similar is True, text_similar False.
        base = "<html><body><script></script><p>Login required</p></body></html>"
        pad = max(0, len(auth_html) - len(base))
        unauth_html = (
            "<html><body><script>"
            + ("z" * pad)
            + "</script><p>Login required</p></body></html>"
        )

        auth_session = fake_session_factory({
            "/report": FakeResponse(200, auth_html, url="https://example.com/report"),
        })
        unauth_session = fake_session_factory({
            "/report": FakeResponse(200, unauth_html, url="https://example.com/report"),
        })

        pages = [{"url": "https://example.com/report", "status": 200, "title": "Report"}]
        alerts = test_horizontal_access_control(auth_session, unauth_session, pages)
        assert alerts == []

    def test_chrome_differs_but_visible_text_matches_flags_medium(self, fake_session_factory):
        """Fix #4: raw length differs (different nav/footer between logged-in and
        logged-out views) but stays within the 20% band, while visible text is
        identical -> flag as Medium with the manual-verification note."""
        from modules.authenticated_scan import test_horizontal_access_control

        shared = "Account statement line item number 5567 amount 128.40 status posted " * 6
        auth_html = (
            "<html><body>"
            "<nav>Home Dashboard Reports Settings Profile Logout</nav>"
            f"<main>{shared}</main>"
            "<footer>Signed in as analyst@corp</footer>"
            "</body></html>"
        )
        unauth_html = (
            "<html><body>"
            "<nav>Home Login</nav>"
            f"<main>{shared}</main>"
            "<footer>Guest session</footer>"
            "</body></html>"
        )

        auth_session = fake_session_factory({
            "/report": FakeResponse(200, auth_html, url="https://example.com/report"),
        })
        unauth_session = fake_session_factory({
            "/report": FakeResponse(200, unauth_html, url="https://example.com/report"),
        })

        pages = [{"url": "https://example.com/report", "status": 200, "title": "Report"}]
        alerts = test_horizontal_access_control(auth_session, unauth_session, pages)
        assert len(alerts) == 1
        assert alerts[0]["risk"] == "Medium"
        assert "manually verify" in alerts[0]["description"].lower()

    def test_large_length_diff_still_flags_when_text_matches(self, fake_session_factory):
        """Fix #4 (revised): visible text is identical but a large nav pushes
        raw-length variance well beyond 20%. Flagging now keys on visible-text
        similarity alone, so this DOES flag as Medium; the raw-length divergence
        is recorded as a corroborating detail, not a gate."""
        from modules.authenticated_scan import test_horizontal_access_control

        shared = "Account statement line item number 5567 amount 128.40 status posted " * 6
        auth_html = (
            "<html><body>"
            f"<nav>{'Menu item link ' * 40}</nav>"
            f"<main>{shared}</main>"
            "</body></html>"
        )
        unauth_html = f"<html><body><nav>Home</nav><main>{shared}</main></body></html>"

        auth_session = fake_session_factory({
            "/report": FakeResponse(200, auth_html, url="https://example.com/report"),
        })
        unauth_session = fake_session_factory({
            "/report": FakeResponse(200, unauth_html, url="https://example.com/report"),
        })

        pages = [{"url": "https://example.com/report", "status": 200, "title": "Report"}]
        alerts = test_horizontal_access_control(auth_session, unauth_session, pages)
        assert len(alerts) == 1
        assert alerts[0]["risk"] == "Medium"
        desc = alerts[0]["description"].lower()
        assert "manually verify" in desc
        # raw-length divergence is reported as corroborating chrome detail
        assert "chrome" in desc and "differs by" in desc

    def test_length_and_text_both_differ_not_flagged(self, fake_session_factory):
        """Fix #4 (revised): with the length gate removed, confirm the flag is
        NOT raised on length alone -- when visible text is genuinely different
        (and raw length also wildly different), no alert fires. Guards against
        regressing into length-only false positives."""
        from modules.authenticated_scan import test_horizontal_access_control

        auth_html = (
            "<html><body><main>"
            + ("Confidential payroll record for employee 8891 net pay 3204.55 " * 8)
            + "</main></body></html>"
        )
        # Different content AND very different length; no password field so the
        # login-page skip does not mask the result.
        unauth_html = "<html><body><main>Please sign in to continue.</main></body></html>"

        auth_session = fake_session_factory({
            "/report": FakeResponse(200, auth_html, url="https://example.com/report"),
        })
        unauth_session = fake_session_factory({
            "/report": FakeResponse(200, unauth_html, url="https://example.com/report"),
        })

        pages = [{"url": "https://example.com/report", "status": 200, "title": "Report"}]
        alerts = test_horizontal_access_control(auth_session, unauth_session, pages)
        assert alerts == []


class TestIdorProbe:
    def test_detects_adjacent_id_access(self, fake_session_factory, monkeypatch):
        import modules.authenticated_scan as mod
        monkeypatch.setattr(mod.time, "sleep", lambda _: None)
        from modules.authenticated_scan import test_idor_probe

        fake = fake_session_factory({
            "/users/42": FakeResponse(200, "x" * 300, url="https://example.com/users/42"),
            "/users/41": FakeResponse(200, "y" * 300, url="https://example.com/users/41"),
            "/users/43": FakeResponse(200, "z" * 300, url="https://example.com/users/43"),
        })

        pages = [{"url": "https://example.com/users/42", "status": 200, "title": "Profile"}]
        alerts = test_idor_probe(fake, pages, timeout=1)
        assert len(alerts) >= 1
        assert "idor" in alerts[0]["alert"].lower()
        # Verify the probe actually tested adjacent IDs
        probed_urls = [c["url"] for c in fake.call_log]
        assert any("/users/41" in u for u in probed_urls) or any("/users/43" in u for u in probed_urls)

    def test_skips_non_id_urls(self, fake_session_factory):
        from modules.authenticated_scan import test_idor_probe

        fake = fake_session_factory({})
        pages = [{"url": "https://example.com/about", "status": 200, "title": "About"}]
        alerts = test_idor_probe(fake, pages)
        assert len(alerts) == 0
        # Verify no HTTP calls were made at all
        assert len(fake.call_log) == 0


class TestRunScan:
    def test_no_credentials_returns_empty(self):
        from modules.authenticated_scan import run_scan

        alerts = run_scan("https://example.com")
        assert alerts == []

    def test_dry_run_returns_empty(self):
        from modules.authenticated_scan import run_scan

        alerts = run_scan(
            "https://example.com",
            session_cookie="sid=test",
            dry_run=True,
        )
        assert alerts == []
