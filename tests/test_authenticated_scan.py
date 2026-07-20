"""Tests for modules.authenticated_scan."""
from __future__ import annotations

import pytest
from tests.conftest import FakeResponse, FakeSession


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
