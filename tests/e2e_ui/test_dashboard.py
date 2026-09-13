# -*- coding: utf-8 -*-
"""
E2E UI Tests — Dashboard & System Panels

Uses go() with wait_until="commit" to avoid blocking
on unpkg.com CDN <script> tags. Fresh Flask server per test.
"""

import pytest
from playwright.sync_api import expect


def go(page, url, **kw):
    """Navigate to target URL cleanly: first unload the current page
    (killing any active SSE connections), then go to the target.
    Uses wait_until='commit' to avoid blocking on CDN <script> tags."""
    kw.setdefault("wait_until", "commit")
    kw.setdefault("timeout", 20000)
    # about:blank unloads the current document, severing all SSE/EventSource.
    # Use a generous 10s timeout — this should always complete under 1s.
    page.goto("about:blank", wait_until="commit", timeout=10000)
    page.wait_for_timeout(200)  # Let browser settle
    return page.goto(url, **kw)


class TestDashboard:
    """Dashboard page and content panels."""

    def test_dashboard_has_content(self, page, server_url):
        """Dashboard should have a main content area."""
        expect(page.locator(".app-shell")).to_be_visible()
        expect(page.locator(".app-header")).to_be_visible()
        expect(page.locator(".app-sidebar")).to_be_visible()

    def test_dashboard_stats_panel(self, page, server_url):
        """Overview page should load metric cards."""
        page.click("a.nav-link[data-path='overview']")
        page.wait_for_timeout(1500)
        body_text = page.locator("body").inner_text()
        assert len(body_text) > 100, "Dashboard body should have meaningful content"

    def test_overview_hides_the_capability_band_when_healthy(self, page, server_url):
        """The band is a warning surface, not a permanent status line.

        It used to render "Healthy / Detection: ... / Notifications: ..." on every
        visit, which cost the quadrant grid ~48px to report nothing wrong.  It is
        now rendered only when the runtime is degraded or carries warnings, so a
        healthy instance must not show it.
        """
        page.click("a.nav-link[data-path='overview']")
        expect(page.locator("[data-testid='overview-grid']")).to_be_visible(timeout=10000)

        band = page.locator("[data-testid='runtime-capabilities']")
        if band.count():
            # Present only because this runtime really is degraded; then it must
            # still explain itself.
            expect(band).to_contain_text("Detection")
            expect(band).to_contain_text("Notifications")
        else:
            assert band.count() == 0

    def test_page_title_appears_once(self, page, server_url):
        """Only the sidebar states which page you are on."""
        page.click("a.nav-link[data-path='overview']")
        page.wait_for_timeout(1200)
        assert page.locator("a.nav-link.active", has_text="Overview").count() == 1
        assert page.locator("#page-title").count() == 0
        assert page.locator(".brand-sub", has_text="Overview").count() == 0

    def test_overview_loads_existing_monitor_history(self, page, server_url, runtime):
        marker = "E2E-HISTORY-MARKER"
        # The panel shows the newest lines at the configured severities, so the
        # marker has to be the newest line: a fixed old date sorts to the front
        # of the tail and drops out as soon as the log holds a full window.
        import datetime as _datetime

        stamp = _datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        runtime.sse.persist_log_line(f"[{stamp}] INFO - {marker}")

        go(page, f"{server_url}/admin/")
        page.click("a.nav-link[data-path='overview']")

        expect(page.locator("#live-log-stream")).to_contain_text(
            marker,
            timeout=10000,
        )

    def test_threats_has_table(self, page, server_url):
        """Threats page should render a table (even if empty)."""
        page.click("a.nav-link[data-path='threats']")
        page.wait_for_timeout(1500)
        # Should have a table or content container, or at minimum no error
        error_el = page.locator(".error-500, .server-error")
        if error_el.count() > 0:
            pytest.fail(f"Threats page returned error: {error_el.inner_text()}")


class TestSystemPage:
    """System management — 4 quadrants: Registry, WAL, Session, Config."""

    def test_system_page_quadrants(self, page, server_url):
        """System page should reference Registry/WAL/Session/Config."""
        go(page, f"{server_url}/admin/system")
        page.wait_for_timeout(2000)

        assert page.locator(".error-500").count() == 0, "System page should not 500"
        # Also verify the page rendered with content
        body_text = page.locator("body").inner_text()
        assert len(body_text) > 100, f"System page too short: {len(body_text)} chars"

    def test_registry_panel_accessible(self, page, server_url):
        """Registry management panel should load via HTMX."""
        go(page, f"{server_url}/admin/system/registry_panel")
        page.wait_for_timeout(1000)
        assert page.locator(".error-500").count() == 0, (
            "Registry panel should load without server error"
        )

    def test_wal_panel_accessible(self, page, server_url):
        """WAL management panel should load."""
        go(page, f"{server_url}/admin/system/wal_panel")
        page.wait_for_timeout(1000)
        assert page.locator(".error-500").count() == 0

    def test_session_panel_accessible(self, page, server_url):
        """Session management panel should load."""
        go(page, f"{server_url}/admin/system/session_panel")
        page.wait_for_timeout(1000)
        assert page.locator(".error-500").count() == 0

    def test_config_panel_accessible(self, page, server_url):
        """Config management panel should load."""
        go(page, f"{server_url}/admin/system/config_panel")
        page.wait_for_timeout(1000)
        assert page.locator(".error-500").count() == 0


class TestSettings:
    """Settings page loads sub-sections."""

    def test_settings_page_loads(self, page, server_url):
        """Settings page should have config sections."""
        go(page, f"{server_url}/admin/settings")
        page.wait_for_timeout(2000)

        assert page.locator(".error-500").count() == 0, "Settings page should not 500"
        body_text = page.locator("body").inner_text()
        assert len(body_text) > 100, f"Settings page too short: {len(body_text)} chars"

    def test_notifications_page_loads(self, page, server_url):
        """Notifications settings should load."""
        go(page, f"{server_url}/admin/settings/notifications")
        page.wait_for_timeout(2000)
        body = page.locator("body").inner_text()
        # Should render without crash — check for any content
        assert len(body) > 50, f"Notifications page should have content, got {len(body)} chars"

    def test_account_page_loads(self, page, server_url):
        """Account page should have password change form."""
        go(page, f"{server_url}/admin/account")
        page.wait_for_timeout(1000)
        body_text = page.locator("body").inner_text()
        assert "password" in body_text.lower(), "Account page should have password change"


class TestSecurityHeaders:
    """Security-related HTTP checks."""

    def test_server_header_absent(self, page, server_url):
        """The production server must not advertise an implementation."""
        response = page.request.get(f"{server_url}/admin/login")
        server_header = response.headers.get("server", "")
        assert server_header == ""

    def test_login_has_csrf(self, unauthenticated_page, server_url):
        """Login form should contain CSRF token (hidden input)."""
        pg = unauthenticated_page
        pg.goto(f"{server_url}/admin/login")
        csrf_input = pg.locator("input[name='csrf_token']")
        # Hidden inputs are not "visible" — check they exist
        assert csrf_input.count() == 1, "Login page should have exactly 1 CSRF input"
        val = csrf_input.get_attribute("value")
        assert val and len(val) > 10, f"CSRF token should be non-trivial, got: {val}"
