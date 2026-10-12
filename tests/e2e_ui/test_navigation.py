# -*- coding: utf-8 -*-
"""E2E UI navigation coverage for the V3 workspace shell."""


from playwright.sync_api import expect

from .conftest import open_console_route

PRIMARY_ITEMS = [
    ("Duty desk", "/admin/overview"),
    ("Detection & investigation", "/admin/threats"),
    ("Response & review", "/admin/quarantine"),
    ("Sites & protection", "/admin/sites"),
    ("Settings", "/admin/settings?open=notifications,plugins"),
    ("System maintenance", "/admin/system"),
]


class TestNavigation:
    """Visible workspaces and their context links replace legacy flat navigation."""

    def test_sidebar_renders_primary_workspaces(self, page, server_url):
        navigation = page.get_by_role("navigation", name="Primary navigation")
        for label, href in PRIMARY_ITEMS:
            link = navigation.get_by_role("link", name=label, exact=True)
            expect(link).to_be_visible(timeout=3000)
            assert link.get_attribute("href") == href

    def test_nav_overview_loads_content(self, page, server_url):
        open_console_route(page, "overview")
        expect(page.locator("[data-testid='overview-grid']")).to_be_visible(timeout=5000)

    def test_nav_threats_loads_records(self, page, server_url):
        open_console_route(page, "threats")
        expect(page.locator("#records-table-container")).to_be_visible(timeout=5000)

    def test_nav_rules_loads_yara_editor(self, page, server_url):
        open_console_route(page, "yara/rules")
        expect(page.locator("#yara-rules-container")).to_be_visible(timeout=5000)

    def test_nav_scanner_loads(self, page, server_url):
        open_console_route(page, "scanner")
        expect(page.locator("#scan-target-dir")).to_be_visible(timeout=5000)

    def test_nav_profiles_loads(self, page, server_url):
        open_console_route(page, "profiles")
        expect(page.locator(".profiles-view")).to_be_visible(timeout=5000)

    def test_nav_blocklist_loads(self, page, server_url):
        open_console_route(page, "blocklist")
        expect(page.locator(".blocklist-view")).to_be_visible(timeout=5000)

    def test_nav_settings_loads(self, page, server_url):
        open_console_route(page, "settings")
        expect(page.locator("[data-settings-panel]").first).to_be_visible(timeout=5000)

    def test_context_link_is_active_after_navigation(self, page, server_url):
        open_console_route(page, "threats")
        active_link = page.locator('#console-context-nav a[aria-current="page"]')
        expect(active_link).to_have_attribute("href", "/admin/threats")

    def test_mobile_sidebar_toggle_hidden_on_desktop(self, page, server_url):
        expect(page.get_by_role("navigation", name="Mobile navigation")).to_be_hidden()
        assert page.locator("#sidebar-toggle").count() == 1

    def test_mobile_navigation_visible_on_mobile(self, page, server_url):
        page.set_viewport_size({"width": 375, "height": 812})
        mobile = page.get_by_role("navigation", name="Mobile navigation")
        expect(mobile).to_be_visible(timeout=3000)
        expect(mobile.get_by_role("link", name="Duty", exact=True)).to_be_visible()
        expect(mobile.get_by_text("More", exact=True)).to_be_visible()

    def test_brand_header_visible(self, page, server_url):
        expect(page.locator(".brand")).to_be_visible()
        expect(page.locator(".brand")).to_contain_text("ANTEUMBRA")


class TestShellBootstrap:
    """Direct navigation must keep the server-rendered content."""

    @staticmethod
    def _go(page, url):
        page.goto("about:blank", wait_until="commit", timeout=10000)
        page.wait_for_timeout(200)
        return page.goto(url, wait_until="commit", timeout=20000)

    def test_quarantine_keeps_its_own_content(self, page, server_url):
        self._go(page, f"{server_url}/admin/quarantine")
        page.wait_for_selector("#quarantine-list-container", timeout=10000)
        page.wait_for_timeout(1500)
        main = page.locator("#main-content").inner_text()
        assert "QUARANTINE" in main.upper() or "Restore" in main, (
            f"quarantine content missing after load: {main[:200]}"
        )
        assert "TOTAL DETECTIONS" not in main, "shell replaced the page with Overview"

    def test_quarantine_page_carries_sse_token(self, page, server_url):
        self._go(page, f"{server_url}/admin/quarantine")
        page.wait_for_selector("#quarantine-list-container", timeout=10000)
        token = page.get_attribute("meta[name='sse-token']", "content")
        assert token, "sse-token meta tag is empty on the quarantine page"
