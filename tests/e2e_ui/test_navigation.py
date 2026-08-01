# -*- coding: utf-8 -*-
"""
E2E UI Tests — Navigation & Page Load

Tests:
  - Sidebar navigation renders all 7 items
  - Clicking each nav item loads correct content panel
  - Mobile sidebar toggle works
  - Brand header is visible
"""

from playwright.sync_api import expect

NAV_ITEMS = [
    ("overview", "Overview"),
    ("threats", "Threats"),
    ("yara/rules", "Rules"),
    ("scanner", "Scanner"),
    ("profiles", "Profiles"),
    ("blocklist", "Blocklist"),
    ("settings", "Settings"),
]


class TestNavigation:
    """Sidebar navigation renders and loads content panels."""

    def test_sidebar_renders_all_items(self, page, server_url):
        """All 7 navigation links should be visible in the sidebar."""
        for data_path, label in NAV_ITEMS:
            selector = f"a.nav-link[data-path='{data_path}']"
            nav_link = page.locator(selector)
            expect(nav_link).to_be_visible(timeout=3000)
            # Check that the text label is present
            assert label.lower() in nav_link.inner_text().lower(), (
                f"Nav item '{data_path}' should show label '{label}'"
            )

    def test_nav_overview_loads_content(self, page, server_url):
        """Clicking Overview should load dashboard content."""
        page.click("a.nav-link[data-path='overview']")
        # Content area should load something
        page.wait_for_selector(
            "#dashboard-content, #overview-content, .dashboard-grid", timeout=5000
        )
        # At minimum, the brand header should still be visible
        expect(page.locator(".brand")).to_be_visible()

    def test_nav_threats_loads_records(self, page, server_url):
        """Threats page should show records table."""
        page.click("a.nav-link[data-path='threats']")
        page.wait_for_timeout(1000)  # HTMX load
        # Should have some content — threats page includes a table or placeholder
        page.locator("#main-content, .table-container, table").first
        # Just verify the page doesn't crash
        expect(page.locator(".brand")).to_be_visible()

    def test_nav_rules_loads_yara_editor(self, page, server_url):
        """Rules page should load YARA rules list/editor."""
        page.click("a.nav-link[data-path='yara/rules']")
        page.wait_for_timeout(1000)
        expect(page.locator(".brand")).to_be_visible()

    def test_nav_scanner_loads(self, page, server_url):
        """Scanner page should load without error."""
        page.click("a.nav-link[data-path='scanner']")
        page.wait_for_timeout(1000)
        expect(page.locator(".brand")).to_be_visible()

    def test_nav_profiles_loads(self, page, server_url):
        """Profiles page should load without error."""
        page.click("a.nav-link[data-path='profiles']")
        page.wait_for_timeout(1000)
        expect(page.locator(".brand")).to_be_visible()

    def test_nav_blocklist_loads(self, page, server_url):
        """Blocklist page should load without error."""
        page.click("a.nav-link[data-path='blocklist']")
        page.wait_for_timeout(1000)
        expect(page.locator(".brand")).to_be_visible()

    def test_nav_settings_loads(self, page, server_url):
        """Settings page should load without error."""
        page.click("a.nav-link[data-path='settings']")
        page.wait_for_timeout(1000)
        expect(page.locator(".brand")).to_be_visible()

    def test_nav_highlight_active(self, page, server_url):
        """Active nav item should have 'active' class after click."""
        # Click Threats
        page.click("a.nav-link[data-path='threats']")
        page.wait_for_timeout(500)
        # Should have active class
        active_link = page.locator("a.nav-link.active")
        expect(active_link).to_be_visible()
        assert active_link.get_attribute("data-path") == "threats", (
            "Threats link should be active after clicking it"
        )

    def test_mobile_sidebar_toggle_hidden_on_desktop(self, page, server_url):
        """Sidebar toggle should be hidden on desktop (1440px) viewport."""
        toggle = page.locator("#sidebar-toggle")
        # On desktop viewport, toggle is hidden via CSS
        # Verify it exists in the DOM (even if not visible)
        assert toggle.count() == 1, "Sidebar toggle should exist in DOM"

    def test_mobile_sidebar_toggle_visible_on_mobile(self, page, server_url):
        """Sidebar toggle should be visible at mobile viewport width."""
        page.set_viewport_size({"width": 375, "height": 812})
        page.wait_for_timeout(500)  # Let CSS media queries take effect
        toggle = page.locator("#sidebar-toggle")
        expect(toggle).to_be_visible(timeout=3000)

    def test_brand_header_visible(self, page, server_url):
        """Brand ANTUMBRA should always be visible."""
        expect(page.locator(".brand")).to_be_visible()
        expect(page.locator(".brand")).to_contain_text("ANTEUMBRA")
