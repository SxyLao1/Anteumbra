"""Browser acceptance for the live console shell; routes are exercised as an operator sees them."""

from __future__ import annotations

import os
import re
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

from playwright.sync_api import expect

ARTIFACTS = Path(
    os.environ.get("ANTEUMBRA_UI_ARTIFACTS", Path(tempfile.gettempdir()) / "anteumbra-ui-artifacts")
)


def origin(page):
    parsed = urlsplit(page.url)
    return f"{parsed.scheme}://{parsed.netloc}"


def screenshot(page, name):
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    page.screenshot(path=str(ARTIFACTS / name), full_page=True)


def open_workspace(page, name):
    if page.viewport_size["width"] <= 768:
        more = page.locator(".console-mobile-nav details")
        if more.get_attribute("open") is None:
            more.locator("summary").click()
        more.get_by_role("button", name="Change site scope").click()
    link = page.locator(f'[data-console-workspaces] [data-workspace="{name}"]')
    expect(link).to_be_visible()
    link.click()
    expect(page.locator("#main-content > .empty-state .spinner")).to_have_count(0)


def test_workspace_navigation_context_language_theme_and_history(real_instance):
    page, _, _ = real_instance
    workspace = page.locator("[data-console-workspaces] .nav-link")
    expect(workspace).to_have_count(6)
    expected = ["duty", "investigate", "respond", "protect", "settings", "system"]
    for name in expected:
        open_workspace(page, name)
        expect(page.locator("#console-context-nav a").first).to_be_visible()
        expect(page.locator(f'[data-console-workspaces] [data-workspace="{name}"]')).to_have_class(
            "nav-link active"
        )
        # Every contextual link is a visible public route, never an invented endpoint.
        count = page.locator("#console-context-nav a").count()
        for index in range(count):
            context_link = page.locator("#console-context-nav a").nth(index)
            destination = context_link.get_attribute("href")
            context_link.click()
            expect(page).to_have_url(origin(page) + destination)
            expect(page.locator("#main-content > .empty-state .spinner")).to_have_count(0)
            expect(page.locator("#main-content")).to_be_visible()
            expect(page.locator("#main-content")).not_to_contain_text("Failed to load")

    # Settings uses its public bookmark route including the expanded-section query.
    open_workspace(page, "settings")
    expect(page).to_have_url(origin(page) + "/admin/settings?open=notifications,plugins")
    site = page.locator("#site-switcher")
    if page.viewport_size["width"] > 768:
        site.select_option("portal")
    else:
        page.goto(origin(page) + "/admin/settings?open=notifications,plugins&site=portal")
    expect(page).to_have_url(re.compile(r"[?&]site=portal(?:&|$)"))
    current = page.url
    page.get_by_title("English").click()
    expect(page).to_have_url(re.compile(r"[?&]lang=en(?:&|$)"))
    assert "site=portal" in page.url and "open=notifications" in page.url and "plugins" in page.url
    expect(page.locator('[data-console-workspaces] [data-workspace="settings"]')).to_contain_text(
        "Settings"
    )
    page.locator(".console-theme-toggle").click()
    expect(page.locator("body")).to_have_attribute("data-console-theme", "light")
    expect(page.locator("body")).to_have_css("--color-bg", "#f2f5f0")
    page.go_back()
    expect(page).to_have_url(current)
    page.reload()
    expect(page.locator("#main-content")).to_be_visible()
    page.get_by_role("link", name="中文", exact=True).click()
    expect(page.locator("html")).to_have_attribute("lang", "zh")
    expect(page.locator("#console-context-nav")).to_contain_text("通知")
    expect(page.locator("#settings-notify")).to_contain_text("启用")
    assert "site=portal" in page.url and "plugins" in page.url
    screenshot(page, "shell-navigation-success.png")


def test_shell_bookmarks_and_mobile_scope_geometry(real_instance):
    page, _, _ = real_instance
    paths = (
        "overview",
        "threats",
        "logs/analyzer",
        "scanner",
        "profiles",
        "file-clusters",
        "quarantine",
        "blocklist",
        "sites",
        "yara/rules",
        "memory-shell",
        "memory-shell/forensics",
        "settings?open=notifications,plugins",
        "config",
        "system",
    )
    if page.viewport_size["width"] < 769:
        paths = (
            "overview",
            "threats",
            "quarantine",
            "sites",
            "settings?open=notifications,plugins",
            "system",
        )
    for path in paths:
        page.goto(origin(page) + "/admin/" + path)
        expect(page.locator("#main-content")).to_be_visible()
        expect(page.locator("#console-context-nav a").first).to_be_visible()

    for width in (320, 768, 1440):
        page.set_viewport_size({"width": width, "height": 900})
        page.goto(origin(page) + "/admin/settings?open=notifications,plugins")
        expect(page.locator("#main-content")).to_be_visible()
        if width < 769:
            expect(page.locator(".site-badge")).to_be_visible()
            expect(page.locator(".console-mobile-nav")).to_be_visible()
        # Check actual essential controls instead of only document width.
        for selector in (
            "#main-content",
            "#console-context-nav",
            ".lang-switch",
            ".console-theme-toggle",
        ):
            box = page.locator(selector).bounding_box()
            assert box is not None and box["width"] > 0 and box["x"] + box["width"] <= width + 1, (
                width,
                selector,
                box,
            )
        screenshot(page, f"shell-geometry-{width}.png")


def test_cancel_navigation_and_browser_back_preserves_unsaved_form(real_instance):
    page, _, _ = real_instance
    open_workspace(page, "settings")
    page.locator("#console-context-nav").get_by_role("link", name="Config editor", exact=True).click()
    page.get_by_role("button", name="Raw", exact=True).click()
    raw = page.locator("textarea[name=raw_text]")
    draft = raw.input_value() + "\n# unsaved browser draft\n"
    raw.fill(draft)
    before = page.url
    page.once("dialog", lambda dialog: dialog.dismiss())
    page.locator("#console-context-nav").get_by_role("link", name="Notifications", exact=True).click()
    expect(page).to_have_url(before)
    expect(raw).to_have_value(draft)
    page.once("dialog", lambda dialog: dialog.dismiss())
    page.go_back()
    expect(page).to_have_url(before)
    expect(raw).to_have_value(draft)
    # Explicitly accepting navigation does discard the unsaved draft.
    page.once("dialog", lambda dialog: dialog.accept())
    page.locator("#console-context-nav").get_by_role("link", name="Notifications", exact=True).click()
    expect(page.locator("#settings-notify")).to_be_visible()
