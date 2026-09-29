"""Deep browser checks for configuration, maintenance and expired sessions."""

from __future__ import annotations

import re
from urllib.parse import urlsplit

import pytest
from playwright.sync_api import expect

from .support import PASSWORD


def _open(page, path):
    parsed = urlsplit(page.url)
    page.goto(f"{parsed.scheme}://{parsed.netloc}/admin/{path}")
    expect(page.locator("#main-content")).to_be_visible()


def _confirm(page):
    result = page.locator("#ce-result")
    expect(result.get_by_role("button", name="Confirm save", exact=True)).to_be_visible()
    result.get_by_role("button", name="Confirm save", exact=True).click()
    expect(result).to_contain_text("written")


def test_notification_values_and_full_editor_filters_batch(real_instance):
    page, _, _ = real_instance
    _open(page, "config?view=tree")
    email = page.locator("details.ce-table").filter(
        has=page.locator(":scope > summary > code").filter(has_text=re.compile(r"^\[notifier\.email\]$"))
    )
    if email.get_attribute("open") is None:
        email.locator("summary").click()
    email.locator('input[name="key"]').fill("smtp_host")
    email.locator('input[name="value"]').fill('"mail.e2e.invalid"')
    email.get_by_role("button", name="Add key", exact=True).click()
    _confirm(page)
    page.reload()
    page.get_by_role("button", name="Form", exact=True).click()
    webhook = page.locator('.ce-row[data-path="notifier.webhook.url"]')
    webhook_section = page.locator("details.ce-section").filter(has=webhook)
    if webhook_section.get_attribute("open") is None:
        webhook_section.locator("summary").click()
    scanner = page.locator('.ce-row[data-path="scanner.scan_existing_on_start"]')
    scanner_section = page.locator("details.ce-section").filter(has=scanner)
    if scanner_section.get_attribute("open") is None:
        scanner_section.locator("summary").click()
    original_url = webhook.locator("input.ce-value").input_value()
    webhook.locator("input.ce-value").fill('"http://127.0.0.1:9/e2e"')
    scanner.locator("input.ce-value").fill("true")
    page.get_by_role("button", name="Review changed fields", exact=True).click()
    result = page.locator("#ce-result")
    expect(result).to_contain_text("notifier.webhook.url")
    expect(result).to_contain_text("scanner.scan_existing_on_start")
    expect(result).to_contain_text("restart required")
    _confirm(page)
    page.reload()
    page.get_by_placeholder("Search keys, values and comments...").fill("notifier")
    page.locator('input[name="set_only"]').check()
    expect(page.locator("#ce-list")).to_contain_text("notifier")
    page.locator('input[name="non_default"]').check()
    expect(page.locator("#ce-list")).to_contain_text("notifier")
    _open(page, "settings?open=notifications")
    expect(page.locator("[data-notification-master]")).to_have_attribute("data-notification-master", "on")
    expect(page.locator("#settings-notify")).to_contain_text("mail.e2e.invalid")
    expect(page.locator("#settings-notify")).to_contain_text("127.0.0.1:9/e2e")
    # Restore the test-owned editable value through the same complete editor.
    _open(page, "config?view=form")
    webhook = page.locator('.ce-row[data-path="notifier.webhook.url"]')
    webhook_section = page.locator("details.ce-section").filter(has=webhook)
    if webhook_section.get_attribute("open") is None:
        webhook_section.locator("summary").click()
    scanner = page.locator('.ce-row[data-path="scanner.scan_existing_on_start"]')
    scanner_section = page.locator("details.ce-section").filter(has=scanner)
    if scanner_section.get_attribute("open") is None:
        scanner_section.locator("summary").click()
    webhook.locator("input.ce-value").fill(original_url)
    scanner.locator("input.ce-value").fill("false")
    page.get_by_role("button", name="Review changed fields", exact=True).click()
    expect(page.locator("#ce-result")).to_contain_text("restart required")
    _confirm(page)


def test_system_actions_render_real_results(real_instance):
    page, _, _ = real_instance
    _open(page, "system")
    for panel in (
        "#system-registry-panel",
        "#system-wal-panel",
        "#system-session-panel",
        "#system-config-panel",
    ):
        expect(page.locator(panel)).not_to_contain_text("Loading...")
    for label, panel, text in (
        ("Compact", "#system-registry-panel", "Registry compacted"),
        ("Replay", "#system-wal-panel", "WAL replay"),
        ("Cleanup", "#system-session-panel", "Cleanup done, deleted"),
    ):
        page.once("dialog", lambda dialog: dialog.accept())
        page.get_by_role("button", name=label, exact=True).click()
        expect(page.locator(panel)).to_contain_text(text)
    page.get_by_role("button", name="Reload", exact=True).click()
    expect(page.locator("#system-config-panel")).to_contain_text("Config hot-reload triggered")


@pytest.mark.expected_http_error("/admin/config/editor/history", 401)
def test_session_expiry_from_another_operator_tab(real_instance):
    page, _, _ = real_instance
    _open(page, "config?tab=history")
    second = page.context.new_page()
    try:
        second.goto(page.url)
        page_title = second.locator("#main-content")
        expect(page_title).to_be_visible()
        second.once("dialog", lambda dialog: dialog.accept())
        if second.viewport_size["width"] < 769:
            second.locator(".console-mobile-nav details > summary").click()
            second.locator('.console-mobile-more [data-action="dashboard.logout"]').click()
        else:
            second.locator('#logout-btn[data-action="dashboard.logout"]').click()
        expect(second).to_have_url(re.compile(r".*/admin/login$"))
        page.locator("#ce-history").get_by_role("button", name="Refresh", exact=True).click()
        overlay = page.locator("#session-expired-overlay")
        expect(overlay).to_have_attribute("aria-hidden", "false")
        overlay.get_by_role("button").click()
        expect(page).to_have_url(re.compile(r".*/admin/login$"))
        page.locator("input[name='username']").fill("admin")
        page.locator("input[name='password']").fill(PASSWORD)
        page.locator("button.login-btn").click()
        expect(page).to_have_url(re.compile(r".*/admin/$"))
    finally:
        second.close()
