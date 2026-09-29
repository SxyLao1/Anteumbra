"""Browser-visible operator edges: confirmations, pagination, and receipts."""

from __future__ import annotations

import re
from urllib.parse import parse_qs, urlsplit

from playwright.sync_api import expect

from .test_management_flows import open_page


def _wait_for_profile(page) -> None:
    for _ in range(15):
        if page.locator(".profile-card").count():
            return
        page.wait_for_timeout(1000)
        page.reload()
    expect(page.locator(".profile-card").first).to_be_visible()


def test_settings_maintenance_confirmation_cancel_and_success(real_instance):
    page, _, _ = real_instance
    open_page(page, "settings?open=advanced")
    page.get_by_role("button", name="Registry Status", exact=True).click()
    modal = page.locator("#system-modal")
    expect(modal).to_contain_text("Registry")
    action = modal.get_by_role("button", name="Compact", exact=True)
    page.once("dialog", lambda dialog: dialog.dismiss())
    action.click()
    expect(modal).not_to_contain_text("Registry compacted")
    page.once("dialog", lambda dialog: dialog.accept())
    action.click()
    expect(modal).to_contain_text("Registry compacted")


def test_profile_ip_selection_survives_page_change_into_blocklist_form(real_instance, external_lab):
    page, _, _ = real_instance
    lab_page = page.context.new_page()
    try:
        lab_page.goto(external_lab.url)
        lab_page.get_by_role("button", name="Generate 37 Portal IP WAF events", exact=True).click()
        expect(lab_page.locator("#event-count")).to_have_text("37 WAF events")

        open_page(page, "profiles?site=portal")
        _wait_for_profile(page)
        page.locator(".profile-card").first.click()
        detail = page.locator(".profile-detail-view")
        expect(detail).to_have_attribute("data-site-id", "portal")
        profile_id = detail.locator(".profile-summary-grid code").first.inner_text()
        first_ip = detail.locator(".ip-checkbox").first.input_value()
        detail.locator(".ip-checkbox").first.check()
        detail.locator("#ip-table-section").get_by_role("button", name="Next", exact=True).click()
        expect(detail.locator(".page-info")).to_contain_text("2 / 2")
        second_ip = detail.locator(".ip-checkbox").first.input_value()
        detail.locator(".ip-checkbox").first.check()
        expect(detail.locator("#ip-selected-count")).to_contain_text("2 selected")
        detail.get_by_role("button", name="Block 2 IP(s)", exact=True).click()
        expect(page).to_have_url(re.compile(r".*/admin/blocklist\?.+"))
        query = parse_qs(urlsplit(page.url).query)
        assert query.get("site") == ["portal"]
        assert query.get("profile_id") == [profile_id]
        values = page.locator("#bl-ip-input").input_value().splitlines()
        assert {first_ip, second_ip}.issubset(values)
        expect(page.locator("#bl-target-site")).to_have_value("portal")
    finally:
        lab_page.close()


def test_blocklist_two_ips_two_devices_show_each_partial_receipt(real_instance, external_lab):
    page, _, _ = real_instance
    lab_page = page.context.new_page()
    try:
        lab_page.goto(external_lab.url)
        lab_page.get_by_role("button", name="Fail device B", exact=True).click()
        open_page(page, "blocklist?site=portal")
        page.locator("#bl-ip-input").fill("198.51.100.70\n198.51.100.71")
        page.get_by_role("button", name="Device A", exact=True).click()
        page.get_by_role("button", name="Device B", exact=True).click()
        page.once("dialog", lambda dialog: dialog.accept())
        page.get_by_role("button", name="Block", exact=True).click()
        result = page.locator("#bl-result")
        for ip in ("198.51.100.70", "198.51.100.71"):
            expect(result).to_contain_text("OK Device A: " + ip)
            expect(result).to_contain_text("FAIL Device B: " + ip)
    finally:
        lab_page.close()
