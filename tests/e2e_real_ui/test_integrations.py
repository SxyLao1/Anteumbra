"""Actual product HTTP/UDP integrations; test control and receipts use browser UI."""
import json
import re

from playwright.sync_api import expect

from .test_management_flows import download_text, open_page


def test_blocking_device_results_site_isolation_notes_exports(real_instance, external_lab):
    page, _, _ = real_instance
    lab_page = page.context.new_page()
    lab_page.goto(external_lab.url)
    lab_page.get_by_role("button", name="Fail device B").click()
    open_page(page, "blocklist?site=portal")
    page.locator("#bl-ip-input").fill("198.51.100.24")
    page.locator("#bl-reason-input").fill("Browser investigation")
    page.get_by_role("button", name="Device A", exact=True).click()
    page.get_by_role("button", name="Device B", exact=True).click()
    page.once("dialog", lambda dialog: dialog.accept())
    page.get_by_role("button", name="Block", exact=True).click()
    expect(page.locator("#bl-result")).to_contain_text("OK Device A")
    expect(page.locator("#bl-result")).to_contain_text("FAIL Device B")
    row = page.locator("#ledger-tbody tr").filter(has_text="198.51.100.24")
    expect(row).to_contain_text("Portal test site")
    row.locator(".notes-cell").click()
    row.locator("input").fill("Reviewed by browser")
    row.locator("input").press("Enter")
    expect(row).to_contain_text("Reviewed by browser")
    receipt = download_text(page, page.get_by_role("button", name="Export JSON", exact=True))
    assert "portal" in receipt and "198.51.100.24" in receipt
    lab_page.get_by_role("link", name="Refresh receipts").click()
    expect(lab_page.locator("tbody")).to_contain_text('"site_id": "portal"')
    expect(lab_page.locator("tbody")).to_contain_text("device-b/block")
    open_page(page, "blocklist?site=shop")
    expect(page.locator("#ledger-tbody")).to_contain_text("No block records found.")
    lab_page.get_by_role("button", name="Recover device").click()
    open_page(page, "blocklist?site=portal")
    page.locator("#bl-ip-input").fill("198.51.100.24")
    page.get_by_role("button", name="Device A", exact=True).click()
    page.get_by_role("button", name="Device B", exact=True).click()
    page.once("dialog", lambda dialog: dialog.accept())
    page.get_by_role("button", name="Unblock", exact=True).click()
    expect(page.locator("#bl-result")).to_contain_text("OK Device B")
    lab_page.get_by_role("link", name="Refresh receipts").click()
    expect(lab_page.locator("tbody")).to_contain_text("device-a/unblock")
    assert "198.51.100.24" in download_text(page, page.get_by_role("button", name="Export CSV", exact=True))
    page.get_by_role("link", name="中文", exact=True).click()
    lab_page.get_by_role("button", name="Fail device B").click()
    page.locator("#bl-ip-input").fill("198.51.100.26")
    page.get_by_role("button", name="Device A", exact=True).click()
    page.get_by_role("button", name="Device B", exact=True).click()
    page.once("dialog", lambda dialog: dialog.accept())
    page.locator('[data-action="blocklist.manual-block"]').click()
    expect(page.locator("#bl-result")).to_contain_text("成功 Device A")
    expect(page.locator("#bl-result")).to_contain_text("失败 Device B")
    lab_page.get_by_role("link", name="Refresh receipts").click()
    expect(lab_page.locator("tbody")).to_contain_text("198.51.100.26")


def test_detection_siem_stream_downloads_and_waf_profiles(real_instance, external_lab):
    page, portal, _ = real_instance
    (portal / "siem-marker.php").write_text("<?php /* ANTEUMBRA_E2E_MARKER */ ?>", encoding="utf-8")
    open_page(page, "threats?site=portal")
    expect(page.locator("#records-table-container")).to_contain_text("siem-marker.php", timeout=20000)
    open_page(page, "settings?open=advanced")
    panel = page.locator("#settings-siem")
    expect(panel).to_contain_text("ACTIVE")
    jsonl = download_text(page, panel.get_by_role("button", name="Export JSON Lines"))
    events = [json.loads(line) for line in jsonl.splitlines() if line]
    assert any(item["source"]["site_id"] == "portal" for item in events)
    assert "CEF:" in download_text(page, panel.get_by_role("button", name="Export CEF"))
    csv = download_text(page, panel.get_by_role("button", name="Export CSV"))
    assert "siem-marker.php" in csv and not csv.startswith("{")
    # The live exporter must keep JSON Lines after CEF/CSV snapshot downloads.
    page.reload()
    expect(panel).to_contain_text("JSON_LINES")
    lab_page = page.context.new_page()
    lab_page.goto(external_lab.url)
    expect(lab_page.locator("tbody")).to_contain_text("syslog")
    expect(lab_page.locator("tbody")).to_contain_text("siem-marker.php")
    lab_page.get_by_role("button", name="Generate Portal WAF events").click()
    expect(lab_page.locator("#event-count")).to_have_text("12 WAF events")
    # Browser refresh is the same user action as revisiting the profiles page.
    open_page(page, "profiles?site=portal")
    for _ in range(15):
        if "sqlmap" in page.locator("#main-content").inner_text().lower():
            break
        page.wait_for_timeout(1000)
        page.reload()
    expect(page.locator("#main-content")).to_contain_text("sqlmap", ignore_case=True)
    open_page(page, "profiles?site=shop")
    expect(page.locator("#main-content")).not_to_contain_text("sqlmap", ignore_case=True)


def test_blocking_target_site_redirects_to_its_ledger(real_instance, external_lab):
    page, _, _ = real_instance
    lab_page = page.context.new_page()
    try:
        lab_page.goto(external_lab.url)
        open_page(page, "blocklist?site=portal")
        page.locator("#bl-ip-input").fill("198.51.100.25")
        page.locator("#bl-target-site").select_option("shop")
        page.get_by_role("button", name="Device A", exact=True).click()
        page.once("dialog", lambda dialog: dialog.accept())
        page.get_by_role("button", name="Block", exact=True).click()
        expect(page.locator("#bl-result")).to_contain_text("OK Device A", timeout=15000)
        page.get_by_role("link", name="View target site ledger", exact=True).click()
        expect(page).to_have_url(re.compile(r".*/admin/blocklist\?site=shop$"), timeout=5000)
        expect(page.locator("#bl-target-site")).to_have_value("shop")
        row = page.locator("#ledger-tbody tr").filter(has_text="198.51.100.25")
        expect(row).to_contain_text("Shop test site")
        lab_page.get_by_role("link", name="Refresh receipts").click()
        expect(lab_page.locator("tbody")).to_contain_text('"site_id": "shop"')
    finally:
        lab_page.close()
