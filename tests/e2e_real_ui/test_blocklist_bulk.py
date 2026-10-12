"""Browser regressions for cross-page block ledger batch actions."""

from playwright.sync_api import expect

from .test_management_flows import open_page


def _action(page, name):
    """Return a visible action button using the application's action contract."""
    return page.locator(f'[data-action="{name}"]')


def _manual_block(page, site, ips, *, devices=("Device A",)):
    open_page(page, f"blocklist?site={site}")
    page.locator("#bl-ip-input").fill("\n".join(ips))
    for device in devices:
        page.get_by_role("button", name=device, exact=True).click()
    page.once("dialog", lambda dialog: dialog.accept())
    _action(page, "blocklist.manual-block").click()
    result = page.locator("#bl-result")
    expect(result).to_contain_text("DONE", timeout=20_000)
    return result


def _ledger_rows(page):
    return page.locator("#ledger-tbody tr")


def _row(page, site_id, ip):
    return page.locator(
        f'.ledger-checkbox[data-site-id="{site_id}"][data-ip="{ip}"]'
    ).locator("xpath=ancestor::tr")


def _select_devices(page, *devices):
    for device in devices:
        button = page.get_by_role("button", name=device, exact=True)
        classes = button.get_attribute("class") or ""
        if "active" not in classes.split():
            button.click()


def test_ledger_batch_selection_survives_pages_filters_and_cancel(real_instance, external_lab):
    page, _, _ = real_instance
    ips = [f"198.51.100.{number}" for number in range(1, 33)]
    _manual_block(page, "portal", ips)

    # The ledger is read back through its visible page controls, with the
    # cross-page selection contract exercised at the 20-row page boundary.
    expect(page.locator("#ledger-tbody")).to_contain_text(ips[0], timeout=15_000)
    expect(page.locator(".ledger-checkbox[data-site-id][data-ip]")).to_have_count(20)
    _select_devices(page, "Device A")
    _action(page, "blocklist.select-page").click()
    expect(page.locator("#ledger-selected-count")).to_contain_text("20")
    excluded_checkbox = page.locator(".ledger-checkbox:visible").first
    expect(excluded_checkbox).to_be_visible()
    excluded_ip = excluded_checkbox.get_attribute("data-ip")
    assert excluded_ip

    page.locator('#ledger-pagination [data-action="blocklist.page"]').last.click()
    second_page_checkbox = page.locator(".ledger-checkbox:visible").first
    expect(second_page_checkbox).to_be_visible()
    second_page_ip = second_page_checkbox.get_attribute("data-ip")
    assert second_page_ip
    page.locator(f'.ledger-checkbox[data-ip="{second_page_ip}"]').check()
    expect(page.locator("#ledger-selected-count")).to_contain_text("21")

    page.locator("#ledger-search").fill(excluded_ip)
    expect(page.locator(f'.ledger-checkbox[data-ip="{excluded_ip}"]')).to_be_visible()
    expect(page.locator("#ledger-selected-count")).to_contain_text("21")
    page.locator(f'.ledger-checkbox[data-ip="{excluded_ip}"]').uncheck()
    expect(page.locator("#ledger-selected-count")).to_contain_text("20")

    page.locator("#ledger-search").fill("")
    expect(page.locator("#ledger-tbody")).to_contain_text(excluded_ip)
    page.once("dialog", lambda dialog: dialog.dismiss())
    _action(page, "blocklist.batch-unblock").click()
    expect(page.locator("#ledger-selected-count")).to_contain_text("20")
    expect(page.locator("#ledger-batch-results [data-outcome]")).to_have_count(0)
    assert "blocked" in _row(page, "portal", excluded_ip).inner_text().lower()

    page.once("dialog", lambda dialog: dialog.accept())
    _action(page, "blocklist.batch-unblock").click()
    results = page.locator("#ledger-batch-results")
    expect(results).to_contain_text("20", timeout=20_000)
    expect(page.locator("#ledger-selected-count")).to_contain_text("0")
    page.locator("#ledger-search").fill(second_page_ip)
    second_page_row = _row(page, "portal", second_page_ip)
    expect(second_page_row).to_be_visible()
    assert "unblocked" in second_page_row.inner_text().lower()
    page.locator("#ledger-search").fill(excluded_ip)
    excluded_row = _row(page, "portal", excluded_ip)
    expect(excluded_row).to_be_visible()
    assert "blocked" in excluded_row.inner_text().lower()
    page.locator("#ledger-search").fill("")

    # The visible external lab page proves only selected IPs reached Device A.
    lab_page = page.context.new_page()
    lab_page.goto(external_lab.url)
    lab_page.get_by_role("link", name="Refresh receipts", exact=True).click()
    receipts = lab_page.locator("tbody")
    expect(receipts).to_contain_text("device-a/unblock")
    expect(receipts).to_contain_text(second_page_ip)
    excluded_receipts = receipts.locator("tr").filter(has_text=excluded_ip)
    expect(excluded_receipts).not_to_contain_text("device-a/unblock")


def test_ledger_batch_partial_device_failure_retry_and_scope_reset(real_instance, external_lab):
    page, _, _ = real_instance
    shared_ip = "198.51.100.77"
    _manual_block(page, "portal", [shared_ip])
    _manual_block(page, "shop", [shared_ip])

    lab_page = page.context.new_page()
    lab_page.goto(external_lab.url)
    lab_page.get_by_role("button", name="Fail device B", exact=True).click()
    open_page(page, "blocklist?site=")
    expect(page.locator('.ledger-checkbox[data-site-id][data-ip]')).to_have_count(2)
    portal_row = _row(page, "portal", shared_ip)
    shop_row = _row(page, "shop", shared_ip)
    expect(portal_row).to_contain_text("Portal test site")
    expect(shop_row).to_contain_text("Shop test site")
    portal_row.locator(".ledger-checkbox").check()
    shop_row.locator(".ledger-checkbox").check()
    expect(page.locator("#ledger-selected-count")).to_contain_text("2")
    _select_devices(page, "Device A", "Device B")

    page.once("dialog", lambda dialog: dialog.accept())
    _action(page, "blocklist.batch-block").click()
    results = page.locator("#ledger-batch-results")
    expect(results).to_contain_text("FAIL", timeout=20_000)
    expect(results).to_contain_text(shared_ip)
    expect(page.locator("#ledger-selected-count")).to_contain_text("2")
    lab_page.get_by_role("link", name="Refresh receipts", exact=True).click()
    expect(lab_page.locator("tbody")).to_contain_text("device-b/block")

    lab_page.get_by_role("button", name="Recover device", exact=True).click()
    page.once("dialog", lambda dialog: dialog.accept())
    _action(page, "blocklist.batch-block").click()
    expect(results).to_contain_text("succeeded", timeout=20_000)
    expect(page.locator("#ledger-selected-count")).to_contain_text("0")
    lab_page.get_by_role("link", name="Refresh receipts", exact=True).click()
    expect(lab_page.locator("tbody")).to_contain_text("device-b/block")

    open_page(page, "blocklist?site=portal")
    expect(page.locator("#ledger-selected-count")).to_contain_text("0")
    expect(page.locator(".ledger-checkbox[data-site-id='portal']")).to_have_count(1)
