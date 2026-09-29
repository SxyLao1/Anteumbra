"""Real monitor-to-browser detection and recovery; no registry or API seeding."""

from playwright.sync_api import expect


def _wait_for_webhook_receipt(lab_page, filename: str, minimum_rows: int = 1) -> None:
    """Read only the counterpart's public receipt page, never its private state."""
    for _ in range(30):
        matching = (
            lab_page.locator("tbody tr")
            .filter(has=lab_page.get_by_role("cell", name="webhook", exact=True))
            .filter(has_text=filename)
        )
        if matching.count() >= minimum_rows:
            return
        lab_page.get_by_role("link", name="Refresh receipts").click()
        lab_page.wait_for_timeout(500)
    assert matching.count() >= minimum_rows, (
        f"expected {minimum_rows} webhook receipt(s) for {filename}, got {matching.count()}"
    )


def test_monitor_detects_quarantines_and_restores_only_portal_instance(real_instance, external_lab):
    page, portal, shop = real_instance
    portal_file, shop_file = portal / "marker.php", shop / "marker.php"
    # Sole allowed business input: harmless marker files in test-owned roots.
    portal_file.write_text("<?php /* ANTEUMBRA_E2E_MARKER */ ?>", encoding="utf-8")
    shop_file.write_text("<?php /* ANTEUMBRA_E2E_MARKER */ ?>", encoding="utf-8")
    # A user bookmark is a public UI navigation path and avoids shell-specific nav markup.
    page.goto(page.url.split("/admin/")[0] + "/admin/threats")
    records = page.locator("#records-table-container")
    expect(records.locator(".record-item").filter(has_text="marker.php")).to_have_count(
        2, timeout=20000
    )
    portal_row = records.locator(".record-item[data-site-id='portal']").filter(
        has_text="marker.php"
    )
    shop_row = records.locator(".record-item[data-site-id='shop']").filter(has_text="marker.php")
    expect(portal_row).to_be_visible()
    expect(shop_row).to_be_visible()
    lab_page = page.context.new_page()
    try:
        lab_page.goto(external_lab.url)
        _wait_for_webhook_receipt(lab_page, portal_file.name)
    finally:
        lab_page.close()
    page.get_by_role("link", name="中文", exact=True).click()
    portal_row.get_by_role("button", name="详情", exact=True).click()
    detail = page.locator("#record-detail-modal")
    expect(detail).to_contain_text("累计计数；此处不提供逐次请求历史。")
    expect(detail.get_by_role("button", name="查看源码", exact=True)).to_be_enabled()
    detail.get_by_role("button", name="查看源码", exact=True).click()
    expect(page.get_by_role("dialog", name="File source viewer")).to_contain_text("ANTEUMBRA_E2E_MARKER")
    page.keyboard.press("Escape")
    expect(page.get_by_role("dialog", name="File source viewer")).not_to_be_visible()
    expect(detail).to_be_visible()
    detail.locator("button.modal-close").click()
    page.get_by_title("English").click()
    portal_row.get_by_role("button", name="Source").click()
    expect(page.get_by_role("dialog", name="File source viewer")).to_contain_text(
        "ANTEUMBRA_E2E_MARKER"
    )
    page.keyboard.press("Escape")
    portal_row.locator("input.rec-checkbox").check()
    page.once("dialog", lambda dialog: dialog.accept())
    page.get_by_role("button", name="Quarantine").click()
    page.get_by_role("tab", name="Quarantine").click()
    quarantine = page.locator("#quarantine-list-container")
    portal_quarantine = quarantine.locator(".record-item[data-site-id='portal']")
    expect(portal_quarantine).to_contain_text("marker.php", timeout=10000)
    page.once("dialog", lambda dialog: dialog.accept())
    portal_quarantine.get_by_role("button", name="Restore").click()
    expect(quarantine.locator(".record-item[data-site-id='portal']")).to_contain_text(
        "RESTORED", timeout=10000
    )
    assert portal_file.read_text(encoding="utf-8") == "<?php /* ANTEUMBRA_E2E_MARKER */ ?>"
    expect(quarantine.locator(".record-item[data-site-id='shop']")).to_have_count(0)
