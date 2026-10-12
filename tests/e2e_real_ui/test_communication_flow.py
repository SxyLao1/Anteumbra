"""Access-log inputs must become precise, site-owned UI communication counts."""

from datetime import datetime

import pytest
from playwright.sync_api import expect


def append_access(log_path, urls):
    stamp = datetime.now().astimezone().strftime("%d/%b/%Y:%H:%M:%S %z")
    with log_path.open("a", encoding="utf-8") as stream:
        for url in urls:
            stream.write(
                f'198.51.100.77 - - [{stamp}] "POST {url} HTTP/1.1" '
                '200 20 "-" "BrowserAcceptance/1.0"\n'
            )


def wait_for_count(page, row, count):
    for _ in range(25):
        if row.count() and f"Comm: {count}" in row.inner_text():
            return
        page.reload()
        page.wait_for_timeout(300)
    expect(row).to_contain_text(f"Comm: {count}")


@pytest.mark.access_logs
def test_communications_match_exact_site_relative_path_and_survive_navigation(real_instance):
    page, portal, shop = real_instance
    nested = portal / "nested"
    nested.mkdir()
    for target in (portal / "shared.php", nested / "shared.php", portal / "sentinel.php", shop / "shared.php"):
        target.write_text("<?php /* ANTEUMBRA_E2E_MARKER */ ?>", encoding="utf-8")
    base = page.url.split("/admin/")[0]
    page.goto(base + "/admin/threats?site=")
    rows = page.locator("#records-table-container .record-item")
    for _ in range(25):
        if rows.count() == 4:
            break
        page.reload()
        page.wait_for_timeout(300)
    expect(rows).to_have_count(4, timeout=20000)
    portal_shared = rows.locator("xpath=self::*[@data-site-id='portal']").filter(has_text="shared.php")
    root_row = portal_shared.locator("xpath=self::*[not(contains(@data-path, 'nested'))]")
    nested_row = portal_shared.locator("xpath=self::*[contains(@data-path, 'nested')]")
    shop_row = rows.locator("xpath=self::*[@data-site-id='shop']")
    sentinel = rows.filter(has_text="sentinel.php")
    for row in (root_row, nested_row, shop_row, sentinel):
        expect(row).to_contain_text("Comm: 0")

    logs = portal.parents[1] / "test-inputs"
    append_access(logs / "portal-access.log", [
        "/shared.php.backup", "/other/shared.php", "/shared.php?test=1",
        "/nested/shared.php", "/nested/shared.php?test=2", "/sentinel.php",
    ])
    append_access(logs / "shop-access.log", ["/shared.php"])
    # The last marker proves preceding non-matching input has been processed;
    # no short sleep is used as proof that a request was ignored.
    wait_for_count(page, sentinel, 1)
    wait_for_count(page, shop_row, 1)
    expect(root_row).to_contain_text("Comm: 1")
    expect(nested_row).to_contain_text("Comm: 2")

    append_access(logs / "portal-access.log", ["/shared.php?test=next"])
    wait_for_count(page, root_row, 2)
    expect(shop_row).to_contain_text("Comm: 1")
    root_row.get_by_role("button", name="Detail", exact=True).click()
    detail = page.locator("#record-detail-modal")
    communication = detail.locator("tr").filter(has=page.get_by_role("cell", name="Communications", exact=True))
    expect(communication.locator("td").nth(1)).to_have_text("2 Cumulative count; request history is not available here.")
    page.keyboard.press("Escape")
    page.goto(base + "/admin/overview?site=portal")
    expect(page.locator("#duty-queue .duty-card[data-file-path]").filter(has_text="sentinel.php")).to_contain_text("Comms: 1")
    page.goto(base + "/admin/threats?site=")
    expect(root_row).to_contain_text("Comm: 2")
    expect(nested_row).to_contain_text("Comm: 2")
    expect(shop_row).to_contain_text("Comm: 1")
