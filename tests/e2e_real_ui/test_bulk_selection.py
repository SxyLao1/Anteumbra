"""Browser-only checks for paged selection and per-object batch results."""

from playwright.sync_api import expect

from .test_management_flows import open_page


def _records_ready(page, total):
    panel = page.locator("#records-table-container")
    selector = panel.get_by_role("button", name=f"Select all {total}", exact=True)
    for _ in range(30):
        if selector.count() and selector.is_visible():
            return panel
        page.wait_for_timeout(500)
        # The monitor publishes genuine file events asynchronously. A normal
        # browser reload is the operator-visible way to reread the ledger.
        page.reload()
    expect(selector).to_be_visible()
    return panel


def _row(panel, filename):
    return panel.locator(".record-item").filter(has_text=filename)


def test_paged_record_selection_exclusion_cancel_and_batch_result(real_instance):
    page, portal, _ = real_instance
    for number in range(23):
        (portal / f"bulk-page-{number:02d}.php").write_text(
            "<?php /* ANTEUMBRA_E2E_MARKER */ ?>", encoding="utf-8"
        )

    open_page(page, "threats?site=portal")
    panel = _records_ready(page, 23)
    excluded = panel.locator(".record-item").first
    excluded_name = excluded.locator(".record-title").inner_text()
    panel.get_by_role("button", name="Select page", exact=True).click()
    excluded.locator(".rec-checkbox").uncheck()
    panel.get_by_role("button", name="Next →", exact=True).click()
    page_two_name = panel.locator(".record-title").first.inner_text()
    panel.locator(".rec-checkbox").first.check()
    expect(panel.locator(".rec-count")).to_contain_text("20 selected")

    # Cancellation is a real browser decision: it must retain the selected set
    # and leave the batch control available without sending a business action.
    page.once("dialog", lambda dialog: dialog.dismiss())
    panel.locator(".batch-toolbar").get_by_role("button", name="Mark FP", exact=True).click()
    expect(panel.locator(".rec-count")).to_contain_text("20 selected")
    expect(panel.locator(".batch-toolbar").get_by_role("button", name="Mark FP", exact=True)).to_be_enabled()

    # Status and text filters redraw the fragment but preserve this site's
    # selection set; the selected page-two object remains part of the action.
    panel.get_by_role("button", name="Active", exact=True).click()
    expect(panel.locator(".rec-count")).to_contain_text("20 selected")
    panel.locator(".rec-search").fill("bulk-page-22")
    expect(panel.locator(".record-item:visible")).to_have_count(1)
    expect(panel.locator(".rec-count")).to_contain_text("20 selected")
    panel.locator(".rec-search").fill("")
    expect(panel.locator(".rec-count")).to_contain_text("20 selected")

    page.once("dialog", lambda dialog: dialog.accept())
    panel.locator(".batch-toolbar").get_by_role("button", name="Mark FP", exact=True).click()
    results = page.locator("#records-batch-results")
    expect(results).to_contain_text("20 succeeded", timeout=15_000)
    expect(results.locator("li[data-outcome='success']")).to_have_count(20)
    expect(results).to_contain_text(page_two_name)

    # The explicit page-one exclusion did not receive the bulk review.
    expect(_row(panel, excluded_name).get_by_role("button", name="Mark FP", exact=True)).to_be_visible(
        timeout=15_000
    )
    expect(panel.locator(".rec-count")).to_contain_text("0 selected")


def test_partial_quarantine_failure_keeps_only_failed_item_for_browser_retry(real_instance):
    page, portal, _ = real_instance
    success_file = portal / "bulk-quarantine-success.php"
    retry_file = portal / "bulk-quarantine-retry.php"
    for target in (success_file, retry_file):
        target.write_text("<?php /* ANTEUMBRA_E2E_MARKER */ ?>", encoding="utf-8")

    open_page(page, "threats?site=portal")
    panel = _records_ready(page, 2)
    _row(panel, success_file.name).locator(".rec-checkbox").check()
    _row(panel, retry_file.name).locator(".rec-checkbox").check()
    retry_file.unlink()

    page.once("dialog", lambda dialog: dialog.accept())
    panel.get_by_role("button", name="Quarantine", exact=True).click()
    results = page.locator("#records-batch-results")
    expect(results).to_contain_text("1 succeeded, 0 skipped, 1 failed", timeout=15_000)
    expect(results.locator("li[data-outcome='success']")).to_contain_text(success_file.name)
    expect(results.locator("li[data-outcome='failed']")).to_contain_text(retry_file.name)
    expect(panel.locator(".rec-count")).to_contain_text("1 selected")

    # Restoring only the harmless missing input makes the retained failed item
    # retryable through the same selected-browser workflow.
    retry_file.write_text("<?php /* ANTEUMBRA_E2E_MARKER */ ?>", encoding="utf-8")
    page.once("dialog", lambda dialog: dialog.accept())
    panel.get_by_role("button", name="Quarantine", exact=True).click()
    expect(results).to_contain_text("1 succeeded, 0 skipped, 0 failed", timeout=15_000)
    expect(results.locator("li[data-outcome='success']")).to_contain_text(retry_file.name)
    expect(panel.locator(".rec-count")).to_contain_text("0 selected")


def test_quarantine_paging_filter_and_bulk_restore(real_instance):
    page, portal, _ = real_instance
    for number in range(21):
        (portal / f"bulk-restore-{number:02d}.php").write_text(
            "<?php /* ANTEUMBRA_E2E_MARKER */ ?>", encoding="utf-8"
        )

    open_page(page, "threats?site=portal")
    records = _records_ready(page, 21)
    records.get_by_role("button", name="Select all 21", exact=True).click()
    page.once("dialog", lambda dialog: dialog.accept())
    records.get_by_role("button", name="Quarantine", exact=True).click()
    expect(page.locator("#records-batch-results")).to_contain_text("21 succeeded", timeout=20_000)

    page.get_by_role("tab", name="Quarantine", exact=True).click()
    quarantine = page.locator("#quarantine-list-container")
    expect(quarantine.locator(".record-item")).to_have_count(20, timeout=15_000)
    quarantine.get_by_role("button", name="Sel Page", exact=True).click()
    quarantine.get_by_role("button", name="Next", exact=True).click()
    expect(quarantine.locator(".record-item")).to_have_count(1)
    quarantine.locator(".q-checkbox").check()
    expect(quarantine.locator(".q-count")).to_contain_text("21 selected")

    quarantine.locator(".q-search").fill("bulk-restore-20")
    expect(quarantine.locator(".record-item:visible")).to_have_count(1)
    expect(quarantine.locator(".q-count")).to_contain_text("21 selected")
    page.once("dialog", lambda dialog: dialog.accept())
    quarantine.get_by_role("button", name="Restore Sel", exact=True).click()
    results = page.locator("#records-batch-results")
    expect(results).to_contain_text("21 succeeded", timeout=20_000)
    expect(results.locator("li[data-outcome='success']")).to_have_count(21)
    expect(quarantine.locator(".q-count")).to_contain_text("0 selected")
    assert all((portal / f"bulk-restore-{number:02d}.php").is_file() for number in range(21))


def test_aggregate_same_filename_batch_keeps_site_identity_and_scope(real_instance):
    page, portal, shop = real_instance
    for root in (portal, shop):
        (root / "same-name-bulk.php").write_text(
            "<?php /* ANTEUMBRA_E2E_MARKER */ ?>", encoding="utf-8"
        )

    # A selection remembered for Portal must not become an implicit Shop action.
    open_page(page, "threats?site=portal")
    portal_panel = _records_ready(page, 1)
    _row(portal_panel, "same-name-bulk.php").locator(".rec-checkbox").check()
    expect(portal_panel.locator(".rec-count")).to_contain_text("1 selected")
    open_page(page, "threats?site=shop")
    shop_panel = _records_ready(page, 1)
    expect(shop_panel.locator(".rec-count")).to_contain_text("0 selected")
    expect(shop_panel.locator(".batch-toolbar").get_by_role("button", name="Mark FP", exact=True)).to_be_disabled()

    # The aggregate view deliberately selects both site-qualified identities;
    # its per-object results prove the new items contract did not collapse them.
    open_page(page, "threats?site=")
    panel = page.locator("#records-table-container")
    portal_row = panel.locator(".record-item[data-site-id='portal']").filter(has_text="same-name-bulk.php")
    shop_row = panel.locator(".record-item[data-site-id='shop']").filter(has_text="same-name-bulk.php")
    expect(portal_row).to_be_visible(timeout=30_000)
    expect(shop_row).to_be_visible(timeout=30_000)
    portal_row.locator(".rec-checkbox").check()
    shop_row.locator(".rec-checkbox").check()
    expect(panel.locator(".rec-count")).to_contain_text("2 selected")
    page.once("dialog", lambda dialog: dialog.accept())
    panel.locator(".batch-toolbar").get_by_role("button", name="Mark FP", exact=True).click()
    results = page.locator("#records-batch-results")
    expect(results).to_contain_text("2 succeeded", timeout=15_000)
    rows = results.locator("li[data-outcome='success']")
    expect(rows).to_have_count(2)
    expect(results).to_contain_text("same-name-bulk.php")
    expect(results).to_contain_text("Portal test site")
    expect(results).to_contain_text("Shop test site")

    # Refresh readback reaches the rendered ledger, not just the result panel.
    expect(portal_row.get_by_role("button", name="Clear FP", exact=True)).to_be_visible(timeout=15_000)
    expect(shop_row.get_by_role("button", name="Clear FP", exact=True)).to_be_visible(timeout=15_000)

