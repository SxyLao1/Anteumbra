"""Real browser checks for record, quarantine and source-viewer actions.

The only business input is a harmless marker file placed into the isolated
runtime's monitored roots.  Assertions inspect browser-visible DOM state; this
module never seeds the registry or calls an admin business endpoint directly.
"""

from urllib.parse import urlsplit

from playwright.sync_api import expect


def open_threats(page):
    origin = urlsplit(page.url)
    page.goto(f"{origin.scheme}://{origin.netloc}/admin/threats")
    expect(page.locator("#records-table-container")).to_be_visible()


def portal_row(page, filename):
    return page.locator("#records-table-container .record-item[data-site-id='portal']").filter(
        has_text=filename
    )


def close_detail(page):
    overlay = page.locator("#record-detail-modal-overlay")
    overlay.click(position={"x": 2, "y": 2})
    expect(overlay).to_have_attribute("aria-hidden", "true")


def wait_for_webhook_receipt(lab_page, filename: str, minimum_rows: int) -> None:
    """Use the counterpart's visible receipt page to prove a real outbound send."""
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


def test_real_record_review_realert_and_quarantine_source(real_instance, external_lab):
    page, portal, _ = real_instance
    review_file = portal / "record-review.php"
    deleted_file = portal / "record-delete-only.php"
    quarantine_file = portal / "record-quarantine-source.php"
    for target in (review_file, deleted_file, quarantine_file):
        target.write_text("<?php /* ANTEUMBRA_E2E_MARKER */ ?>", encoding="utf-8")

    open_threats(page)
    review = portal_row(page, review_file.name)
    expect(review).to_be_visible(timeout=20000)
    lab_page = page.context.new_page()
    try:
        lab_page.goto(external_lab.url)
        wait_for_webhook_receipt(lab_page, review_file.name, 1)
        receipt_count = (
            lab_page.locator("tbody tr")
            .filter(has=lab_page.get_by_role("cell", name="webhook", exact=True))
            .filter(has_text=review_file.name)
            .count()
        )

        # Source and detail bind to the actual portal record, including its site.
        review.get_by_role("button", name="Source", exact=True).click()
        expect(page.get_by_role("dialog", name="File source viewer")).to_contain_text("ANTEUMBRA_E2E_MARKER")
        page.keyboard.press("Escape")
        review.get_by_role("button", name="Detail", exact=True).click()
        detail = page.locator("#record-detail-modal")
        expect(detail).to_contain_text("Portal test site")
        expect(detail).to_contain_text("Cumulative count")

        # A review is reversible through the real UI, then the operator can re-arm
        # the standing alert and a file write produces a visible alert again.
        close_detail(page)
        review = portal_row(page, review_file.name)
        review.get_by_role("button", name="Mark FP", exact=True).click()
        expect(portal_row(page, review_file.name).get_by_role("button", name="Clear FP", exact=True)).to_be_visible()
        portal_row(page, review_file.name).get_by_role("button", name="Clear FP", exact=True).click()
        expect(portal_row(page, review_file.name).get_by_role("button", name="Mark FP", exact=True)).to_be_visible()
        # Soft deletion records an audit state but never deletes the original file.
        deleted = portal_row(page, deleted_file.name)
        deleted.locator("input.rec-checkbox").check()
        page.once("dialog", lambda dialog: dialog.accept())
        page.locator("#records-table-container").get_by_role("button", name="Delete", exact=True).click()
        results = page.locator("#records-batch-results")
        expect(results).to_contain_text("Succeeded", timeout=10000)
        expect(results).to_contain_text(deleted_file.name)
        assert deleted_file.exists(), "soft-delete must retain the original monitored file"
        page.locator("#records-table-container").get_by_role("button", name="Deleted", exact=True).click()
        expect(portal_row(page, deleted_file.name)).to_be_visible(timeout=10000)

        # Quarantine moves the file, so its source viewer must use the real qid,
        # not the now-missing original path.  Its batch outcome is persisted in DOM.
        page.locator("#records-table-container").get_by_role("button", name="All", exact=True).click()
        quarantined = portal_row(page, quarantine_file.name)
        expect(quarantined).to_be_visible(timeout=10000)
        quarantined.locator("input.rec-checkbox").check()
        page.once("dialog", lambda dialog: dialog.accept())
        page.locator("#records-table-container").get_by_role("button", name="Quarantine", exact=True).click()
        expect(results).to_contain_text(quarantine_file.name, timeout=10000)
        page.get_by_role("tab", name="Quarantine", exact=True).click()
        qrow = page.locator("#quarantine-list-container .record-item[data-site-id='portal']").filter(
            has_text=quarantine_file.name
        )
        expect(qrow).to_be_visible(timeout=10000)
        qrow.get_by_role("button", name="Source", exact=True).click()
        expect(page.get_by_role("dialog", name="File source viewer")).to_contain_text("ANTEUMBRA_E2E_MARKER")
        page.keyboard.press("Escape")
        qrow.locator("input.q-checkbox").check()
        page.once("dialog", lambda dialog: dialog.accept())
        page.locator("#quarantine-list-container").get_by_role("button", name="Restore Sel", exact=True).click()
        expect(results).to_contain_text("Succeeded", timeout=10000)
        expect(results.locator("li")).to_contain_text("Q-")
        expect(page.locator(".q-count")).to_contain_text("0 selected")

        # A re-armed record receives a real subsequent monitor event when its
        # own test file changes; both its alert state and an outbound receipt
        # must reappear through their public operator surfaces.
        open_threats(page)
        portal_row(page, review_file.name).get_by_role("button", name="Detail", exact=True).click()
        expect(detail.get_by_role("button", name="Alert me again", exact=True)).to_be_visible()
        detail.get_by_role("button", name="Alert me again", exact=True).click()
        expect(detail).to_contain_text("No", timeout=10000)
        # The real monitor intentionally collapses duplicate MODIFY events for
        # five seconds; wait past that operator-visible debounce window before
        # making the next genuine change to this same file.
        page.wait_for_timeout(5500)
        review_file.write_text(
            "<?php /* ANTEUMBRA_E2E_MARKER */ ?>\n// re-alerted through browser workflow\n",
            encoding="utf-8",
        )
        close_detail(page)
        open_threats(page)
        re_alerted = portal_row(page, review_file.name)
        expect(re_alerted).to_contain_text("ALERT", timeout=20000)
        wait_for_webhook_receipt(lab_page, review_file.name, receipt_count + 1)
    finally:
        lab_page.close()
