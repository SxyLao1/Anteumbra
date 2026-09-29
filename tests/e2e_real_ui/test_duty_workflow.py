"""Browser-only acceptance for the overview duty queue and record workbench."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

from playwright.sync_api import expect

MARKER = "<?php /* ANTEUMBRA_E2E_MARKER */ ?>\n"
ARTIFACTS = Path(
    os.environ.get(
        "ANTEUMBRA_UI_ARTIFACTS", Path(tempfile.gettempdir()) / "anteumbra-ui-artifacts"
    )
)


def screenshot(page, name: str) -> None:
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    page.screenshot(path=str(ARTIFACTS / name), full_page=True, animations="disabled")


def assert_essential_geometry(page, *selectors: str) -> None:
    """Keep the real mobile and desktop controls inside the visible viewport."""
    width = page.viewport_size["width"]
    for selector in selectors:
        box = page.locator(selector).bounding_box()
        assert box is not None and box["width"] > 0 and box["x"] + box["width"] <= width + 1, (
            width,
            selector,
            box,
        )


def open_overview(page, site: str | None = "portal") -> None:
    """Use the operator's overview bookmark, then wait for its queue fragment."""
    origin = urlsplit(page.url)
    suffix = f"?site={site or ''}"
    page.goto(f"{origin.scheme}://{origin.netloc}/admin/overview{suffix}")
    expect(page.locator("#duty-queue .duty-queue")).to_be_visible()


def refresh_duty_queue(page) -> None:
    page.get_by_role("button", name="Refresh queue", exact=True).click()


def wait_for_duty_card(page, filename: str, *, site: str = "portal", attempts: int = 30):
    """Poll only through the visible refresh control while monitor intake catches up."""
    card = page.locator(
        f"#duty-queue .duty-card[data-site-id='{site}']"
    ).filter(has_text=filename)
    for _ in range(attempts):
        if card.count() and card.first.is_visible():
            return card
        refresh_duty_queue(page)
        page.wait_for_timeout(500)
    expect(card).to_be_visible()
    return card


def wait_for_duty_count(page, view: str, count: int, attempts: int = 30) -> None:
    counter = page.locator(f"#duty-queue [data-duty-filter='{view}'] span")
    for _ in range(attempts):
        if counter.inner_text() == str(count):
            return
        refresh_duty_queue(page)
        page.wait_for_timeout(500)
    expect(counter).to_have_text(str(count))


def select_duty_view(page, view: str) -> None:
    page.locator(f"#duty-queue [data-duty-filter='{view}']").click()
    expect(page.locator("#duty-queue .duty-queue")).to_have_attribute("data-duty-view", view)


def open_detail(page, card):
    card.get_by_role("button", name="View evidence", exact=True).click()
    detail = page.locator("#record-detail-modal .record-workbench")
    expect(detail).to_be_visible()
    return detail


def test_duty_queue_aggregates_site_scope_and_keeps_page_on_refresh(real_instance):
    page, portal, shop = real_instance
    # Start in aggregate scope: two identical names must remain two site-owned
    # cards before the portal-only queue grows beyond one page.
    (portal / "duty-shared.php").write_text(MARKER, encoding="utf-8")
    (shop / "duty-shared.php").write_text(MARKER, encoding="utf-8")
    open_overview(page, None)
    aggregate = page.locator("#duty-queue")
    wait_for_duty_card(page, "duty-shared.php", site="portal")
    wait_for_duty_card(page, "duty-shared.php", site="shop")
    expect(aggregate.locator(".duty-card").filter(has_text="duty-shared.php")).to_have_count(2)

    for number in range(12):
        (portal / f"duty-page-{number:02d}.php").write_text(MARKER, encoding="utf-8")
    wait_for_duty_count(page, "active", 14)

    # The portal-only queue owns thirteen records. The first-created shared
    # file sorts behind newer detections, so counts/pages are the stable proof.
    open_overview(page, "portal")
    wait_for_duty_count(page, "active", 13)
    queue = page.locator("#duty-queue .duty-queue")
    expect(queue.locator(".duty-card[data-site-id='shop']")).to_have_count(0)
    expect(queue.locator(".page-info")).to_contain_text("Page 1 / 2 (13 items)")
    queue.get_by_role("button", name="Next", exact=True).click()
    expect(page.locator("#duty-queue .duty-queue")).to_have_attribute("data-duty-page", "2")
    expect(page.locator("#duty-queue .page-info")).to_contain_text("Page 2 / 2 (13 items)")
    expect(page.locator("#duty-queue .duty-card")).to_have_count(1)

    refresh_duty_queue(page)
    expect(page.locator("#duty-queue .duty-queue")).to_have_attribute("data-duty-view", "active")
    expect(page.locator("#duty-queue .duty-queue")).to_have_attribute("data-duty-page", "2")
    page.reload()
    wait_for_duty_count(page, "active", 13)
    expect(page.locator("#duty-queue .page-info")).to_contain_text("Page 1 / 2 (13 items)")
    page.get_by_role("link", name="中文", exact=True).click()
    page.locator(".console-theme-toggle").click()
    expect(page.locator("html")).to_have_attribute("lang", "zh")
    expect(page.locator("body")).to_have_attribute("data-console-theme", "light")
    assert_essential_geometry(page, "#main-content", "#duty-queue", ".console-theme-toggle")
    screenshot(page, f"duty-overview-zh-light-{page.viewport_size['width']}.png")


def test_detail_source_escape_cancel_and_false_positive_undo(real_instance):
    page, portal, _ = real_instance
    target = portal / "duty-review.php"
    target.write_text(MARKER, encoding="utf-8")

    open_overview(page)
    detail = open_detail(page, wait_for_duty_card(page, target.name))
    expect(detail.locator(".record-workbench__target")).to_contain_text("Portal test site")

    detail.locator('[data-action="records.detail-source"]').click()
    source = page.locator("#file-viewer-modal.modal-overlay--front.active")
    expect(source).to_contain_text("ANTEUMBRA_E2E_MARKER")
    page.keyboard.press("Escape")
    expect(source).not_to_be_visible()
    expect(detail).to_be_visible()

    quarantine = detail.locator(
        '[data-action="records.detail-response"][data-batch-action="quarantine"]'
    )
    page.once("dialog", lambda dialog: dialog.dismiss())
    quarantine.click()
    expect(quarantine).to_be_visible()
    expect(detail.locator("[data-detail-receipt]")).to_be_hidden()
    assert target.exists(), "a cancelled disposition must not alter the monitored file"

    mark_false_positive = detail.locator(
        '[data-action="records.detail-response"][data-batch-action="false_positive"]'
    )
    page.once("dialog", lambda dialog: dialog.accept())
    mark_false_positive.click()
    receipt = detail.locator('[data-detail-receipt][data-outcome="success"]')
    expect(receipt).to_be_visible(timeout=15_000)
    expect(detail.get_by_role("button", name="Undo false positive", exact=True)).to_be_visible()

    page.keyboard.press("Escape")
    expect(page.locator("#record-detail-modal-overlay")).to_have_attribute("aria-hidden", "true")
    select_duty_view(page, "reviewed")
    detail = open_detail(page, wait_for_duty_card(page, target.name))
    undo = detail.locator(
        '[data-action="records.detail-response"][data-batch-action="unmark_false_positive"]'
    )
    page.once("dialog", lambda dialog: dialog.accept())
    undo.click()
    expect(detail.locator('[data-detail-receipt][data-outcome="success"]')).to_be_visible()
    expect(detail.get_by_role("button", name="Mark false positive", exact=True)).to_be_visible()
    page.keyboard.press("Escape")
    page.get_by_role("link", name="中文", exact=True).click()
    page.locator(".console-theme-toggle").click()
    page.locator('.duty-card').filter(has_text=target.name).locator('[data-action="records.detail-open"]').click()
    expect(detail).to_contain_text('检测处置台')
    assert_essential_geometry(page, "#record-detail-modal", ".record-workbench__response")
    screenshot(page, f"duty-detail-zh-light-{page.viewport_size['width']}.png")
    original_viewport = page.viewport_size
    page.set_viewport_size({"width": 320, "height": 740})
    expect(page.locator("#record-detail-modal-overlay")).to_have_css("opacity", "1")
    body_box = detail.locator(".record-workbench__body").bounding_box()
    assert body_box is not None
    for note in detail.locator(".detail-profile-meta").all():
        if note.is_visible():
            note_box = note.bounding_box()
            assert note_box is not None
            assert note_box["x"] + note_box["width"] <= body_box["x"] + body_box["width"] + 1
    screenshot(page, "duty-detail-zh-light-320.png")
    page.set_viewport_size(original_viewport)


def test_duty_missing_and_quarantined_groups_keep_evidence_and_site(real_instance):
    page, portal, shop = real_instance
    missing = portal / "duty-missing.php"
    quarantined = portal / "duty-quarantined.php"
    same_name_elsewhere = shop / quarantined.name
    missing.write_text(MARKER, encoding="utf-8")
    quarantined.write_text(MARKER, encoding="utf-8")
    same_name_elsewhere.write_text(MARKER, encoding="utf-8")

    # Enter from aggregate scope, then choose the portal card by its visible
    # ownership marker. The detail target proves the action cannot drift to the
    # identically named shop record.
    open_overview(page, None)
    wait_for_duty_card(page, quarantined.name, site="portal")
    wait_for_duty_card(page, quarantined.name, site="shop")
    quarantine_card = page.locator("#duty-queue .duty-card[data-site-id='portal']").filter(
        has_text=quarantined.name
    )
    detail = open_detail(page, quarantine_card)
    expect(detail.locator(".record-workbench__target")).to_contain_text(quarantined.name)
    expect(detail.locator(".record-workbench__target")).to_contain_text("Portal test site")

    action = detail.locator(
        '[data-action="records.detail-response"][data-batch-action="quarantine"]'
    )
    page.once("dialog", lambda dialog: dialog.accept())
    action.click()
    receipt = detail.locator('[data-detail-receipt][data-outcome="success"]')
    expect(receipt).to_be_visible(timeout=15_000)
    expect(receipt).to_contain_text(quarantined.name)
    expect(receipt).to_contain_text("Portal test site")
    expect(detail.locator(".record-workbench__state--danger")).to_contain_text("Quarantined")
    detail.locator(".record-workbench__metadata summary").click()
    expect(detail.locator(".record-workbench__metadata")).to_contain_text("Moved to quarantine")
    expect(detail.locator(".record-workbench__metadata")).not_to_contain_text("Deleted outside the product")
    expect(detail.locator('.record-workbench__ledger-link')).to_have_attribute(
        'href', '/admin/quarantine?status=all&site=portal'
    )
    detail.locator('[data-action="records.detail-source"][data-quarantine-id]').click()
    expect(page.locator("#file-viewer-modal.modal-overlay--front.active")).to_contain_text(
        "ANTEUMBRA_E2E_MARKER"
    )
    page.keyboard.press("Escape")
    page.keyboard.press("Escape")
    expect(page.locator('#main-content')).to_have_attribute('data-site', '')
    wait_for_duty_card(page, quarantined.name, site='shop')
    assert same_name_elsewhere.exists()

    # A genuine external deletion enters the missing group. Known unavailable
    # actions explain why they are disabled instead of causing a predictable 404.
    missing.unlink()
    select_duty_view(page, "missing")
    missing_card = wait_for_duty_card(page, missing.name)
    expect(page.locator("#duty-queue .duty-queue__hint")).to_contain_text(
        "does not establish that risk is gone"
    )
    detail = open_detail(page, missing_card)
    expect(detail.get_by_role('button', name='View source', exact=True)).to_be_disabled()
    expect(detail).to_contain_text('File is missing; source is unavailable.')
    expect(detail.locator('[data-batch-action="quarantine"]')).to_have_count(0)
    page.keyboard.press("Escape")

    select_duty_view(page, "quarantined")
    quarantined_card = wait_for_duty_card(page, quarantined.name)
    expect(quarantined_card).to_have_attribute("data-site-id", "portal")
    expect(quarantined_card).to_contain_text("Portal test site")
    detail = open_detail(page, quarantined_card)
    first_qid = detail.locator('[data-quarantine-id]').get_attribute('data-quarantine-id')
    detail.locator('.record-workbench__ledger-link').click()
    row = page.locator('#quarantine-list-container .record-item').filter(has_text=first_qid)
    page.once('dialog', lambda dialog: dialog.accept())
    row.get_by_role('button', name='Restore', exact=True).click()
    expect(row).to_contain_text('RESTORED')
    assert quarantined.exists()

    # The second payload must contain this version, not the older cycle's copy.
    quarantined.write_text(MARKER + '<?php /* second-cycle */ ?>', encoding='utf-8')
    open_overview(page, None)
    detail = open_detail(page, wait_for_duty_card(page, quarantined.name))
    expect(detail.locator('.record-workbench__state')).to_have_text('Awaiting review')
    page.once('dialog', lambda dialog: dialog.accept())
    detail.get_by_role('button', name='Quarantine this file', exact=True).click()
    source_control = detail.locator('[data-action="records.detail-source"][data-quarantine-id]')
    expect(source_control).to_be_visible()
    assert source_control.get_attribute('data-quarantine-id') != first_qid
    source_control.click()
    expect(page.locator('#fv-content')).to_contain_text('second-cycle')


def test_detail_response_reports_failure_when_file_disappears_before_quarantine(real_instance):
    page, portal, _ = real_instance
    target = portal / "duty-race.php"
    target.write_text(MARKER, encoding="utf-8")

    open_overview(page)
    detail = open_detail(page, wait_for_duty_card(page, target.name))
    target.unlink()
    action = detail.locator(
        '[data-action="records.detail-response"][data-batch-action="quarantine"]'
    )
    page.once("dialog", lambda dialog: dialog.accept())
    action.click()
    failed = detail.locator('[data-detail-receipt][data-outcome="failed"]')
    expect(failed).to_be_visible(timeout=15_000)
    expect(detail.locator('[data-detail-receipt][data-outcome="success"]')).to_have_count(0)
    expect(detail).to_be_visible()
