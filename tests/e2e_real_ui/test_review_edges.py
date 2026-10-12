"""Less frequent operator tasks, with genuine browser-visible outcomes."""

import json
import re
from datetime import datetime
from pathlib import Path

import pytest
from playwright.sync_api import expect

from .test_management_flows import download_text, open_page


def test_rule_syntax_edit_save_and_reopen(real_instance):
    page, _, _ = real_instance
    open_page(page, "yara/rules")
    row = page.locator('article[data-filename="e2e_marker.yar"]')
    row.get_by_role("button", name="Edit", exact=True).click()
    editor = page.locator("#rule-editor")
    original = editor.input_value()
    editor.fill("not valid YARA")
    page.get_by_role("button", name="Validate Syntax", exact=True).click()
    expect(page.locator("#yara-validation-result")).to_have_attribute("data-status", "error")
    editor.fill(original + "\n// edited through the browser\n")
    page.get_by_role("button", name="Validate Syntax", exact=True).click()
    expect(page.locator("#yara-validation-result")).to_have_text("Syntax OK")
    page.once("dialog", lambda dialog: dialog.accept())
    page.get_by_role("button", name="Save Update", exact=True).click()
    expect(page.locator("#yara-validation-result")).to_have_text("Rule updated successfully")
    page.keyboard.press("Escape")
    page.reload()
    row.get_by_role("button", name="Edit", exact=True).click()
    expect(editor).to_have_value(re.compile("edited through the browser"))


@pytest.mark.expected_http_error("/admin/file/content", 404)
def test_records_paging_search_selection_scope_and_missing_source(real_instance):
    page, portal, shop = real_instance
    for number in range(23):
        (portal / f"paging-{number:02d}.php").write_text(
            "<?php /* ANTEUMBRA_E2E_MARKER */ ?>", encoding="utf-8"
        )
    (shop / "shop-only.php").write_text("<?php /* ANTEUMBRA_E2E_MARKER */ ?>", encoding="utf-8")
    open_page(page, "threats?site=portal")
    panel = page.locator("#records-table-container")
    for _ in range(30):
        if panel.get_by_role("button", name="Select all 23", exact=True).count():
            break
        page.wait_for_timeout(500)
        page.reload()
    expect(panel.get_by_role("button", name="Select all 23", exact=True)).to_be_visible(
        timeout=30000
    )
    panel.get_by_role("button", name="Select page", exact=True).click()
    expect(panel.locator(".rec-checkbox:checked")).to_have_count(20)
    panel.get_by_role("button", name="Next →", exact=True).click()
    expect(panel.locator(".rec-checkbox")).to_have_count(3)
    panel.get_by_role("button", name="Select all 23", exact=True).click()
    expect(panel.locator(".rec-count")).to_contain_text("23 selected")
    panel.get_by_role("button", name="Clear", exact=True).click()
    expect(panel.locator(".rec-count")).to_contain_text("0 selected")
    panel.locator(".rec-search").fill("paging-00")
    expect(panel.locator(".record-item:visible")).to_have_count(1)
    panel.locator(".rec-checkbox:visible").check()
    open_page(page, "threats?site=shop")
    expect(panel).to_contain_text("shop-only.php")
    expect(panel.locator(".rec-checkbox:checked")).to_have_count(0)
    # A genuine external file deletion is an allowed filesystem stimulus.
    (shop / "shop-only.php").unlink()
    panel.get_by_role("button", name="Source", exact=True).click()
    expect(page.get_by_role("dialog", name="File source viewer")).to_contain_text(
        "Source is no longer available"
    )


def test_log_controls_and_access_analysis(real_instance):
    page, portal, _ = real_instance
    open_page(page, "logs/analyzer?site=portal")
    page.locator("#log-level").select_option("ERROR")
    page.locator("#log-hits-only").check()
    page.locator("#log-limit").select_option("200")
    page.get_by_role("button", name="Custom", exact=True).click()
    expect(page.locator("#log-from")).to_be_visible()
    page.locator("#log-from").fill("2020-01-01T00:00")
    page.locator("#log-to").fill("2030-01-01T00:00")
    page.get_by_role("button", name="Apply filters", exact=True).click()
    expect(page.locator("#log-state")).not_to_contain_text("Loading")
    page.get_by_role("button", name="Reset filters", exact=True).click()
    expect(page.locator("#log-level")).to_have_value("all")
    page.locator("#log-live-btn").click()
    expect(page.locator("#log-state")).to_have_text("Live tail connected")
    (portal / "live-tail-marker.php").write_text(
        "<?php /* ANTEUMBRA_E2E_MARKER */ ?>", encoding="utf-8"
    )
    expect(page.locator("#log-rows")).to_contain_text("live-tail-marker.php", timeout=20000)
    page.locator("#log-live-btn").click()
    expect(page.locator("#log-state")).to_have_text("Live tail stopped")
    page.locator("#log-keyword").fill("live-tail-marker.php")
    page.get_by_role("button", name="Apply filters", exact=True).click()
    expect(page.locator("#log-rows")).to_contain_text("live-tail-marker.php")
    rows = json.loads(
        download_text(page, page.get_by_role("button", name="Export JSON", exact=True))
    )
    assert rows and all("live-tail-marker.php" in str(row) for row in rows)
    page.get_by_role("button", name="Access log analysis", exact=True).click()
    access = page.locator("#log-access-content")
    expect(access).to_contain_text("Portal test site")
    expect(access).to_contain_text("Shop test site")
    expect(access).to_contain_text("[DISABLED]")


def test_quarantine_permanent_delete_preserves_history(real_instance):
    page, portal, _ = real_instance
    for name in ("permanent-one.php", "permanent-two.php"):
        (portal / name).write_text("<?php /* ANTEUMBRA_E2E_MARKER */ ?>", encoding="utf-8")
    open_page(page, "threats?site=portal")
    records = page.locator("#records-table-container")
    for _ in range(20):
        if records.locator(".record-item").count() == 2:
            break
        page.wait_for_timeout(500)
        page.reload()
    expect(records.locator(".record-item")).to_have_count(2)
    records.get_by_role("button", name="Select page", exact=True).click()
    page.once("dialog", lambda dialog: dialog.accept())
    records.get_by_role("button", name="Quarantine", exact=True).click()
    expect(page.locator("#records-batch-results")).to_contain_text("2 succeeded")
    page.get_by_role("tab", name="Quarantine", exact=True).click()
    panel = page.locator("#quarantine-list-container")
    payloads = []
    for name in ("permanent-one.php", "permanent-two.php"):
        panel.locator(".record-item").filter(has_text=name).get_by_role("button", name="Detail", exact=True).click()
        path = Path(page.locator("#quarantine-detail-content tr").filter(
            has=page.get_by_role("cell", name="Quarantine path", exact=True)
        ).locator("code").inner_text())
        if not path.is_absolute():
            path = portal.parents[1] / path
        assert path.resolve().is_relative_to(portal.parents[1].resolve())
        assert path.is_file()
        payloads.append(path)
        page.keyboard.press("Escape")
    first = panel.locator(".record-item").filter(has_text="permanent-one.php")
    page.once("dialog", lambda dialog: dialog.accept())
    first.get_by_role("button", name="Delete", exact=True).click()
    expect(first).to_contain_text("DELETED")
    second = panel.locator(".record-item").filter(has_text="permanent-two.php")
    second.locator(".q-checkbox").check()
    page.once("dialog", lambda dialog: dialog.accept())
    panel.get_by_role("button", name="Delete Sel", exact=True).click()
    expect(page.locator("#records-batch-results")).to_contain_text("1 succeeded")
    panel.get_by_role("button", name="Deleted", exact=True).click()
    expect(panel.locator(".record-item")).to_have_count(2)
    expect(panel.get_by_role("button", name="Restore", exact=True)).to_have_count(0)
    first.get_by_role("button", name="Detail", exact=True).click()
    expect(page.locator("#quarantine-detail-content")).to_contain_text("deleted", ignore_case=True)
    assert all(not path.exists() for path in payloads)


@pytest.mark.access_logs
def test_access_log_analysis_reads_real_site_logs(real_instance):
    page, portal, _ = real_instance
    log_dir = portal.parents[1] / "test-inputs"
    stamp = datetime.now().astimezone().strftime("%d/%b/%Y:%H:%M:%S %z")
    (log_dir / "portal-access.log").write_text(
        f'198.51.100.71 - - [{stamp}] "GET /probe.php HTTP/1.1" 200 20 "-" "sqlmap/1.8"\n' * 4,
        encoding="utf-8",
    )
    (log_dir / "shop-access.log").write_text(
        f'198.51.100.72 - - [{stamp}] "GET / HTTP/1.1" 200 20 "-" "Mozilla/5.0"\n',
        encoding="utf-8",
    )
    open_page(page, "logs/analyzer?site=portal")
    page.get_by_role("button", name="Access log analysis", exact=True).click()
    access = page.locator("#log-access-content")
    expect(access).to_contain_text("198.51.100.71")
    expect(access).to_contain_text("sqlmap")
    expect(access).to_contain_text("[CLEAN]")
    expect(access).to_contain_text("Portal test site")
    expect(access).to_contain_text("Shop test site")
    expect(access).not_to_contain_text("[DISABLED]")
    expect(access).not_to_contain_text("[ERROR]")
