"""Manual scanner acceptance through the real browser and isolated runtime only."""
from __future__ import annotations

from urllib.parse import urlsplit

import pytest
from playwright.sync_api import expect


def _open_scanner(page) -> None:
    """Open the public admin scanner bookmark, without a business API call."""
    current = urlsplit(page.url)
    page.goto(f"{current.scheme}://{current.netloc}/admin/scanner")
    expect(page.locator("#scan-target-dir")).to_be_visible()


def _open_threats(page) -> None:
    current = urlsplit(page.url)
    page.goto(f"{current.scheme}://{current.netloc}/admin/threats")
    expect(page.locator("#records-table-container")).to_be_visible()


def _run_scan(page, target, extension: str = ".php") -> None:
    page.locator("#scan-target-dir").fill(str(target))
    page.locator("#scan-extensions").fill(extension)
    page.locator("#scan-start-btn").click()
    expect(page.get_by_test_id("scan-status")).to_have_attribute(
        "data-state", "completed", timeout=45_000
    )


@pytest.mark.expected_http_error("/admin/scanner/quarantine", 404)
def test_scanner_new_known_source_report_history_and_partial_quarantine(real_instance):
    page, portal, _ = real_instance
    scan_only = portal.parent / "scan-only"
    scan_only.mkdir()
    quarantined_marker = scan_only / "scanner-new.php"
    missing_marker = scan_only / "scanner-missing.php"
    quarantined_marker.write_text("<?php /* ANTEUMBRA_E2E_MARKER */ ?>\n", encoding="utf-8")
    missing_marker.write_text("<?php /* ANTEUMBRA_E2E_MARKER */ ?>\n", encoding="utf-8")

    _open_scanner(page)
    _run_scan(page, scan_only)
    expect(page.locator("#tab-new-count")).to_have_text("2")
    finding = page.locator("#results-tbody tr.result-new").filter(has_text="scanner-new.php")
    expect(finding).to_be_visible()

    finding.get_by_role("button", name="Source", exact=True).click()
    source = page.get_by_role("dialog", name="File source viewer")
    expect(source).to_contain_text("ANTEUMBRA_E2E_MARKER")
    source.get_by_role("button", name="Close", exact=True).click()

    finding.get_by_role("button", name="Detail", exact=True).click()
    detail = page.locator("#record-detail-modal")
    expect(detail).to_contain_text("Detection Detail")
    expect(detail).to_contain_text("scanner-new.php")
    detail.locator("button.modal-close").click()

    report = page.get_by_role("button", name="Generate Report", exact=True)
    expect(report).to_be_visible()
    with page.expect_popup() as pending_report:
        report.click()
    report_page = pending_report.value
    expect(report_page.locator("h1")).to_contain_text("Manual Scan Report")
    expect(report_page.locator("body")).to_contain_text("scanner-new.php")
    report_page.close()

    # The file was real at scan time. Removing it afterwards exercises the
    # product's actual per-file failure path, without any business API setup.
    missing_marker.unlink()
    finding.locator("input.scan-cb").check()
    missing = page.locator("#results-tbody tr.result-new").filter(has_text="scanner-missing.php")
    missing.locator("input.scan-cb").check()
    page.once("dialog", lambda dialog: dialog.accept())
    page.get_by_role("button", name="Quarantine Selected", exact=True).click()
    outcome = page.locator("#scan-quarantine-results")
    expect(outcome).to_contain_text("Quarantined")
    expect(outcome).to_contain_text("scanner-new.php")
    expect(outcome).to_contain_text("Failed")
    expect(outcome).to_contain_text("scanner-missing.php")
    expect(finding.locator("input.scan-cb")).not_to_be_checked()
    expect(missing.locator("input.scan-cb")).to_be_checked()
    expect(page.locator("#scan-selected-count")).to_have_text("1 selected")

    # Wait for the real monitor's visible detection before scanning the site.
    known_marker = portal / "scanner-known.php"
    known_marker.write_text("<?php /* ANTEUMBRA_E2E_MARKER */ ?>\n", encoding="utf-8")
    _open_threats(page)
    records = page.locator("#records-table-container")
    expect(records.locator(".record-item").filter(has_text="scanner-known.php")).to_be_visible(timeout=20_000)

    _open_scanner(page)
    _run_scan(page, portal)
    expect(page.locator("#tab-known-count")).to_have_text("1")
    page.locator("#tab-known").click()
    known = page.locator("#results-tbody tr.result-known").filter(has_text="scanner-known.php")
    expect(known).to_be_visible()
    expect(page.locator("#tab-new-count")).to_have_text("0")

    # Saved history must reload into the same completed state and retain the
    # report action; it exercises a separate user-facing entry point.
    history_row = page.locator(".scan-history-row").filter(has_text=str(portal))
    expect(history_row).to_have_count(1, timeout=15_000)
    history_row.get_by_role("button", name="View", exact=True).click()
    expect(page.get_by_test_id("scan-status")).to_have_attribute("data-state", "completed")
    expect(report).to_be_visible()
    page.get_by_role("link", name="中文", exact=True).click()
    history_row.get_by_role("button", name="查看", exact=True).click()
    expect(page.get_by_test_id("scan-status")).to_contain_text("已完成")
    expect(page.get_by_test_id("scan-status")).not_to_contain_text("findings")


def test_scanner_stop_reaches_terminal_stopped_state(real_instance):
    page, portal, _ = real_instance
    stop_target = portal / "stop-candidate"
    stop_target.mkdir()
    # A sizable harmless corpus gives the real scanner enough work for a user to
    # stop it; no assertion is made about what a cancelled scan should retain.
    for index in range(6_000):
        (stop_target / f"ordinary-{index:05d}.txt").write_text("ordinary\n", encoding="utf-8")

    _open_scanner(page)
    page.locator("#scan-target-dir").fill(str(stop_target))
    page.locator("#scan-extensions").fill(".txt")
    page.locator("#scan-start-btn").click()
    expect(page.get_by_test_id("scan-status")).to_have_attribute("data-state", "running", timeout=15_000)
    page.locator("#scan-stop-btn").click()
    expect(page.get_by_test_id("scan-status")).to_have_attribute("data-state", "stopped", timeout=45_000)
    expect(page.locator("#scan-stop-btn")).to_be_hidden()
