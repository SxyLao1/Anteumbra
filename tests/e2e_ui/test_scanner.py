import time

from playwright.sync_api import expect


def _open_scanner(page):
    page.click("a.nav-link[data-path='scanner']")
    page.wait_for_selector("#scan-target-dir", timeout=10000)


def test_empty_directory_scan_reaches_terminal_state_and_refreshes_history(
    page, server_url, tmp_path
):
    target = tmp_path / "empty-scan-target"
    target.mkdir()

    _open_scanner(page)
    page.fill("#scan-target-dir", str(target))
    page.click("#scan-start-btn")

    status = page.get_by_test_id("scan-status")
    expect(status).to_have_attribute("data-state", "completed", timeout=15000)
    expect(status).to_have_text("Completed")
    expect(page.locator("#scan-progress-text")).to_contain_text("0 / 0 files")
    expect(page.locator("#scan-stop-btn")).to_be_hidden()
    expect(page.locator("#scan-start-btn")).to_be_enabled()
    expect(page.locator("#scan-history-list")).to_contain_text(str(target), timeout=10000)


def test_scanner_honors_custom_extensions(page, server_url, tmp_path, monkeypatch):
    target = tmp_path / "custom-extension-target"
    target.mkdir()
    (target / "sample.custom").write_text("plain content", encoding="utf-8")
    monkeypatch.setattr(
        "anteumbra.infrastructure.detection.manual_scanner.quick_scan_yara",
        lambda *_args, **_kwargs: None,
    )

    _open_scanner(page)
    page.fill("#scan-target-dir", str(target))
    page.fill("#scan-extensions", "custom")
    page.click("#scan-start-btn")

    expect(page.get_by_test_id("scan-status")).to_have_attribute(
        "data-state", "completed", timeout=15000
    )
    expect(page.locator("#scan-progress-text")).to_contain_text("1 / 1 files")


def test_missing_directory_is_reported_as_failed(page, server_url, tmp_path):
    target = tmp_path / "does-not-exist"

    _open_scanner(page)
    page.fill("#scan-target-dir", str(target))
    page.click("#scan-start-btn")

    status = page.get_by_test_id("scan-status")
    expect(status).to_have_attribute("data-state", "failed", timeout=15000)
    expect(status).to_have_text("Failed")
    expect(page.locator("#scan-progress-text")).to_contain_text("does-not-exist")
    expect(page.locator("#scan-stop-btn")).to_be_hidden()
    expect(page.locator("#scan-start-btn")).to_be_enabled()
    expect(page.locator("#scan-history-list")).to_contain_text(str(target), timeout=10000)


def test_cancel_waits_for_backend_and_reaches_stopped_state(
    page, server_url, tmp_path, monkeypatch
):
    target = tmp_path / "cancel-scan-target"
    target.mkdir()
    for index in range(40):
        (target / f"sample-{index}.php").write_text("<?php echo 1;", encoding="utf-8")

    def slow_clean_scan(*_args, **_kwargs):
        time.sleep(0.03)
        return None

    monkeypatch.setattr(
        "anteumbra.infrastructure.detection.manual_scanner.quick_scan_yara",
        slow_clean_scan,
    )

    _open_scanner(page)
    page.fill("#scan-target-dir", str(target))
    page.fill("#scan-extensions", ".php")
    page.click("#scan-start-btn")
    expect(page.get_by_test_id("scan-status")).to_have_attribute(
        "data-state", "running", timeout=10000
    )
    page.click("#scan-stop-btn")

    expect(page.get_by_test_id("scan-status")).to_have_attribute(
        "data-state", "stopped", timeout=15000
    )
    expect(page.locator("#scan-progress-text")).to_contain_text("Stopped")
    expect(page.locator("#scan-stop-btn")).to_be_hidden()
    expect(page.locator("#scan-start-btn")).to_be_enabled()
    expect(page.locator("#scan-history-list")).to_contain_text(str(target), timeout=10000)
