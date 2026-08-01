"""Browser regressions for frontend resource teardown."""

import time

from playwright.sync_api import expect


def test_navigation_closes_active_scanner_sse_without_cancelling_job(
    page, tmp_path, monkeypatch
):
    target = tmp_path / "scanner-lifecycle"
    target.mkdir()
    for index in range(80):
        (target / f"sample-{index}.php").write_text("<?php echo 1;", encoding="utf-8")

    def slow_clean_scan(*_args, **_kwargs):
        time.sleep(0.04)
        return None

    monkeypatch.setattr(
        "anteumbra.infrastructure.detection.scanner.ScannerService.scan",
        slow_clean_scan,
    )

    page.click("a.nav-link[data-path='scanner']")
    page.wait_for_selector("#scan-target-dir", timeout=10000)
    page.evaluate(
        """() => {
            const NativeEventSource = window.EventSource;
            window.__anteumbraScannerCloseCalls = 0;
            window.EventSource = function TrackingEventSource(url, options) {
                const stream = new NativeEventSource(url, options);
                const close = stream.close.bind(stream);
                stream.close = function () {
                    window.__anteumbraScannerCloseCalls += 1;
                    return close();
                };
                return stream;
            };
            window.EventSource.prototype = NativeEventSource.prototype;
        }"""
    )
    page.fill("#scan-target-dir", str(target))
    page.click("#scan-start-btn")
    expect(page.get_by_test_id("scan-status")).to_have_attribute(
        "data-state", "running", timeout=10000
    )

    page.click("a.nav-link[data-path='overview']")
    page.wait_for_function("() => window.__anteumbraScannerCloseCalls > 0")

    assert page.evaluate("window.__anteumbraScannerCloseCalls") == 1