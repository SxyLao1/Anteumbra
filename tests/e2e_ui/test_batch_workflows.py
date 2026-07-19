# -*- coding: utf-8 -*-
"""E2E UI coverage for cross-page record and quarantine batch workflows."""

from pathlib import Path

from playwright.sync_api import expect


def _seed_records(runtime, tmp_path: Path, prefix: str, count: int) -> list[str]:
    paths = []
    for idx in range(1, count + 1):
        path = tmp_path / prefix / f"{prefix}_{idx:02d}.php"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("<?php eval($_POST['cmd']); ?>\n", encoding="utf-8")
        identity = runtime.config.resolve_site_identity(path)
        runtime.registry.add(
            path,
            [prefix, "eval_post"],
            first_seen_ip="127.0.0.1",
            detection_source="active",
            site=identity,
        )
        paths.append(str(path.resolve()).lower())
    return paths


def _seed_quarantine_records(runtime, tmp_path: Path, prefix: str, count: int):
    for idx in range(1, count + 1):
        path = tmp_path / prefix / f"{prefix}_{idx:02d}.php"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("<?php eval($_POST['cmd']); ?>\n", encoding="utf-8")
        identity = runtime.config.resolve_site_identity(path)
        runtime.registry.add(
            path,
            [prefix, "eval_post"],
            first_seen_ip="127.0.0.1",
            detection_source="active",
            site=identity,
        )
        runtime.quarantine.quarantine_file(
            path,
            prefix,
            [prefix, "eval_post"],
            site=identity,
        )


def _open_threats(page):
    page.click("a.nav-link[data-path='threats']")
    page.wait_for_selector("#records-table-container", timeout=10000)
    page.wait_for_selector("#records-table-container .record-item", timeout=10000)
    page.wait_for_timeout(500)


def _load_records_page(page, page_no: int, audit: bool = False):
    cid = "records-table-container-audit" if audit else "records-table-container"
    url = f"/admin/records?page={page_no}&compact=1"
    if audit:
        url += "&audit=true"
    page.evaluate(
        "([url,cid]) => htmx.ajax('GET', url, {target:'#'+cid, swap:'outerHTML'})",
        [url, cid],
    )
    page.wait_for_timeout(500)
    return cid


def _select_matching_records(page, needle: str, count: int, audit: bool = False) -> int:
    cid = "records-table-container-audit" if audit else "records-table-container"
    selected = 0
    for page_no in range(1, 5):
        _load_records_page(page, page_no, audit=audit)
        rows = page.locator(f"#{cid} .record-item").filter(has_text=needle)
        for idx in range(rows.count()):
            if selected >= count:
                return selected
            rows.nth(idx).locator("input.rec-checkbox").click()
            selected += 1
    return selected


def _switch_tab(page, tab: str):
    page.locator(f".threats-tab[data-tab='{tab}']").click()
    page.wait_for_timeout(700)


def _load_quarantine_page(page, page_no: int, status: str = "quarantined"):
    page.evaluate(
        "([pageNo,status]) => htmx.ajax('GET', '/admin/quarantine?status='+status+'&page='+pageNo, "
        "{target:'#quarantine-list-container', swap:'outerHTML'})",
        [str(page_no), status],
    )
    page.wait_for_timeout(500)


def _select_matching_quarantine(page, needle: str, count: int) -> int:
    selected = 0
    for page_no in range(1, 5):
        _load_quarantine_page(page, page_no)
        rows = page.locator("#quarantine-list-container .record-item").filter(has_text=needle)
        for idx in range(rows.count()):
            if selected >= count:
                return selected
            rows.nth(idx).locator("input.q-checkbox").click()
            selected += 1
    return selected


def _stub_dialogs(page):
    page.evaluate(
        """() => {
            window.__batchMessages = [];
            window.confirm = (message) => {
                window.__batchMessages.push(message);
                return true;
            };
            window.alert = (message) => {
                window.__batchMessages.push(message);
            };
        }"""
    )


def _wait_for_message(page, expected: str, timeout_ms: int = 10000):
    page.wait_for_function(
        "expected => (window.__batchMessages || []).some(message => message.includes(expected))",
        arg=expected,
        timeout=timeout_ms,
    )


def test_cross_page_batch_false_positive_quarantine_and_restore(
    page, tmp_path, runtime
):
    browser_errors = []
    page.on("console", lambda msg: browser_errors.append(f"{msg.type}: {msg.text}"))
    page.on("pageerror", lambda exc: browser_errors.append(f"pageerror: {exc}"))
    _stub_dialogs(page)

    _seed_records(runtime, tmp_path, "codex_e2e_fp", 8)
    _seed_records(runtime, tmp_path, "codex_e2e_q", 8)
    _seed_quarantine_records(runtime, tmp_path, "codex_e2e_qrestore", 8)

    page.request.get(page.url.rstrip("/") + "/records?force=true")
    _open_threats(page)

    assert _select_matching_records(page, "codex_e2e_fp", 4) == 4
    assert page.evaluate("window._recSelected && window._recSelected.size") == 4
    fp_button = page.locator("#records-table-container .rec-batch-btn").filter(has_text="FP Sel")
    expect(fp_button).to_be_enabled()
    fp_button.click()
    try:
        _wait_for_message(page, "4 success")
    except Exception as exc:
        messages = page.evaluate("window.__batchMessages || []")
        raise AssertionError(f"FP batch did not complete; messages={messages!r}; browser_errors={browser_errors!r}") from exc
    expect(page.locator("#records-table-container .rec-count")).to_contain_text("0 selected", timeout=8000)

    fp_records = {
        Path(item["file_path"]).name: item
        for item in runtime.registry.get_all(
            include_deleted=True,
            include_false_positive=True,
        )
        if "codex_e2e_fp" in item.get("file_path", "")
    }
    assert sum(bool(item.get("marked_false_positive")) for item in fp_records.values()) == 4

    assert _select_matching_records(page, "codex_e2e_q", 8) == 8
    assert page.evaluate("window._recSelected && window._recSelected.size") == 8
    q_button = page.locator("#records-table-container .rec-batch-btn").filter(has_text="Quar Sel")
    expect(q_button).to_be_enabled()
    q_button.click()
    _wait_for_message(page, "8 success")
    expect(page.locator("#records-table-container .rec-count")).to_contain_text("0 selected", timeout=10000)

    quarantined_registry = [
        item
        for item in runtime.registry.get_all(
            include_deleted=True,
            include_false_positive=True,
        )
        if Path(item.get("file_path", "")).name.startswith("codex_e2e_q_")
    ]
    assert len(quarantined_registry) == 8
    assert all(item.get("quarantine_id") for item in quarantined_registry)
    assert all(not Path(item["file_path"]).exists() for item in quarantined_registry)

    quarantine_records = runtime.quarantine.list_records(
        status="quarantined", limit=1000
    )
    stored_ids = {item["quarantine_id"] for item in quarantine_records}
    assert {item["quarantine_id"] for item in quarantined_registry} <= stored_ids

    _switch_tab(page, "quarantine")
    page.wait_for_selector("#quarantine-list-container", timeout=10000)
    assert _select_matching_quarantine(page, "codex_e2e_qrestore", 8) == 8
    assert page.evaluate("window._qSelected && window._qSelected.size") == 8
    restore_button = page.locator("#quarantine-list-container .q-batch-btn").filter(has_text="Restore Sel")
    expect(restore_button).to_be_enabled()
    restore_button.click()
    _wait_for_message(page, "8 success")
    expect(page.locator("#quarantine-list-container .q-count")).to_contain_text("0 selected", timeout=10000)

    restored_records = [
        item
        for item in runtime.quarantine.list_records(status="restored", limit=1000)
        if "codex_e2e_qrestore" in item.get("original_path", "")
    ]
    assert len(restored_records) == 8
    assert all(Path(item["original_path"]).exists() for item in restored_records)

    _switch_tab(page, "audit")
    page.wait_for_selector("#records-table-container-audit", timeout=10000)
    assert _select_matching_records(page, "codex_e2e_fp", 2, audit=True) == 2
    assert page.evaluate("window._recSelected && window._recSelected.size") == 2
    page.locator("#records-table-container-audit .rec-batch-btn").filter(has_text="Del Sel").click()
    _wait_for_message(page, "2 success")
    expect(page.locator("#records-table-container-audit input.rec-checkbox:checked")).to_have_count(0, timeout=10000)

    deleted_fp = [
        item
        for item in runtime.registry.get_all(
            include_deleted=True,
            include_false_positive=True,
        )
        if "codex_e2e_fp" in item.get("file_path", "") and item.get("deleted_at")
    ]
    assert len(deleted_fp) == 2
    assert not [entry for entry in browser_errors if entry.startswith("pageerror:")]
