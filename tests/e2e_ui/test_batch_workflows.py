# -*- coding: utf-8 -*-
"""E2E UI coverage for cross-page record and quarantine batch workflows."""

import re
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


PAGE_RE = re.compile(r"Page\s+(\d+)\s*/\s*(\d+)")


def _page_indicator(page, cid: str) -> str:
    """The rendered 'Page n / m (total)' text, or '' when there is a single page."""
    node = page.locator(f"#{cid} .page-info")
    return node.inner_text().strip() if node.count() else ""


def _current_page(page, cid: str) -> int | None:
    match = PAGE_RE.search(_page_indicator(page, cid))
    return int(match.group(1)) if match else None


def _total_pages(page, cid: str) -> int:
    match = PAGE_RE.search(_page_indicator(page, cid))
    return int(match.group(2)) if match else 1


def _goto_page(page, cid: str, target: int) -> None:
    """Page the list forward with its own Next control and wait for it to render.

    The previous helper called ``htmx.ajax`` for page N and then slept a fixed
    500ms without checking that page N arrived.  The server clamps ``page`` to
    ``total_pages``, so asking for a page past the end silently re-rendered the
    *last* page: the loop then re-clicked rows it had already selected, and
    clicking an already-checked box toggles it back off.  That is exactly what
    made the selection set (4) disagree with the click count (8) in issue #16.

    Clicking the rendered paging control is the path a human takes, and waiting
    for the page indicator to change is a deterministic completion signal rather
    than a guess.
    """
    for _ in range(8):
        current = _current_page(page, cid)
        if current is None or current >= target:
            return
        # The paging bar is [Prev] info [jump] [Next]; the Next button is the
        # button that follows the page indicator, and it is absent on the last
        # page -- picking ``button:last`` would grab Prev instead and oscillate.
        next_button = page.locator(f"#{cid} .pagination-bar .page-info ~ button").last
        if not next_button.count() or next_button.is_disabled():
            return
        before = _page_indicator(page, cid)
        next_button.click()
        try:
            page.wait_for_function(
                """([cid, prev]) => {
                    const el = document.querySelector('#' + cid + ' .page-info');
                    return !!el && el.textContent !== prev;
                }""",
                arg=[cid, before],
                timeout=8000,
            )
        except Exception:  # noqa: BLE001 - a late refresh may have raced us
            return
    raise AssertionError(
        f"{cid} never reached page {target}; indicator reads {_page_indicator(page, cid)!r}"
    )


def _load_records_page(page, page_no: int, audit: bool = False):
    # one ledger now: the audit view is the "deleted" status filter
    cid = "records-table-container"
    _goto_page(page, cid, page_no)
    return cid


def _is_selected(page, value: str) -> bool:
    return page.evaluate(
        "v => window.Anteumbra.module('records').selectedRecords().has(v)", value
    )


def _select_matching_records(page, needle: str, count: int, audit: bool = False) -> int:
    # one ledger now: the audit view is the "deleted" status filter
    cid = "records-table-container"
    selected = 0
    visited_pages: set[str] = set()
    for page_no in range(1, 5):
        _load_records_page(page, page_no, audit=audit)
        indicator = _page_indicator(page, cid)
        if indicator in visited_pages:
            break  # paging no longer moves; stop instead of re-clicking the same rows
        visited_pages.add(indicator)

        rows = page.locator(f"#{cid} .record-item").filter(has_text=needle)
        for idx in range(rows.count()):
            if selected >= count:
                return selected
            checkbox = rows.nth(idx).locator("input.rec-checkbox")
            value = checkbox.input_value()
            # Clicking an already-selected box would toggle it *off*, so a record
            # seen on an earlier page must be skipped rather than re-clicked.
            if _is_selected(page, value):
                continue
            checkbox.click()
            # Verify the click registered before moving on: a click that lands on
            # a detached node is otherwise counted but never selected.
            page.wait_for_function(
                "v => window.Anteumbra.module('records').selectedRecords().has(v)",
                arg=value,
                timeout=5000,
            )
            selected += 1
    return selected


def _switch_tab(page, tab: str):
    page.locator(f".threats-tab[data-tab='{tab}']").click()
    page.wait_for_timeout(700)


def _load_quarantine_page(page, page_no: int, status: str = "quarantined"):
    _goto_page(page, "quarantine-list-container", page_no)


def _select_matching_quarantine(page, needle: str, count: int) -> int:
    selected = 0
    visited_pages: set[str] = set()
    for page_no in range(1, 5):
        _load_quarantine_page(page, page_no)
        indicator = _page_indicator(page, "quarantine-list-container")
        if indicator in visited_pages:
            break
        visited_pages.add(indicator)

        rows = page.locator("#quarantine-list-container .record-item").filter(has_text=needle)
        for idx in range(rows.count()):
            if selected >= count:
                return selected
            checkbox = rows.nth(idx).locator("input.q-checkbox")
            value = checkbox.input_value()
            if page.evaluate(
                "v => window.Anteumbra.module('records').selectedQuarantine().has(v)", value
            ):
                continue
            checkbox.click()
            page.wait_for_function(
                "v => window.Anteumbra.module('records').selectedQuarantine().has(v)",
                arg=value,
                timeout=5000,
            )
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


def test_cross_page_batch_false_positive_quarantine_and_restore(page, tmp_path, runtime):
    browser_errors = []
    page.on("console", lambda msg: browser_errors.append(f"{msg.type}: {msg.text}"))
    page.on("pageerror", lambda exc: browser_errors.append(f"pageerror: {exc}"))
    _stub_dialogs(page)

    _seed_records(runtime, tmp_path, "batch_e2e_fp", 8)
    _seed_records(runtime, tmp_path, "batch_e2e_q", 8)
    _seed_quarantine_records(runtime, tmp_path, "batch_e2e_qrestore", 8)

    page.request.get(page.url.rstrip("/") + "/records?force=true")
    _open_threats(page)

    assert _select_matching_records(page, "batch_e2e_fp", 4) == 4
    assert page.evaluate("window.Anteumbra.module('records').selectedRecords().size") == 4
    fp_button = page.locator("#records-table-container .rec-batch-btn").filter(has_text="Mark FP")
    expect(fp_button).to_be_enabled()
    fp_button.click()
    try:
        _wait_for_message(page, "4 success")
    except Exception as exc:
        messages = page.evaluate("window.__batchMessages || []")
        raise AssertionError(
            f"FP batch did not complete; messages={messages!r}; browser_errors={browser_errors!r}"
        ) from exc
    expect(page.locator("#records-table-container .rec-count")).to_contain_text(
        "0 selected", timeout=8000
    )

    fp_records = {
        Path(item["file_path"]).name: item
        for item in runtime.registry.get_all(
            include_deleted=True,
            include_false_positive=True,
        )
        if "batch_e2e_fp" in item.get("file_path", "")
    }
    assert sum(bool(item.get("marked_false_positive")) for item in fp_records.values()) == 4

    assert _select_matching_records(page, "batch_e2e_q", 8) == 8
    assert page.evaluate("window.Anteumbra.module('records').selectedRecords().size") == 8
    q_button = page.locator("#records-table-container .rec-batch-btn").filter(has_text="Quarantine")
    expect(q_button).to_be_enabled()
    q_button.click()
    _wait_for_message(page, "8 success")
    expect(page.locator("#records-table-container .rec-count")).to_contain_text(
        "0 selected", timeout=10000
    )

    quarantined_registry = [
        item
        for item in runtime.registry.get_all(
            include_deleted=True,
            include_false_positive=True,
        )
        if Path(item.get("file_path", "")).name.startswith("batch_e2e_q_")
    ]
    assert len(quarantined_registry) == 8
    assert all(item.get("quarantine_id") for item in quarantined_registry)
    assert all(not Path(item["file_path"]).exists() for item in quarantined_registry)

    quarantine_records = runtime.quarantine.list_records(status="quarantined", limit=1000)
    stored_ids = {item["quarantine_id"] for item in quarantine_records}
    assert {item["quarantine_id"] for item in quarantined_registry} <= stored_ids

    _switch_tab(page, "quarantine")
    page.wait_for_selector("#quarantine-list-container", timeout=10000)
    assert _select_matching_quarantine(page, "batch_e2e_qrestore", 8) == 8
    assert page.evaluate("window.Anteumbra.module('records').selectedQuarantine().size") == 8
    restore_button = page.locator("#quarantine-list-container .q-batch-btn").filter(
        has_text="Restore Sel"
    )
    expect(restore_button).to_be_enabled()
    restore_button.click()
    _wait_for_message(page, "8 success")
    expect(page.locator("#quarantine-list-container .q-count")).to_contain_text(
        "0 selected", timeout=10000
    )

    restored_records = [
        item
        for item in runtime.quarantine.list_records(status="restored", limit=1000)
        if "batch_e2e_qrestore" in item.get("original_path", "")
    ]
    assert len(restored_records) == 8
    assert all(Path(item["original_path"]).exists() for item in restored_records)

    # the audit view is now the unified ledger ("All" status); switch back to it
    _switch_tab(page, "active")
    page.click("#records-table-container .records-status-filter button[data-status='all']")
    page.wait_for_selector("#records-table-container[data-status='all'] .record-item", timeout=10000)
    assert _select_matching_records(page, "batch_e2e_fp", 2, audit=True) == 2
    assert page.evaluate("window.Anteumbra.module('records').selectedRecords().size") == 2
    page.locator("#records-table-container .rec-batch-btn").filter(has_text="Delete").click()
    _wait_for_message(page, "2 success")
    expect(page.locator("#records-table-container input.rec-checkbox:checked")).to_have_count(
        0, timeout=10000
    )

    deleted_fp = [
        item
        for item in runtime.registry.get_all(
            include_deleted=True,
            include_false_positive=True,
        )
        if "batch_e2e_fp" in item.get("file_path", "") and item.get("deleted_at")
    ]
    assert len(deleted_fp) == 2
    assert not [entry for entry in browser_errors if entry.startswith("pageerror:")]
