"""Prove that rules changed through the console affect subsequent real scans."""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from playwright.sync_api import expect

RULE_FILE = "browser_effectiveness.yar"
RULE_NAME = "BrowserRuleEffectiveness"
OLD_MARKER = "BROWSER_RULE_EFFECTIVENESS_OLD"
NEW_MARKER = "BROWSER_RULE_EFFECTIVENESS_NEW"


def open_page(page, path: str) -> None:
    origin = urlsplit(page.url)
    page.goto(f"{origin.scheme}://{origin.netloc}/admin/{path}")
    expect(page.locator("#main-content")).to_be_visible()


def rule_source(marker: str) -> bytes:
    return (
        f'rule {RULE_NAME} {{ strings: $marker = "{marker}" condition: $marker }}\n'.encode()
    )


def upload_rule(page, marker: str) -> None:
    page.get_by_role("button", name="[+] Upload", exact=True).click()
    page.locator("#yara-file-input").set_input_files(
        {"name": RULE_FILE, "mimeType": "text/plain", "buffer": rule_source(marker)}
    )
    page.locator("#yara-upload-btn").click()
    expect(page.locator(f'article[data-filename="{RULE_FILE}"]')).to_be_visible(timeout=15_000)


def scan_directory(page, target) -> None:
    open_page(page, "scanner?site=portal")
    page.locator("#scan-target-dir").fill(str(target))
    # This is an explicit operator selection.  The manual scan must apply it
    # when constructing the scan policy as well as when collecting files.
    page.locator("#scan-extensions").fill(".txt")
    page.locator("#scan-start-btn").click()
    expect(page.get_by_test_id("scan-status")).to_have_attribute(
        "data-state", "completed", timeout=45_000
    )


def assert_scan_hit(page, filename: str) -> None:
    expect(page.locator("#tab-all-count")).to_have_text("1")
    result = page.locator("#results-tbody tr").filter(has_text=filename)
    expect(result).to_be_visible()
    expect(result).to_contain_text(RULE_NAME)


def assert_scan_has_no_findings(page) -> None:
    """A terminal scan plus zero rows is the negative evidence, never a sleep."""
    expect(page.get_by_test_id("scan-status")).to_have_attribute("data-state", "completed")
    expect(page.locator("#tab-all-count")).to_have_text("0")
    expect(page.locator("#results-tbody tr")).to_have_count(0)


def test_uploaded_edited_and_deleted_rule_changes_real_scan_results(real_instance):
    page, portal, _ = real_instance
    initial = portal / "rule-effectiveness-initial"
    old_after_edit = portal / "rule-effectiveness-old-after-edit"
    new_after_edit = portal / "rule-effectiveness-new-after-edit"
    after_delete = portal / "rule-effectiveness-after-delete"
    for directory in (initial, old_after_edit, new_after_edit, after_delete):
        directory.mkdir()

    open_page(page, "yara/rules")
    upload_rule(page, OLD_MARKER)
    rules = page.locator("#yara-rules-container")
    uploaded = rules.locator(f'article[data-filename="{RULE_FILE}"]')
    built_in = rules.locator('article[data-filename="e2e_marker.yar"]')
    expect(uploaded).to_be_visible()
    expect(built_in).to_be_visible()

    # The selection set is independent from a temporary visual filter: both
    # rules remain selected when one row is hidden, then Clear removes both.
    uploaded.locator("input.yara-checkbox").check()
    built_in.locator("input.yara-checkbox").check()
    expect(rules.locator("#yara-selected-count")).to_have_text("2 selected")
    search = rules.get_by_placeholder("Search rules...")
    search.fill("browser_effectiveness")
    expect(uploaded).to_be_visible()
    expect(built_in).not_to_be_visible()
    expect(rules.locator("#yara-selected-count")).to_have_text("2 selected")
    search.fill("")
    expect(built_in.locator("input.yara-checkbox")).to_be_checked()
    rules.locator("#yara-deselect-btn").click()
    expect(rules.locator("#yara-selected-count")).to_have_text("0 selected")
    expect(uploaded.locator("input.yara-checkbox")).not_to_be_checked()
    expect(built_in.locator("input.yara-checkbox")).not_to_be_checked()

    initial_file = initial / "initial-marker.txt"
    initial_file.write_text(OLD_MARKER, encoding="utf-8")
    scan_directory(page, initial)
    assert_scan_hit(page, initial_file.name)

    open_page(page, "yara/rules")
    uploaded = page.locator(f'article[data-filename="{RULE_FILE}"]')
    uploaded.get_by_role("button", name="Edit", exact=True).click()
    editor = page.locator("#rule-editor")
    expect(editor).to_have_value(re.compile(OLD_MARKER))
    editor.fill(rule_source(NEW_MARKER).decode())
    page.once("dialog", lambda dialog: dialog.accept())
    page.get_by_role("button", name="Save Update", exact=True).click()
    expect(page.locator("#yara-validation-result")).to_have_text("Rule updated successfully")
    page.keyboard.press("Escape")

    # The edited rule is checked against fresh files in separate scans.  The
    # old condition reaching a completed zero-result scan proves it was removed
    # from the live engine; the new condition then proves the reload took hold.
    old_file = old_after_edit / "old-marker.txt"
    old_file.write_text(OLD_MARKER, encoding="utf-8")
    scan_directory(page, old_after_edit)
    assert_scan_has_no_findings(page)

    new_file = new_after_edit / "new-marker.txt"
    new_file.write_text(NEW_MARKER, encoding="utf-8")
    scan_directory(page, new_after_edit)
    assert_scan_hit(page, new_file.name)

    open_page(page, "yara/rules")
    uploaded = page.locator(f'article[data-filename="{RULE_FILE}"]')
    uploaded.locator("input.yara-checkbox").check()
    page.once("dialog", lambda dialog: dialog.accept())
    page.locator("#yara-batch-delete-btn").click()
    expect(uploaded).to_have_count(0, timeout=15_000)

    deleted_file = after_delete / "after-delete-marker.txt"
    deleted_file.write_text(NEW_MARKER, encoding="utf-8")
    scan_directory(page, after_delete)
    assert_scan_has_no_findings(page)
