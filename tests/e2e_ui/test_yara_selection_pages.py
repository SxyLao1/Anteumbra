# -*- coding: utf-8 -*-
"""Selection must survive pagination, and "select every page" must reach beyond it."""

from __future__ import annotations

from playwright.sync_api import expect

RULE = "rule anteumbra_selection_{index} {{ condition: true }}\n"
CREATED = 9  # more than one page at the default page size


def _create_rules(runtime) -> list:
    directory = runtime.yara_engine.rules_path
    directory.mkdir(parents=True, exist_ok=True)
    files = []
    for index in range(CREATED):
        path = directory / f"anteumbra_selection_{index:02d}.yar"
        path.write_text(RULE.format(index=index), encoding="utf-8")
        files.append(path)
    return files


def _open_rules(page) -> None:
    page.click("a.nav-link[data-path='yara/rules']")
    expect(page.locator(".yara-checkbox").first).to_be_visible(timeout=10000)


def _selected_count(page) -> int:
    return page.evaluate("window.Anteumbra.module('yara').selectedRules().size")


def test_selection_survives_pagination_and_select_every_page(page, runtime):
    files = _create_rules(runtime)
    try:
        _open_rules(page)

        first = page.locator(".yara-checkbox").first
        first_name = first.get_attribute("data-filename")
        first.click()
        expect(first).to_be_checked()

        next_button = page.locator("#yara-rules-container .pagination-bar button").last
        next_button.click()
        second = page.locator(".yara-checkbox").first
        expect(second).not_to_have_attribute("data-filename", first_name, timeout=10000)
        second_name = second.get_attribute("data-filename")
        second.click()

        back = page.locator("#yara-rules-container .pagination-bar button").first
        back.click()
        expect(
            page.locator(f"input.yara-checkbox[data-filename='{first_name}']")
        ).to_be_checked(timeout=10000)
        assert _selected_count(page) == 2, "the selection was lost across pages"

        page.locator("#yara-select-all-btn").click()

        selected = _selected_count(page)
        expect(page.locator("#yara-selected-count")).to_contain_text(str(selected), timeout=5000)
        assert selected >= CREATED, f"select every page reached only {selected} rules"
        assert page.evaluate(
            f"window.Anteumbra.module('yara').selectedRules().has({first_name!r})"
        ), "the first page's pick is still selected"
        assert page.evaluate(
            f"window.Anteumbra.module('yara').selectedRules().has({second_name!r})"
        ), "the second page's pick is still selected"

        page.locator("#yara-deselect-btn").click()
        assert _selected_count(page) == 0, "clear selection left something behind"
    finally:
        for path in files:
            path.unlink(missing_ok=True)
