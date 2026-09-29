"""Operator-facing administration workflows against an isolated real runtime.

These tests intentionally use only pages, controls, browser navigation and
browser downloads.  They do not reach into the runtime through HTTP APIs or
inspect its internal state.
"""
from __future__ import annotations

import json
import re
from urllib.parse import urlsplit

from playwright.sync_api import Page, expect

from .support import PASSWORD


def _origin(page: Page) -> str:
    parsed = urlsplit(page.url)
    return f"{parsed.scheme}://{parsed.netloc}"


def _open(page: Page, path: str) -> None:
    page.goto(f"{_origin(page)}/admin/{path}")
    expect(page.locator("#main-content")).to_be_visible()


def _review_and_confirm(page: Page, form) -> None:
    form.get_by_role("button", name="Add table or block", exact=True).click()
    result = page.locator("#ce-result")
    expect(result.get_by_role("button", name="Confirm save", exact=True)).to_be_visible()
    result.get_by_role("button", name="Confirm save", exact=True).click()
    expect(result).to_contain_text("written")


def _confirm_result(page: Page) -> None:
    result = page.locator("#ce-result")
    expect(result.get_by_role("button", name="Confirm save", exact=True)).to_be_visible()
    result.get_by_role("button", name="Confirm save", exact=True).click()
    expect(result).to_contain_text("written")


def _open_plugins(page: Page) -> None:
    _open(page, "settings?open=plugins")
    expect(page.locator("[data-plugin-panel]")).to_be_visible()
    expect(page.locator('[data-plugin-row="stdout_logger"]')).to_be_visible()


def test_raw_config_validation_and_concurrent_preview_conflict(real_instance):
    page, _, _ = real_instance
    _open(page, "config?view=raw")
    raw = page.locator("textarea[name=raw_text]")
    baseline = raw.input_value()

    raw.fill("[broken\nvalue = true\n")
    page.get_by_role("button", name="Review raw changes", exact=True).click()
    expect(page.locator("#ce-result")).to_contain_text("config.toml does not parse")
    page.reload()
    expect(page.locator("textarea[name=raw_text]")).to_have_value(baseline)

    # Two visible editor windows obtain independent previews of the same file.
    second = page.context.new_page()
    try:
        second.goto(f"{_origin(page)}/admin/config?view=raw")
        expect(second.locator("textarea[name=raw_text]")).to_be_visible()
        first_text = baseline + "\n# e2e first editor preview\n"
        second_text = baseline + "\n# e2e second editor preview\n"
        page.locator("textarea[name=raw_text]").fill(first_text)
        second.locator("textarea[name=raw_text]").fill(second_text)
        page.get_by_role("button", name="Review raw changes", exact=True).click()
        second.get_by_role("button", name="Review raw changes", exact=True).click()
        _confirm_result(page)
        stale = second.locator("#ce-result")
        stale.get_by_role("button", name="Confirm save", exact=True).click()
        expect(stale).to_contain_text("Not saved: the file moved under us.")
        expect(stale).to_contain_text("changed on disk since this preview")
    finally:
        second.close()


def test_config_tree_structures_and_write_only_secrets(real_instance):
    page, _, _ = real_instance
    _open(page, "config?view=tree")
    root_add = page.locator('form[hx-post="/admin/config/editor/table/add"]')
    root_add.locator('input[name="table"]').fill("e2e_operator_tree")
    _review_and_confirm(page, root_add)

    page.reload()
    tree = page.locator('details.ce-table').filter(has_text="e2e_operator_tree")
    expect(tree).to_be_visible()
    add_key = tree.locator('form[hx-post="/admin/config/editor/key/add"]')
    add_key.locator('input[name="key"]').fill("marker")
    add_key.locator('input[name="value"]').fill('"ui-saved"')
    add_key.get_by_role("button", name="Add key", exact=True).click()
    _confirm_result(page)

    page.reload()
    arrays = page.locator('form[hx-post="/admin/config/editor/array/add"]').filter(
        has=page.locator('input[name="key"][value="plugins.builtin"]')
    )
    arrays.locator("xpath=ancestor::details[1]/summary").click()
    expect(arrays).to_be_visible()
    count_text = arrays.locator("xpath=..").inner_text()
    count = int(re.search(r"(\d+) item", count_text).group(1))
    arrays.locator('input[name="value"]').fill('"e2e_operator_member"')
    arrays.get_by_role("button", name="Add item", exact=True).click()
    _confirm_result(page)

    page.reload()
    remove_item = page.locator('form[hx-post="/admin/config/editor/array/remove"]').filter(
        has=page.locator('input[name="key"][value="plugins.builtin"]')
    )
    remove_item.locator("xpath=ancestor::details[1]/summary").click()
    remove_item.locator('input[name="index"]').fill(str(count))
    remove_item.get_by_role("button", name="Remove item", exact=True).click()
    _confirm_result(page)

    page.reload()
    tree = page.locator('details.ce-table').filter(has_text="e2e_operator_tree")
    tree.get_by_role("button", name="Remove this table", exact=True).click()
    _confirm_result(page)

    page.get_by_role("tab", name="Secrets", exact=True).click()
    secret_row = page.locator('[data-env-key="ANTEUMBRA_EMAIL_PASSWORD"]')
    expect(secret_row).to_be_visible()
    secret_row.locator('input[name="value"]').fill("")
    secret_row.get_by_role("button", name="Save to .env", exact=True).click()
    expect(page.locator("#ce-result")).to_contain_text("nothing was written")
    # A test-owned value can be explicitly cleared; empty save never means clear.
    secret_row.locator('input[name="value"]').fill("e2e-only-secret")
    secret_row.get_by_role("button", name="Save to .env", exact=True).click()
    expect(page.locator("#ce-result")).to_contain_text("written")
    page.reload()
    secret_row = page.locator('[data-env-key="ANTEUMBRA_EMAIL_PASSWORD"]')
    expect(secret_row.get_by_role("button", name="Clear", exact=True)).to_be_visible()
    page.once("dialog", lambda dialog: dialog.accept())
    secret_row.get_by_role("button", name="Clear", exact=True).click()
    expect(page.locator("#ce-result")).to_contain_text("written")


def test_plugin_controls_and_notification_surfaces(real_instance):
    page, _, _ = real_instance
    _open_plugins(page)
    stdout = page.locator('[data-plugin-row="stdout_logger"]')
    stdout.locator('[data-plugin-configure="stdout_logger"]').click()
    form = page.locator('[data-plugin-config-form="stdout_logger"]')
    expect(form).to_be_visible()
    color = form.locator('input[name="field__color"][type="checkbox"]')
    original_color = color.is_checked()
    color.set_checked(not original_color)
    form.get_by_role("button", name="Save plugin settings", exact=True).click()
    expect(page.locator('[data-plugin-notice="success"]')).to_contain_text("Saved")
    expect(page.locator('[data-plugin-row="stdout_logger"]')).to_be_visible()
    stdout = page.locator('[data-plugin-row="stdout_logger"]')
    stdout.locator('[data-plugin-configure="stdout_logger"]').click()
    expect(page.locator('[data-plugin-config-form="stdout_logger"] input[name="field__color"][type="checkbox"]')).to_be_checked(
        checked=not original_color
    )

    # Restore the fixture's original typed setting before exercising controls.
    form = page.locator('[data-plugin-config-form="stdout_logger"]')
    form.locator('input[name="field__color"][type="checkbox"]').set_checked(original_color)
    form.get_by_role("button", name="Save plugin settings", exact=True).click()
    expect(page.locator('[data-plugin-notice="success"]')).to_contain_text("Saved")
    stdout = page.locator('[data-plugin-row="stdout_logger"]')
    state_button = stdout.get_by_role("button", name=re.compile("^(Enable|Disable)$"))
    prior_action = state_button.inner_text()
    state_button.click()
    stdout = page.locator('[data-plugin-row="stdout_logger"]')
    changed_action = "Enable" if prior_action == "Disable" else "Disable"
    expect(stdout.get_by_role("button", name=changed_action, exact=True)).to_be_visible()
    stdout.get_by_role("button", name=changed_action, exact=True).click()
    stdout = page.locator('[data-plugin-row="stdout_logger"]')
    expect(stdout.get_by_role("button", name=prior_action, exact=True)).to_be_visible()

    stdout = page.locator('[data-plugin-row="stdout_logger"]')
    membership = stdout.get_by_role("button", name=re.compile("^(Add to builtin|Remove from builtin)$"))
    prior_membership = membership.inner_text()
    membership.click()
    stdout = page.locator('[data-plugin-row="stdout_logger"]')
    changed_membership = (
        "Add to builtin" if prior_membership == "Remove from builtin" else "Remove from builtin"
    )
    expect(stdout.get_by_role("button", name=changed_membership, exact=True)).to_be_visible()
    stdout.get_by_role("button", name=changed_membership, exact=True).click()
    stdout = page.locator('[data-plugin-row="stdout_logger"]')
    expect(stdout.get_by_role("button", name=prior_membership, exact=True)).to_be_visible()
    expect(page.locator('[data-plugin-row="notifier_handler"]')).to_contain_text("Protected:")
    expect(page.locator('[data-plugin-row="notifier_handler"] button', has_text="Disable")).to_be_disabled()

    _open(page, "settings?open=notifications")
    notifications = page.locator("#settings-notify .notify-section")
    expect(notifications).to_have_count(3)
    original_states = []
    for section in notifications.all():
        toggle = section.locator('input[type="checkbox"]')
        expect(toggle).to_be_visible()
        expect(toggle).to_have_attribute("hx-post", "/admin/settings/notifications/save")
        original_states.append(toggle.is_checked())
        if not toggle.is_checked():
            with page.expect_response(
                lambda response: response.url.endswith("/admin/settings/notifications/save")
                and response.status == 200
            ):
                toggle.check()
    page.reload()
    expect(page.locator("#settings-notify .notify-section input[type=checkbox]")).to_have_count(3)
    for toggle in page.locator("#settings-notify .notify-section input[type=checkbox]").all():
        expect(toggle).to_be_checked()
    for toggle, original in zip(
        page.locator("#settings-notify .notify-section input[type=checkbox]").all(), original_states
    ):
        if not original:
            with page.expect_response(
                lambda response: response.url.endswith("/admin/settings/notifications/save")
                and response.status == 200
            ):
                toggle.uncheck()
    page.reload()
    restored = page.locator("#settings-notify .notify-section input[type=checkbox]").all()
    for toggle, original in zip(restored, original_states):
        if original:
            expect(toggle).to_be_checked()
        else:
            expect(toggle).not_to_be_checked()


def test_logs_filters_downloads_and_account_password_flow(real_instance):
    page, _, _ = real_instance
    _open(page, "logs/analyzer")
    expect(page.locator("#log-rows .logs-row, #log-rows .logs-placeholder").first).to_be_visible()
    page.locator("#log-keyword").fill("e2e-no-match")
    page.get_by_role("button", name="Apply filters", exact=True).click()
    expect(page.locator("#log-rows")).to_contain_text("No log lines match")
    page.get_by_role("button", name="Reset filters", exact=True).click()
    expect(page.locator("#log-keyword")).to_have_value("")
    expect(page.locator("#log-level")).to_have_value("all")
    for label, suffix in (("Export JSON", ".json"), ("Export CSV", ".csv")):
        with page.expect_download() as pending:
            page.get_by_role("button", name=label, exact=True).click()
        download = pending.value
        assert download.suggested_filename.endswith(suffix)
        content = download.path().read_text(encoding="utf-8")
        if suffix == ".json":
            assert isinstance(json.loads(content), list)
        else:
            assert content.startswith("time,level,module,marker,message")

    _open(page, "account")
    account = page.locator('form[action="/admin/account/password"]')
    account.locator('input[name="current_password"]').fill("not-the-current-password")
    account.locator('input[name="new_password"]').fill("E2e!OperatorPassword2026")
    account.locator('input[name="confirm_password"]').fill("E2e!OperatorPassword2026")
    account.get_by_role("button", name="UPDATE PASSWORD", exact=True).click()
    expect(page.locator(".account-message")).to_contain_text("Current password is incorrect")

    account.locator('input[name="current_password"]').fill(PASSWORD)
    account.locator('input[name="new_password"]').fill("E2e!OperatorPassword2026")
    account.locator('input[name="confirm_password"]').fill("E2e!OperatorPassword2026")
    account.get_by_role("button", name="UPDATE PASSWORD", exact=True).click()
    expect(page).to_have_url(re.compile(r".*/admin/login$"))
    page.locator("input[name='username']").fill("admin")
    page.locator("input[name='password']").fill("E2e!OperatorPassword2026")
    page.locator("button.login-btn").click()
    expect(page).to_have_url(re.compile(r".*/admin/$"))
    page.once("dialog", lambda dialog: dialog.accept())
    if page.viewport_size["width"] < 769:
        page.locator(".console-mobile-nav details > summary").click()
        page.locator('.console-mobile-more [data-action="dashboard.logout"]').click()
    else:
        page.locator('#logout-btn[data-action="dashboard.logout"]').click()
    expect(page).to_have_url(re.compile(r".*/admin/login$"))
