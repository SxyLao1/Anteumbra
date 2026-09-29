"""Browser-only coverage for every administrator-password entry point."""

import pytest
from playwright.sync_api import expect

from .support import PASSWORD

NEW_PASSWORD = "E2e!Password9"


def _logout(page):
    logout = page.locator("#logout-btn")
    if not logout.is_visible():
        page.locator("details > summary").click()
        logout = page.locator("button[data-action='dashboard.logout']:visible")
    page.once("dialog", lambda dialog: dialog.accept())
    logout.click()
    page.wait_for_url("**/admin/login")


def _assert_new_password_can_sign_in(page):
    page.locator("input[name='username']").fill("admin")
    page.locator("input[name='password']").fill(PASSWORD)
    page.locator("button.login-btn").click()
    expect(page.locator(".login-error")).to_be_visible()

    # A failed form submission re-renders the login page, so fill both fields
    # again rather than assuming the server retains the username.
    page.locator("input[name='username']").fill("admin")
    page.locator("input[name='password']").fill(NEW_PASSWORD)
    with page.expect_navigation(url="**/admin/"):
        page.locator("button.login-btn").click()


@pytest.mark.parametrize("entrypoint", ["settings", "config_editor", "environment"])
@pytest.mark.expected_http_error("/admin/login", 401)
def test_authenticated_password_reset_uses_active_literal_config(real_instance, entrypoint):
    """Each authenticated UI entry point activates a new password after logout."""
    page, _, _ = real_instance
    base = page.url.split("/admin/")[0]

    if entrypoint == "settings":
        page.goto(base + "/admin/settings?open=advanced")
        form = page.locator("form[hx-post='/admin/settings/password/save']")
        form.locator("input[name='new_password']").fill(NEW_PASSWORD)
        form.locator("input[name='confirm_password']").fill(NEW_PASSWORD)
        form.get_by_role("button", name="Set a new password").click()
        expect(page.locator("[data-settings-password-notice='success']")).to_be_visible()
    elif entrypoint == "config_editor":
        page.goto(base + "/admin/config?tab=secrets")
        form = page.locator("form[hx-post='/admin/config/editor/password']")
        form.locator("input[name='password']").fill(NEW_PASSWORD)
        form.locator("input[name='password_confirm']").fill(NEW_PASSWORD)
        form.get_by_role("button", name="Set a new password").click()
        expect(page.locator("#ce-result")).to_contain_text("Password updated")
    else:
        page.goto(base + "/admin/settings?open=advanced")
        page.locator("#settings-config .config-section-header").click()
        password = page.locator("#env-pwd-input")
        expect(password).to_be_visible()
        password.fill(NEW_PASSWORD)
        page.get_by_role("button", name="Generate Hash").click()
        expect(page.locator("#env-pwd-display")).not_to_have_text("not set")
        page.get_by_role("button", name="Save .env").click()
        expect(page.locator("#env-saved")).to_have_text("Saved")

    _logout(page)
    _assert_new_password_can_sign_in(page)
