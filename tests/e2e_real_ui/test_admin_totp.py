"""Complete single-admin TOTP enrollment, login, recovery, and disablement."""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import time
from urllib.parse import urlsplit

import pytest
from playwright.sync_api import Page, expect

from .support import PASSWORD


def _origin(page: Page) -> str:
    parsed = urlsplit(page.url)
    return f"{parsed.scheme}://{parsed.netloc}"


def _totp(secret: str, now: float | None = None) -> str:
    normalized = secret.strip().upper()
    key = base64.b32decode(normalized + "=" * ((8 - len(normalized) % 8) % 8))
    counter = int((time.time() if now is None else now) // 30)
    digest = hmac.new(key, counter.to_bytes(8, "big"), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = int.from_bytes(digest[offset : offset + 4], "big") & 0x7FFFFFFF
    return str(value % 1_000_000).zfill(6)


def _logout(page: Page) -> None:
    page.once("dialog", lambda dialog: dialog.accept())
    if page.viewport_size["width"] < 769:
        page.locator(".console-mobile-nav details > summary").click()
        page.locator('.console-mobile-more [data-action="dashboard.logout"]').click()
    else:
        page.locator('#logout-btn[data-action="dashboard.logout"]').click()
    expect(page).to_have_url(re.compile(r".*/admin/login$"))


@pytest.mark.expected_http_error("/admin/login/totp", 401)
def test_single_admin_totp_full_lifecycle(real_instance):
    page, _, _ = real_instance
    page.goto(f"{_origin(page)}/admin/account")
    expect(page.locator("#main-content")).to_be_visible()

    setup = page.locator('form[action="/admin/account/totp/setup"]')
    expect(setup).to_be_visible()
    setup.locator('input[name="current_password"]').fill(PASSWORD)
    setup.get_by_role("button", name="START TOTP SETUP", exact=True).click()

    secret = page.locator("[data-totp-secret]").inner_text()
    assert len(secret) >= 20
    recovery = page.locator("div.badge").filter(has_text="One-time recovery codes").locator("div code").all_inner_texts()
    assert len(recovery) == 8
    enable = page.locator('form[action="/admin/account/totp/enable"]')
    enable.locator('input[name="totp_code"]').fill(_totp(secret))
    enable.get_by_role("button", name="ENABLE TOTP", exact=True).click()
    expect(page.locator(".account-message").filter(has_text="TOTP enabled").first).to_be_visible()
    expect(page.locator("[data-totp-secret]")).to_have_count(0)
    expect(page.locator('form[action="/admin/account/totp/disable"]')).to_be_visible()

    _logout(page)
    page.locator("input[name='username']").fill("admin")
    page.locator("input[name='password']").fill(PASSWORD)
    page.locator("button.login-btn").click()
    expect(page).to_have_url(re.compile(r".*/admin/login/totp$"))
    page.locator("input[name='totp_code']").fill(_totp(secret))
    page.locator("button.login-btn").click()
    expect(page).to_have_url(re.compile(r".*/admin/$"))

    _logout(page)
    page.locator("input[name='username']").fill("admin")
    page.locator("input[name='password']").fill(PASSWORD)
    page.locator("button.login-btn").click()
    expect(page).to_have_url(re.compile(r".*/admin/login/totp$"))
    page.locator("input[name='totp_code']").fill(recovery[0])
    page.locator("button.login-btn").click()
    expect(page).to_have_url(re.compile(r".*/admin/$"))

    _logout(page)
    page.locator("input[name='username']").fill("admin")
    page.locator("input[name='password']").fill(PASSWORD)
    page.locator("button.login-btn").click()
    page.locator("input[name='totp_code']").fill(recovery[0])
    page.locator("button.login-btn").click()
    expect(page.locator(".login-error")).to_contain_text("Invalid authenticator or recovery code")
    page.locator("input[name='totp_code']").fill(_totp(secret))
    page.locator("button.login-btn").click()
    expect(page).to_have_url(re.compile(r".*/admin/$"))

    page.goto(f"{_origin(page)}/admin/account")
    disable = page.locator('form[action="/admin/account/totp/disable"]')
    disable.locator('input[name="current_password"]').fill(PASSWORD)
    disable.locator('input[name="totp_code"]').fill(_totp(secret))
    disable.get_by_role("button", name="DISABLE TOTP", exact=True).click()
    expect(page.locator(".account-message").filter(has_text="TOTP disabled").first).to_be_visible()
    expect(page.locator('form[action="/admin/account/totp/setup"]')).to_be_visible()

    _logout(page)
    page.locator("input[name='username']").fill("admin")
    page.locator("input[name='password']").fill(PASSWORD)
    page.locator("button.login-btn").click()
    expect(page).to_have_url(re.compile(r".*/admin/$"))
