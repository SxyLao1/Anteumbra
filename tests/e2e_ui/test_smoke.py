# -*- coding: utf-8 -*-
"""
Minimal smoke test — verifies Flask server starts and basic pages respond.
Run this FIRST to isolate config/server issues from navigation issues.
"""
from playwright.sync_api import expect


def test_server_alive(server_url):
    """The test server should have started."""
    assert server_url.startswith("http://"), f"Invalid server URL: {server_url}"


def test_login_page_loads(unauthenticated_page, server_url):
    """Login page should load without server errors."""
    pg = unauthenticated_page
    resp = pg.goto(f"{server_url}/admin/login")
    # Should not be a 500 error
    assert resp.status < 500, f"Login page returned {resp.status}"
    # Take a screenshot for debugging
    pg.screenshot(path="tests/e2e_ui/screenshots/login_page.png")


def test_login_form_exists(unauthenticated_page, server_url):
    """Login page should have the login form."""
    pg = unauthenticated_page
    pg.goto(f"{server_url}/admin/login")
    # Check page title at minimum
    title = pg.title()
    content = pg.content()
    assert any(kw in title or kw in content for kw in ("Anteumbra", "ANTEUMBRA", "Login", "login")), \
        f"Login page title/content unexpected: '{title}'"
    # Print page content for debugging (encode-safe)
    body = pg.locator("body").inner_text()
    safe_body = body.encode('ascii', errors='replace').decode('ascii')
    print(f"\n[SMOKE] Login page body ({len(body)} chars): {safe_body[:300]}")


def test_csrf_token_present(unauthenticated_page, server_url):
    """Login form should contain CSRF token."""
    pg = unauthenticated_page
    pg.goto(f"{server_url}/admin/login")
    csrf = pg.locator("input[name='csrf_token']")
    count = csrf.count()
    assert count > 0, "No CSRF token input found on login page"


def test_login_success_redirects(page, server_url):
    """After login, we should see authenticated dashboard content."""
    pg = page
    # page fixture already logged in — just check we're not on login page anymore
    assert "/login" not in pg.url.lower(), \
        f"After login, URL should not be login page, got: {pg.url}"
    body = pg.locator("body").inner_text()
    safe_body = body.encode('ascii', errors='replace').decode('ascii')
    print(f"\n[SMOKE] Dashboard body ({len(body)} chars): {safe_body[:300]}")
    # Brand should be visible
    expect(pg.locator(".brand")).to_be_visible(timeout=3000)
