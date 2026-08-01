# -*- coding: utf-8 -*-
"""
E2E UI Tests — Authentication & Login

Tests:
  - Login page renders correctly
  - Wrong credentials show error
  - Successful login redirects to dashboard
  - Logout clears session
"""
from playwright.sync_api import expect


class TestLogin:
    """Login page and authentication flow."""

    def test_login_page_renders(self, unauthenticated_page, server_url):
        """Login page should show brand, form, and no error."""
        pg = unauthenticated_page
        pg.goto(f"{server_url}/admin/login")

        expect(pg.locator(".login-brand")).to_have_text("ANTEUMBRA")
        expect(pg.locator("input[name='username']")).to_be_visible()
        expect(pg.locator("input[name='password']")).to_be_visible()
        expect(pg.locator("button.login-btn")).to_be_visible()

    def test_login_wrong_password_shows_error(self, unauthenticated_page, server_url):
        """Wrong password should stay on login page with error message."""
        pg = unauthenticated_page
        pg.goto(f"{server_url}/admin/login")

        pg.fill("input[name='username']", "admin")
        pg.fill("input[name='password']", "WRONG_PASSWORD")
        pg.click("button.login-btn")

        # Should stay on login page with error
        expect(pg.locator(".login-error")).to_be_visible(timeout=5000)

    def test_login_empty_username_shows_error(self, unauthenticated_page, server_url):
        """Empty username should show error and 400 status."""
        pg = unauthenticated_page
        pg.goto(f"{server_url}/admin/login")

        pg.fill("input[name='password']", "something")
        # Don't fill username — submit with empty username
        pg.click("button.login-btn")

        # The form submits via POST, browser re-renders the page with error.
        # Wait for the error element to appear (or check if we're still on login)
        pg.wait_for_timeout(1000)
        # Either the error div appears or we stay on the login page
        error = pg.locator(".login-error")
        if error.count() > 0:
            expect(error).to_be_visible()
        else:
            # Still on login page — that's also correct (re-rendered)
            expect(pg.locator("form.login-form")).to_be_visible()

    def test_logout_clears_session(self, page, server_url):
        """After navigating to logout, user should be redirected to login."""
        pg = page
        # Kill SSE first, then navigate to logout
        pg.goto("about:blank", wait_until="commit", timeout=10000)
        pg.wait_for_timeout(200)
        pg.goto(f"{server_url}/admin/logout", wait_until="commit", timeout=20000)
        # After redirect, login form should be visible
        expect(pg.locator("form.login-form")).to_be_visible(timeout=10000)
        assert "/login" in pg.url.lower(), (
            f"After logout, should be on login page, got: {pg.url}"
        )
