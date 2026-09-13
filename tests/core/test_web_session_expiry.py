# -*- coding: utf-8 -*-
"""An expired session must not drop a login page into the dashboard.

HTMX and fetch follow a 302 silently, so ``require_auth`` redirecting to the
login route made the sign-in form appear inside the content pane — nav bar still
rendered, current menu item still highlighted — with nothing telling the user
what happened.  Async requests now get a 401 they can react to.
"""

from __future__ import annotations

import os

import pytest

from anteumbra.interfaces.web.auth import (
    AUTH_STATUS_HEADER,
    IP_DENIED_CODE,
    SESSION_EXPIRED_CODE,
    is_async_request,
)

PROTECTED = "/admin/records?compact=1"


@pytest.fixture(scope="module")
def _app():
    os.environ.setdefault("ANTEUMBRA_TOOL_MODE", "true")

    from anteumbra.interfaces.web.factory import create_app

    app = create_app()
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False
    return app


@pytest.fixture()
def client(_app):
    """Anonymous client: no session, so every protected route hits the guard."""
    with _app.test_client() as c:
        yield c


class TestAsyncDetection:
    def test_htmx_request_is_async(self, _app):
        with _app.test_request_context("/", headers={"HX-Request": "true"}):
            assert is_async_request() is True

    def test_fetch_request_is_async(self, _app):
        # fetch() sends Sec-Fetch-Dest: empty
        with _app.test_request_context("/", headers={"Sec-Fetch-Dest": "empty"}):
            assert is_async_request() is True

    def test_browser_navigation_is_not_async(self, _app):
        with _app.test_request_context("/", headers={"Sec-Fetch-Dest": "document"}):
            assert is_async_request() is False

    def test_missing_headers_default_to_navigation(self, _app):
        with _app.test_request_context("/"):
            assert is_async_request() is False


class TestExpiredSessionOnAsyncRequest:
    def test_htmx_gets_401_not_a_redirect(self, client):
        response = client.get(PROTECTED, headers={"HX-Request": "true"})
        assert response.status_code == 401
        assert response.headers[AUTH_STATUS_HEADER] == SESSION_EXPIRED_CODE
        payload = response.get_json()
        assert payload["code"] == SESSION_EXPIRED_CODE
        # The body must not be an HTML login page.
        assert "<form" not in response.get_data(as_text=True)

    def test_fetch_gets_401_not_a_redirect(self, client):
        response = client.get(PROTECTED, headers={"Sec-Fetch-Dest": "empty"})
        assert response.status_code == 401
        assert response.headers[AUTH_STATUS_HEADER] == SESSION_EXPIRED_CODE

    def test_json_accept_gets_401(self, client):
        response = client.get(PROTECTED, headers={"Accept": "application/json"})
        assert response.status_code == 401
        assert response.headers[AUTH_STATUS_HEADER] == SESSION_EXPIRED_CODE

    def test_no_login_markup_leaks_into_the_fragment(self, client):
        body = client.get(PROTECTED, headers={"HX-Request": "true"}).get_data(as_text=True)
        for marker in ("login-form", "login-container", 'name="password"', "app-shell"):
            assert marker not in body


class TestNavigationStillRedirects:
    def test_top_level_navigation_redirects_to_login(self, client):
        response = client.get(PROTECTED, headers={"Sec-Fetch-Dest": "document"})
        assert response.status_code == 302
        assert "/admin/login" in response.headers["Location"]

    def test_plain_get_redirects_to_login(self, client):
        response = client.get(PROTECTED)
        assert response.status_code == 302
        assert "/admin/login" in response.headers["Location"]


class TestOtherAuthFailuresKeepTheirMeaning:
    def test_wrong_password_401_is_not_marked_as_session_expiry(self, client):
        response = client.post(
            "/admin/login",
            data={"username": "admin", "password": "definitely-wrong"},
            headers={"HX-Request": "true"},
        )
        assert response.status_code == 401
        # A failed sign-in must not be reported to the shell as an expired session.
        assert response.headers.get(AUTH_STATUS_HEADER) != SESSION_EXPIRED_CODE

    def test_ip_denial_is_async_aware(self, _app, monkeypatch):
        from anteumbra.interfaces.web import auth as auth_module

        monkeypatch.setattr(
            auth_module,
            "get_admin_credentials",
            lambda: ("admin", "", ["10.255.255.1"]),
        )
        with _app.test_client() as client:
            async_response = client.get(PROTECTED, headers={"HX-Request": "true"})
            document_response = client.get(PROTECTED, headers={"Sec-Fetch-Dest": "document"})

        assert async_response.status_code == 403
        assert async_response.headers[AUTH_STATUS_HEADER] == IP_DENIED_CODE
        # A blocked IP is not an expired session, and a plain navigation keeps the
        # original plain-text body.
        assert document_response.status_code == 403
        assert document_response.headers.get(AUTH_STATUS_HEADER) is None
        assert "被拒绝访问" in document_response.get_data(as_text=True)
