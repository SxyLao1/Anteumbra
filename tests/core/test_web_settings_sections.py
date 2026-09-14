# -*- coding: utf-8 -*-
"""The settings page structure: ordering, collapsible sections, summaries.

The page was one long column of cards in the order they happened to be written,
so the mail password sat at the bottom of the config editor.  These tests pin
the new contract: secrets first, then the operational sections in order, every
section collapsible, expansion state remembered (query string and session), and
a one-line state summary in each header so nothing needs expanding to be read.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from anteumbra.interfaces.web.blueprints.settings_bp import SETTINGS_SECTIONS

PAGE_URL = "/admin/settings"

CONFIG = {
    "website": [
        {
            "name": "alpha",
            "path": "/srv/alpha",
            "port": 8080,
            "enabled": True,
            "log_config": {
                "log_monitor_enabled": True,
                "access_log_path": "/var/log/nginx/access.log",
            },
        },
        {"name": "beta", "path": "/srv/beta", "port": 8081, "enabled": True, "log_config": {}},
        {"name": "gamma", "path": "/srv/gamma", "port": 8082, "enabled": False, "log_config": {}},
    ],
    "paths": {
        "monitor_paths": ["/srv/alpha", "/srv/beta"],
        "monitor_extensions": [".php", ".jsp"],
    },
    "notifier": {"enabled": True, "email": {"enabled": False}, "wechat": {"enabled": True}},
    "storage": {"backend": "sqlite"},
    "quarantine": {"auto_quarantine_enabled": True},
    "ip_blocker": {"auto_block_enabled": False},
    "waf_source": {"enabled": False},
    "plugins": {"enabled": True, "builtin": []},
}


class _Config:
    def __init__(self, path, data):
        self.path = path
        self._data = data

    def get(self):
        return self._data

    def reload(self):
        return self._data


class _Runtime:
    def __init__(self, config):
        self.config = config


@pytest.fixture(scope="module")
def _app():
    import os

    os.environ.setdefault("ANTEUMBRA_TOOL_MODE", "true")

    from anteumbra.interfaces.web.factory import create_app

    app = create_app()
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False
    return app


@pytest.fixture
def client(tmp_path, monkeypatch, _app):
    from anteumbra.interfaces.web.blueprints import settings_bp as module

    config_path = tmp_path / "config.toml"
    config_path.write_text("", encoding="utf-8")
    (tmp_path / ".env").write_text(
        "ANTEUMBRA_WECHAT_API_KEY=token-value\nANTEUMBRA_EMAIL_USERNAME=\n",
        encoding="utf-8",
    )
    runtime = _Runtime(_Config(config_path, CONFIG))
    monkeypatch.setattr(module, "get_runtime", lambda: runtime)
    monkeypatch.delitem(_app.extensions, "anteumbra.plugin_manager", raising=False)

    created = _app.test_client()
    with created.session_transaction() as flask_session:
        flask_session["authenticated"] = True
        flask_session["username"] = "admin"
    return created


def _panel_names(body: str) -> list[str]:
    return re.findall(r'data-settings-panel="([^"]+)"', body)


def _headers(body: str) -> dict[str, str]:
    headers = {}
    for match in re.finditer(r"<button[^>]*data-settings-section=\"([^\"]+)\"[^>]*>", body):
        headers[match.group(1)] = match.group(0)
    return headers


def _section_html(body: str, name: str) -> str:
    start = body.index(f'data-settings-panel="{name}"')
    end = body.find('data-settings-panel="', start + 1)
    return body[start : end if end != -1 else len(body)]


def _collapsed_bodies(body: str) -> list[str]:
    """Panel ids whose body is hidden in the served HTML."""
    hidden = []
    for name in SETTINGS_SECTIONS:
        after_header = _section_html(body, name).split("</button>", 1)
        assert len(after_header) == 2, f"{name} rendered without a header button"
        opening_tag = after_header[1].split(">", 1)[0]
        if "display:none" in opening_tag:
            hidden.append(name)
    return hidden


# ── ordering ───────────────────────────────────────────────────────────────


def test_sections_are_served_in_the_requested_order(client):
    body = client.get(PAGE_URL, headers={"HX-Request": "true"}).get_data(as_text=True)

    assert _panel_names(body) == list(SETTINGS_SECTIONS)


def test_the_environment_section_comes_first(client):
    body = client.get(PAGE_URL, headers={"HX-Request": "true"}).get_data(as_text=True)

    assert _panel_names(body)[0] == "environment"
    assert body.index('data-settings-panel="environment"') < body.index(
        'data-settings-panel="sites"'
    )
    assert "ENVIRONMENT &amp; SECRETS" in body or "ENVIRONMENT & SECRETS" in body
    assert 'name="ANTEUMBRA_EMAIL_USERNAME"' in body
    assert 'name="ANTEUMBRA_EMAIL_PASSWORD"' in body
    assert 'hx-post="/admin/settings/environment/save"' in body


# ── collapse state ─────────────────────────────────────────────────────────


def test_only_the_first_section_is_open_on_a_first_visit(client):
    body = client.get(PAGE_URL, headers={"HX-Request": "true"}).get_data(as_text=True)
    headers = _headers(body)

    assert headers["environment"].find('aria-expanded="true"') >= 0
    for name in SETTINGS_SECTIONS[1:]:
        assert 'aria-expanded="false"' in headers[name], f"{name} should start collapsed"

    hidden = _collapsed_bodies(body)
    assert "environment" not in hidden
    assert set(hidden) == set(SETTINGS_SECTIONS[1:])


def test_the_query_string_chooses_the_open_sections(client):
    body = client.get(
        PAGE_URL + "?open=notifications,storage", headers={"HX-Request": "true"}
    ).get_data(as_text=True)
    headers = _headers(body)

    assert 'aria-expanded="true"' in headers["notifications"]
    assert 'aria-expanded="true"' in headers["storage"]
    assert 'aria-expanded="false"' in headers["environment"]
    assert 'aria-expanded="false"' in headers["plugins"]

    hidden = _collapsed_bodies(body)
    assert set(hidden) == set(SETTINGS_SECTIONS) - {"notifications", "storage"}


def test_an_unknown_section_name_in_the_query_string_is_ignored(client):
    body = client.get(
        PAGE_URL + "?open=<script>,plugins", headers={"HX-Request": "true"}
    ).get_data(as_text=True)

    assert 'aria-expanded="true"' in _headers(body)["plugins"]
    assert "<script>" not in body


def test_the_open_state_survives_a_visit_without_the_query_string(client):
    client.get(PAGE_URL + "?open=plugins", headers={"HX-Request": "true"})

    body = client.get(PAGE_URL, headers={"HX-Request": "true"}).get_data(as_text=True)

    assert 'aria-expanded="true"' in _headers(body)["plugins"]
    assert 'aria-expanded="false"' in _headers(body)["environment"]


def test_collapsing_everything_is_remembered(client):
    client.get(PAGE_URL + "?open=", headers={"HX-Request": "true"})

    body = client.get(PAGE_URL, headers={"HX-Request": "true"}).get_data(as_text=True)

    assert set(_collapsed_bodies(body)) == set(SETTINGS_SECTIONS)


def test_section_headers_toggle_through_the_query_string(client):
    body = client.get(PAGE_URL, headers={"HX-Request": "true"}).get_data(as_text=True)
    headers = _headers(body)

    # Environment is open, so its header offers the URL that collapses it.
    assert 'hx-get="/admin/settings?open="' in headers["environment"]
    # Plugins is closed, so its header offers the URL that opens it.
    assert 'hx-get="/admin/settings?open=environment,plugins"' in headers["plugins"]
    for name in SETTINGS_SECTIONS:
        assert 'hx-target="#main-content"' in headers[name]
        assert 'hx-push-url="true"' in headers[name], "the state must land in the address bar"


# ── summaries ──────────────────────────────────────────────────────────────


def test_each_header_carries_a_one_line_state_summary(client):
    body = client.get(PAGE_URL, headers={"HX-Request": "true"}).get_data(as_text=True)

    assert "2 site(s) enabled" in body
    assert "2 watched path(s)" in body and "access log on" in body
    assert "1 channel(s) enabled" in body
    assert "backend sqlite" in body
    assert "1 credentials set" in body and "mail not configured" in body
    assert "signed in as admin" in body


def test_mail_credentials_are_reported_as_configured(client, tmp_path):
    (tmp_path / ".env").write_text(
        "ANTEUMBRA_EMAIL_USERNAME=ops@example.com\n"
        "ANTEUMBRA_EMAIL_PASSWORD=secret\n",
        encoding="utf-8",
    )

    body = client.get(PAGE_URL, headers={"HX-Request": "true"}).get_data(as_text=True)

    assert "mail configured" in body
    assert "mail not configured" not in body


# ── nothing existing was removed ───────────────────────────────────────────


def test_existing_panels_and_hooks_are_still_present(client):
    body = client.get(PAGE_URL, headers={"HX-Request": "true"}).get_data(as_text=True)

    assert "settings-grid" in body, "the shell's page marker must stay"
    assert 'id="system-modal"' in body
    for endpoint in (
        "/admin/account",
        "/admin/settings/notifications",
        "/admin/settings/storage-status",
        "/admin/settings/siem-status",
        "/admin/settings/plugin-status",
        "/admin/settings/config/editor",
    ):
        assert endpoint in body, f"{endpoint} disappeared from the settings page"
    for action in ("settings.system-open", "core.backdrop-close", "core.modal-hide"):
        assert f'data-action="{action}"' in body


def test_the_config_editor_still_owns_the_full_config_tree(client):
    """The .env block stays in the config editor; the new section adds a view, not a move."""
    body = client.get(
        "/admin/settings/config/editor", headers={"HX-Request": "true"}
    ).get_data(as_text=True)

    assert 'id="config-tree"' in body
    assert 'data-action="settings.config-save"' in body
    assert 'id="env-pwd-input"' in body


def test_section_names_are_stable_identifiers():
    """The ids are part of the URL contract; renaming one breaks bookmarks."""
    assert SETTINGS_SECTIONS == (
        "environment",
        "account",
        "sites",
        "detection",
        "notifications",
        "storage",
        "plugins",
        "advanced",
    )


# ── the environment section saves through .env ─────────────────────────────


def test_environment_section_writes_values_and_reports_them(client, tmp_path):
    import os

    written_key = "ANTEUMBRA_EMAIL_USERNAME"
    try:
        response = client.post(
            "/admin/settings/environment/save",
            data={written_key: "ops@example.com", "ANTEUMBRA_EMAIL_PASSWORD": ""},
            headers={"HX-Request": "true"},
        )

        assert response.status_code == 200
        body = response.get_data(as_text=True)
        assert 'data-env-notice="success"' in body
        assert "1 value(s) written to .env" in body
        env_text = (tmp_path / ".env").read_text(encoding="utf-8")
        assert "ANTEUMBRA_EMAIL_USERNAME=ops@example.com" in env_text
        assert "ANTEUMBRA_WECHAT_API_KEY=token-value" in env_text, "untouched keys must survive"
    finally:
        os.environ.pop(written_key, None)


def test_environment_section_never_blanks_a_credential(client, tmp_path):
    import os

    try:
        response = client.post(
            "/admin/settings/environment/save",
            data={"ANTEUMBRA_WECHAT_API_KEY": "", "ANTEUMBRA_EMAIL_PASSWORD": ""},
            headers={"HX-Request": "true"},
        )

        assert response.status_code == 200
        assert "Nothing to save" in response.get_data(as_text=True)
        assert "ANTEUMBRA_WECHAT_API_KEY=token-value" in (tmp_path / ".env").read_text(
            encoding="utf-8"
        )
    finally:
        os.environ.pop("ANTEUMBRA_EMAIL_PASSWORD", None)


def test_environment_section_survives_an_unwritable_env_file(client, tmp_path, monkeypatch):
    def _explode(*args, **kwargs):
        raise OSError("disk is read-only")

    from anteumbra.interfaces.web.blueprints import settings_bp as module

    monkeypatch.setattr(module, "write_env_value", _explode)

    response = client.post(
        "/admin/settings/environment/save",
        data={"ANTEUMBRA_EMAIL_USERNAME": "ops@example.com"},
        headers={"HX-Request": "true"},
    )

    assert response.status_code == 200, "a failed .env write must render inline, not 500"
    assert 'data-env-notice="error"' in response.get_data(as_text=True)


def test_the_page_requires_authentication(client):
    with client.session_transaction() as flask_session:
        flask_session.clear()

    response = client.get(PAGE_URL)

    assert response.status_code in (301, 302, 401, 403)


def test_config_path_is_reported_in_the_advanced_summary(client, tmp_path):
    body = client.get(PAGE_URL, headers={"HX-Request": "true"}).get_data(as_text=True)

    assert Path("config.toml").name in body
    assert "config file config.toml" in body
