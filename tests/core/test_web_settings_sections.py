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


# ── the readability pass ───────────────────────────────────────────────────
#
# The page was long and its values never said which of three sources was in
# force.  These tests pin the controls that answer "what did I change here?":
# two server-side filters, a jump-to-section list, a per-section count of values
# that differ from the shipped defaults, and the link to the full config editor.


def _filter_links(body: str) -> dict[str, str]:
    return {
        match.group(1): match.group(0)
        for match in re.finditer(r'<a[^>]*data-settings-filter="([^"]+)"[^>]*>', body)
    }


def test_the_page_offers_the_readability_filters(client):
    body = client.get(PAGE_URL, headers={"HX-Request": "true"}).get_data(as_text=True)
    links = _filter_links(body)

    assert set(links) == {"all", "changed", "shipped"}
    assert "Only non-default values" in body
    assert "Only changed from shipped defaults" in body
    # The chosen filter has to survive a reload, so it travels in the URL.
    assert "only=changed" in links["changed"]
    assert "only=shipped" in links["shipped"]
    assert links["all"].count('data-settings-filter-active="true"') == 1


def test_the_active_filter_is_marked_and_remembered(client):
    body = client.get(
        PAGE_URL + "?only=changed", headers={"HX-Request": "true"}
    ).get_data(as_text=True)

    assert _filter_links(body)["changed"].count('data-settings-filter-active="true"') == 1
    assert _filter_links(body)["all"].count('data-settings-filter-active="false"') == 1

    later = client.get(PAGE_URL, headers={"HX-Request": "true"}).get_data(as_text=True)
    assert _filter_links(later)["changed"].count('data-settings-filter-active="true"') == 1, (
        "a filter, like the expansion state, must outlive the link that set it"
    )


def test_an_unknown_filter_falls_back_to_showing_everything(client):
    body = client.get(
        PAGE_URL + "?only=<script>", headers={"HX-Request": "true"}
    ).get_data(as_text=True)

    assert _filter_links(body)["all"].count('data-settings-filter-active="true"') == 1
    assert "<script>" not in body


def test_toggling_a_section_keeps_the_active_filter(client):
    body = client.get(
        PAGE_URL + "?only=changed&open=environment", headers={"HX-Request": "true"}
    ).get_data(as_text=True)
    headers = _headers(body)

    assert "only=changed" in headers["storage"], (
        "collapsing a section must not silently reset which values are shown"
    )


def test_the_jump_control_lists_every_section(client):
    body = client.get(PAGE_URL, headers={"HX-Request": "true"}).get_data(as_text=True)

    assert 'data-settings-jump="1"' in body
    for name in SETTINGS_SECTIONS:
        assert f"#settings-{name}" in body, f"no jump target for {name}"


def test_each_section_header_counts_the_values_that_differ_from_defaults(client):
    """The count is over values a reader can actually see, per section."""
    body = client.get(PAGE_URL, headers={"HX-Request": "true"}).get_data(as_text=True)

    storage = _section_html(body, "storage")
    counts = re.findall(r'data-settings-changed="(\d+)"', storage)
    assert counts, "the header must carry a count"
    assert int(counts[0]) >= 1, "backend sqlite differs from the shipped json"
    assert "changed" in storage

    environment = _section_html(body, "environment")
    assert 'data-settings-changed="0"' in environment, "no config.toml keys belong to it"
    assert "all defaults" in environment


def test_the_page_links_to_the_advanced_config_editor(client):
    body = client.get(PAGE_URL, headers={"HX-Request": "true"}).get_data(as_text=True)

    assert 'href="/admin/config"' in body
    assert 'data-settings-advanced-editor-link="1"' in body
    assert body.count('data-settings-advanced-editor-link="1"') >= 2, (
        "both the page controls and the advanced section offer the editor"
    )

    from anteumbra.interfaces.web.pages import _NAV_TITLES

    assert _NAV_TITLES.get("config") == "Config Editor"


# ── secrets on the page ────────────────────────────────────────────────────


def test_the_page_reports_stored_credentials_without_rendering_them(client):
    """A credential must not sit in the page source, password input or not."""
    body = client.get(PAGE_URL, headers={"HX-Request": "true"}).get_data(as_text=True)

    assert "token-value" not in body, "ANTEUMBRA_WECHAT_API_KEY is set in .env"
    assert 'data-env-secret-state="set"' in body
    assert "ANTEUMBRA_WECHAT_API_KEY" in body
    assert "leave blank to keep the stored one" in body


def test_an_unset_credential_is_marked_unset(client, tmp_path):
    (tmp_path / ".env").write_text("", encoding="utf-8")

    body = client.get(PAGE_URL, headers={"HX-Request": "true"}).get_data(as_text=True)

    assert 'data-env-secret-state="unset"' in body
    assert 'data-env-secret-state="set"' not in body


def test_the_page_offers_a_password_form_instead_of_the_hash(client):
    body = client.get(PAGE_URL, headers={"HX-Request": "true"}).get_data(as_text=True)

    assert 'data-settings-password="1"' in body
    assert 'name="new_password"' in body
    assert "/admin/settings/password/save" in body
    assert 'data-env-password-hash="1"' in body
    assert 'name="web_admin.password_hash"' not in body


def test_a_shipped_default_resolves_from_both_map_shapes():
    """A parsed config nests; ``_read_shipped_defaults`` returns flat dotted keys.

    Looking the flat map up segment by segment finds nothing, and every count and
    filter built on it then reports "nothing changed" - which is exactly the
    failure this pins.
    """
    from anteumbra.interfaces.web.blueprints.settings_bp import _MISSING, _get_dotted

    assert _get_dotted({"storage": {"backend": "json"}}, "storage.backend") == "json"
    assert _get_dotted({"storage.backend": "json"}, "storage.backend") == "json"
    assert _get_dotted({"storage.backend": "json"}, "storage.missing") is _MISSING
    assert _get_dotted({"storage.backend": "json"}, "missing.backend") is _MISSING

