# -*- coding: utf-8 -*-
"""The per-plugin configuration forms and the settings readability pass.

Before this work the plugin panel could switch a plugin on and off and nothing
else: SMTP hosts, webhook URLs, poll intervals, thresholds and cooldowns were
reachable only by hand-editing ``config.toml``, and the settings page never said
which of three possible sources (``config.toml``, ``.env``, the plugin's own
built-in default) was actually in force.

These tests drive the real endpoints against a throwaway ``config.toml``, a
throwaway ``config.toml.example`` (the "shipped defaults" baseline) and a real
``PluginManager``, because the behaviour worth pinning is the interaction between
the file, the schema and the live plugin set:

* a typed control per declared field, with its effective value AND its source,
* saving through the same path the plugin-control endpoint uses (backup -> write
  -> delta validate -> live apply) and an honest report of the outcome,
* field-level validation enforced server-side, so a hand-crafted POST cannot
  write a value the form would have refused,
* secrets that are visible only as set/unset and never as a value anywhere,
* the non-default filters, and the password flow that hashes instead of storing.
"""

from __future__ import annotations

import html
import os
import re
from typing import Any

import pytest
import tomli_w

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10
    import tomli as tomllib

from anteumbra.application.plugin_manager import PluginManager
from anteumbra.domain.plugin import DomainEvent, Plugin

PAGE_URL = "/admin/settings"
PANEL_URL = "/admin/settings/plugin-status"
FORM_URL = "/admin/settings/plugins/config"
SAVE_URL = "/admin/settings/plugins/config/save"
PASSWORD_URL = "/admin/settings/password/save"

#: The plugin whose ``config_schema()`` declares every control kind the form
#: knows, plus one key of each source (config.toml / .env / built-in default).
TYPED = "typed_plugin"

#: A plugin with no ``config_schema()`` at all: the form must still render the
#: keys its section actually has, and say that the types were inferred.
PLAIN = "plain_plugin"

SECRET_VAR = "TEST_API_TOKEN"
SECRET_VALUE = "cf-token-9f8e7d6c5b4a3210"
#: A variable config.toml refers to, which nothing defines and which has no
#: fallback: the effective value is "nothing", and the form has to say so.
UNSET_VAR = "TEST_INGEST_PATH"

TYPED_SCHEMA: list[dict[str, Any]] = [
    {
        "name": "enabled",
        "type": "toggle",
        "default": True,
        "label": "Enabled",
        "description": "Master switch for this adapter.",
    },
    {
        "name": "host",
        "type": "text",
        "default": "127.0.0.1",
        "label": "Listen host",
        "required": True,
    },
    {
        "name": "port",
        "type": "number",
        "default": 514,
        "min": 1,
        "max": 65535,
        "label": "Listen port",
        "description": "UDP port the receiver binds.",
    },
    {
        "name": "format",
        "type": "select",
        "default": "cef",
        "choices": ("cef", "json", "raw"),
        "label": "Wire format",
    },
    {
        "name": "site_ids",
        "type": "list",
        "default": [],
        "label": "Sites",
        "item_pattern": r"^[a-z0-9][a-z0-9_-]*$",
        "item_pattern_hint": "a lowercase site id",
    },
    {
        # Absent from both config.toml and the shipped template: its effective
        # value can only come from the plugin's own declared default.
        "name": "cooldown",
        "type": "number",
        "default": 30,
        "min": 0,
        "max": 3600,
        "label": "Cooldown (seconds)",
    },
    {
        "name": "ingest_path",
        "type": "text",
        "default": "",
        "label": "Ingest path",
    },
    {
        "name": "api_token",
        "type": "secret",
        "default": "",
        "label": "API token",
        "description": "Credential for the upstream API.",
        "env_key": SECRET_VAR,
        "required": True,
    },
]

LIVE_CONFIG: dict[str, Any] = {
    "web_admin": {
        "port": 11111,
        "allowed_ips": ["127.0.0.1"],
        "session_cookie_secure": True,
    },
    "quarantine": {"auto_quarantine_enabled": True},
    "ip_blocker": {"auto_block_enabled": True, "devices": ["10.0.0.0/8"]},
    "plugins": {
        "enabled": True,
        "builtin": [TYPED, PLAIN],
        TYPED: {
            "enabled": True,
            "host": "0.0.0.0",
            "port": 1514,
            "format": "json",
            "site_ids": ["alpha"],
            "ingest_path": "${" + UNSET_VAR + "}",
            "api_token": "${" + SECRET_VAR + ":-}",
        },
        # Identical to the shipped template: this plugin has nothing that differs
        # from the file the deployment started with, which is what the "changed
        # from shipped defaults" filter is for.
        PLAIN: {"enabled": True, "retries": 1, "note": "shipped"},
    },
}

#: What ``config.toml.example`` says: the baseline the "changed from shipped
#: defaults" filter and the per-section counters compare against.
SHIPPED_TEMPLATE: dict[str, Any] = {
    "plugins": {
        "enabled": True,
        "builtin": [TYPED, PLAIN],
        TYPED: {
            "enabled": True,
            "host": "0.0.0.0",
            "port": 514,
            "format": "cef",
            "site_ids": [],
            "api_token": "${" + SECRET_VAR + ":-}",
        },
        PLAIN: {"enabled": True, "retries": 1, "note": "shipped"},
    },
}


class _TypedPlugin(Plugin):
    """A plugin that declares its own schema, like the built-in adapters do."""

    @property
    def name(self) -> str:
        return TYPED

    @property
    def version(self) -> str:
        return "9.9.9"

    @property
    def supported_events(self) -> list[str]:
        return ["waf.event"]

    @classmethod
    def config_schema(cls) -> list[dict[str, Any]]:
        return [dict(entry) for entry in TYPED_SCHEMA]

    def activate(self, config: dict[str, Any]) -> None:
        self.activated_with = dict(config)

    def deactivate(self) -> None:
        return None

    def on_event(self, event: DomainEvent) -> None:
        return None


class _PlainPlugin(Plugin):
    """A plugin that declares nothing: the form falls back to its real keys."""

    @property
    def name(self) -> str:
        return PLAIN

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def supported_events(self) -> list[str]:
        return ["test.event"]

    def activate(self, config: dict[str, Any]) -> None:
        self.activated_with = dict(config)

    def deactivate(self) -> None:
        return None

    def on_event(self, event: DomainEvent) -> None:
        return None


class _Config:
    """Path-backed config surface, shaped like TomlConfigProvider."""

    def __init__(self, path):
        self.path = path
        self.reloads = 0

    def get(self) -> dict[str, Any]:
        with open(self.path, "rb") as handle:
            return tomllib.load(handle)

    def reload(self) -> dict[str, Any]:
        self.reloads += 1
        return self.get()


class _Runtime:
    def __init__(self, config: _Config) -> None:
        self.config = config


class Harness:
    def __init__(self, manager, runtime, client, tmp_path) -> None:
        self.manager = manager
        self.runtime = runtime
        self.client = client
        self.tmp_path = tmp_path

    # -- files ------------------------------------------------------------

    @property
    def config_path(self):
        return self.tmp_path / "config.toml"

    @property
    def env_path(self):
        return self.tmp_path / ".env"

    def config(self) -> dict[str, Any]:
        with open(self.config_path, "rb") as handle:
            return tomllib.load(handle)

    def section(self, name: str = TYPED) -> dict[str, Any]:
        return self.config()["plugins"].get(name, {})

    def write_config(self, data: dict[str, Any]) -> None:
        self.config_path.write_text(tomli_w.dumps(data), encoding="utf-8")

    def config_text(self) -> str:
        return self.config_path.read_text(encoding="utf-8")

    def env_text(self) -> str:
        return self.env_path.read_text(encoding="utf-8") if self.env_path.exists() else ""

    def write_env(self, values: dict[str, str]) -> None:
        self.env_path.write_text(
            "".join(f"{key}={value}\n" for key, value in values.items()), encoding="utf-8"
        )

    # -- requests ---------------------------------------------------------

    def get(self, url: str, **params) -> str:
        response = self.client.get(url, query_string=params, headers={"HX-Request": "true"})
        assert response.status_code == 200, f"{url} answered HTTP {response.status_code}"
        return html.unescape(response.get_data(as_text=True))

    def page(self) -> str:
        return self.get(PAGE_URL)

    def panel(self, **params) -> str:
        return self.get(PANEL_URL, **params)

    def form(self, plugin: str = TYPED, **params) -> str:
        return self.get(FORM_URL, plugin=plugin, **params)

    def save(self, data: dict[str, Any], plugin: str = TYPED):
        payload = {"plugin": plugin, **data}
        response = self.client.post(SAVE_URL, data=payload, headers={"HX-Request": "true"})
        assert response.status_code == 200, (
            "a rejected plugin setting must render inline, not fail the request: "
            f"HTTP {response.status_code}"
        )
        return html.unescape(response.get_data(as_text=True))

    def every_fragment(self) -> dict[str, str]:
        """Every page and fragment this feature serves, for a secret sweep."""
        bodies = {
            "settings page": self.page(),
            "plugin panel": self.panel(),
            "config editor fragment": self.get("/admin/settings/config/editor"),
        }
        for row in re.findall(r'data-plugin-row="([^"]+)"', bodies["plugin panel"]):
            bodies[f"plugin form {row}"] = self.form(row)
        return bodies


def _build_harness(tmp_path, monkeypatch, app) -> Harness:
    from anteumbra.interfaces.web.blueprints import settings_bp as module

    config_path = tmp_path / "config.toml"
    config_path.write_text(tomli_w.dumps(LIVE_CONFIG), encoding="utf-8")
    # The shipped template beside the live file is what "shipped defaults" means
    # for this deployment; ``_shipped_config_path`` prefers it over the package's.
    (tmp_path / "config.toml.example").write_text(
        tomli_w.dumps(SHIPPED_TEMPLATE), encoding="utf-8"
    )
    runtime = _Runtime(_Config(config_path))

    manager = PluginManager()
    manager.set_plugin_factories({TYPED: _TypedPlugin, PLAIN: _PlainPlugin})
    manager.init_from_config(runtime.config.get())

    monkeypatch.setattr(module, "get_runtime", lambda: runtime)
    monkeypatch.setitem(app.extensions, "anteumbra.plugin_manager", manager)

    client = app.test_client()
    with client.session_transaction() as flask_session:
        flask_session["authenticated"] = True
        flask_session["username"] = "admin"
    return Harness(manager, runtime, client, tmp_path)


@pytest.fixture(scope="module")
def _app():
    os.environ.setdefault("ANTEUMBRA_TOOL_MODE", "true")

    from anteumbra.interfaces.web.factory import create_app

    app = create_app()
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False
    return app


@pytest.fixture
def harness(tmp_path, monkeypatch, _app):
    """A settings page whose runtime reads throwaway config files."""
    for name in (SECRET_VAR, UNSET_VAR):
        monkeypatch.delenv(name, raising=False)
    created = _build_harness(tmp_path, monkeypatch, _app)
    yield created
    created.manager.shutdown()
    for name in (SECRET_VAR, UNSET_VAR):
        os.environ.pop(name, None)


# ── small readers ──────────────────────────────────────────────────────────


def _field(body: str, key: str) -> str:
    """The rendered block of one configuration field."""
    start = body.find(f'data-plugin-field="{key}"')
    if start == -1:
        return ""
    end = body.find("data-plugin-field=", start + 1)
    return body[start : end if end != -1 else len(body)]


def _row(body: str, name: str) -> str:
    start = body.index(f'data-plugin-row="{name}"')
    end = body.find("data-plugin-row=", start + 1)
    return body[start : end if end != -1 else len(body)]


def _notices(body: str) -> list[tuple[str, str]]:
    return re.findall(r'data-plugin-notice="(\w+)"[^>]*>(.*?)</div>', body, re.DOTALL)


def _levels(body: str) -> list[str]:
    return [level for level, _ in _notices(body)]


# ═══════════════════════════════════════════════════════════════════════════
# 1. Every plugin exposes a typed form
# ═══════════════════════════════════════════════════════════════════════════


def test_every_row_opens_a_form_for_its_own_section(harness):
    body = harness.panel()

    for name, section in ((TYPED, TYPED), (PLAIN, PLAIN)):
        row = _row(body, name)
        assert f'data-plugin-configure="{name}"' in row
        assert f'hx-get="/admin/settings/plugins/config?plugin={name}' in row
        assert f"plugins.{section}" in row, "the row must name the section it edits"
    assert 'data-plugin-config-target="1"' in body, "one shared form target, not one per row"
    assert 'hx-target="#plugin-config-form"' in body, (
        "the row must expand into the shared form target, not replace the inventory"
    )


def test_the_form_renders_one_typed_control_per_declared_field(harness):
    body = harness.form()

    assert 'data-plugin-config-form="typed_plugin"' in body
    assert "[plugins.typed_plugin]" in body

    enabled = _field(body, "enabled")
    assert 'data-plugin-field-type="toggle"' in enabled and 'type="checkbox"' in enabled
    assert "checked" in enabled, "the effective value is true, so the box is ticked"

    port = _field(body, "port")
    assert 'data-plugin-field-type="number"' in port
    assert 'type="number"' in port and 'min="1"' in port and 'max="65535"' in port
    assert 'value="1514"' in port, "the control shows the effective value, not the default"

    wire = _field(body, "format")
    assert 'data-plugin-field-type="select"' in wire
    for choice in ("cef", "json", "raw"):
        assert f'<option value="{choice}"' in wire
    assert '<option value="json" selected>' in wire

    sites = _field(body, "site_ids")
    assert 'data-plugin-field-type="list"' in sites
    assert 'value="alpha"' in sites

    token = _field(body, "api_token")
    assert 'data-plugin-field-type="secret"' in token
    assert 'type="password"' in token and 'data-plugin-secret-input="1"' in token


def test_every_field_reports_its_effective_value_and_the_source_it_came_from(harness):
    """The reader must never have to guess which of three files is in charge."""
    harness.write_env({SECRET_VAR: SECRET_VALUE})
    body = harness.form()

    # value in config.toml -> source config.toml
    host = _field(body, "host")
    assert 'data-plugin-field-source="config"' in host
    assert 'value="0.0.0.0"' in host
    assert "effective from:" in host and "config.toml" in host

    # nothing anywhere -> the plugin's own declared default
    cooldown = _field(body, "cooldown")
    assert 'data-plugin-field-source="builtin"' in cooldown
    assert 'value="30"' in cooldown and "built-in default" in cooldown

    # a credential .env defines -> source .env
    token = _field(body, "api_token")
    assert 'data-plugin-field-source="env"' in token and ".env" in token

    # every rendered field carries both facts, none is left silent
    assert body.count("data-plugin-field=") == body.count("data-plugin-field-source-label=")


def test_a_plugin_without_a_schema_gets_controls_for_the_keys_it_actually_has(harness):
    body = harness.form(PLAIN)

    assert "declares no schema in this build" in body, "the caveat must be stated"
    assert 'data-plugin-field="enabled"' in body
    assert 'data-plugin-field-type="toggle"' in _field(body, "enabled")
    retries = _field(body, "retries")
    assert 'data-plugin-field-type="number"' in retries and 'value="1"' in retries
    assert 'value="shipped"' in _field(body, "note")


def test_a_declared_schema_is_not_reported_as_guessed_controls(harness):
    body = harness.form(TYPED)

    assert "declares no schema in this build" not in body, (
        "a plugin that ships a schema must not be told its types were inferred"
    )


def test_an_unresolved_variable_is_reported_as_having_no_effective_value(harness):
    """config.toml refers to a variable nothing defines: say so, do not show it."""
    body = harness.form()

    ingest = _field(body, "ingest_path")
    assert 'data-plugin-field-unresolved="ingest_path"' in ingest
    assert UNSET_VAR in ingest
    assert re.search(r'name="field__ingest_path"[^>]*value="([^"]*)"', ingest).group(1) == "", (
        "the literal placeholder must not be presented as the effective value"
    )
    assert "No value is in effect" in body


# ═══════════════════════════════════════════════════════════════════════════
# 2. Saving goes through the validated write path and reports the outcome
# ═══════════════════════════════════════════════════════════════════════════


def test_saving_writes_config_with_a_backup_and_reports_the_live_outcome(harness):
    body = harness.save({"field__port": "20514", "field__format": "raw"})

    assert harness.section()["port"] == 20514
    assert harness.section()["format"] == "raw"
    backups = sorted(harness.tmp_path.glob("config.toml.*.bak"))
    assert len(backups) == 1, "every write keeps one timestamped backup"
    assert _levels(body)[0] == "success", body
    assert "error" not in _levels(body)
    assert "reloaded the plugin" in body and "uses them now" in body
    assert "2 value(s)" in body
    assert "Backup kept" in body
    # the resulting state comes back with the row that was just changed
    row = _row(body, TYPED)
    assert 'data-plugin-focus="1"' in row
    assert re.search(r'data-plugin-changed="(\d+)"', row)


def test_a_save_that_cannot_be_applied_asks_for_a_restart(harness):
    harness.manager.shutdown()
    harness.manager._enabled = False

    body = harness.save({"field__port": "20514"})

    assert harness.section()["port"] == 20514, "the config is still written"
    assert _levels(body)[0] == "warning"
    assert "A restart is required." in body
    assert "reloaded the plugin" not in body, "never claim a live apply that did not happen"


def test_saving_a_toggle_stores_true_where_the_operator_ticked_it(harness):
    """The form posts a hidden "false" next to the checkbox, both under one name."""
    before = harness.section()["enabled"]
    assert before is True

    body = harness.save({"field__port": "1514"}, plugin=TYPED)
    assert body  # unchanged save renders a result rather than failing
    assert harness.section()["enabled"] is True, "an untouched toggle must not be switched off"

    harness.save({"field__enabled": ["false", "true"], "field__port": "1514"})
    assert harness.section()["enabled"] is True, "a ticked checkbox wins over the hidden false"

    harness.save({"field__enabled": "false", "field__port": "1514"})
    assert harness.section()["enabled"] is False


def test_a_field_the_form_did_not_render_is_never_written(harness):
    """A readability filter hides fields; hiding one must not blank it."""
    filtered = harness.form(only="changed")
    assert 'data-plugin-field="enabled"' not in filtered, "the filter hid the toggle"
    assert "field__enabled" not in filtered

    harness.save({"field__port": "20514"})

    assert harness.section()["port"] == 20514
    assert harness.section()["enabled"] is True, (
        "a toggle the filter hid must keep its stored value"
    )


def test_nothing_is_written_when_every_value_is_unchanged(harness):
    before = harness.config_text()

    body = harness.save({"field__port": "1514", "field__host": "0.0.0.0"})

    assert _levels(body) == ["info"]
    assert "Nothing to save" in body
    assert harness.config_text() == before
    assert not list(harness.tmp_path.glob("config.toml.*.bak")), "no backup for a no-op"


# ═══════════════════════════════════════════════════════════════════════════
# 3. Field-level validation, enforced server-side
# ═══════════════════════════════════════════════════════════════════════════


@pytest.mark.parametrize(
    ("payload", "key", "expected"),
    [
        ({"field__port": "70000"}, "port", "Must be at most 65535."),
        ({"field__port": "0"}, "port", "Must be at least 1."),
        ({"field__port": "not-a-number"}, "port", "Expected a number."),
        ({"field__format": "yaml"}, "format", "Must be one of: cef, json, raw."),
        ({"field__site_ids": "Alpha Site"}, "site_ids", "Every entry must be a lowercase site id"),
        ({"field__host": ""}, "host", "This value is required."),
    ],
)
def test_an_invalid_value_is_rejected_inline_and_never_written(
    harness, payload, key, expected
):
    before = harness.config_text()

    body = harness.save(payload)

    assert f'data-plugin-field-error="{key}"' in body, body
    assert expected in body
    assert harness.config_text() == before, "a rejected value must never reach the file"
    assert not list(harness.tmp_path.glob("config.toml.*.bak"))
    # the operator stays in the form, with the inventory still around it
    assert 'data-plugin-panel="1"' in body
    assert f'data-plugin-config-form="{TYPED}"' in body
    assert "Nothing was written" in body


def test_one_bad_field_stops_the_whole_save(harness):
    """A partially applied form is the outcome an operator cannot reason about."""
    before = harness.config_text()

    body = harness.save({"field__port": "20514", "field__format": "yaml"})

    assert "field__port" in body or 'data-plugin-field-error="format"' in body
    assert harness.config_text() == before, "the valid half must not be written either"
    assert harness.section()["port"] == 1514


def test_a_hand_crafted_post_cannot_write_an_undeclared_key(harness):
    body = harness.save({"field__not_a_setting": "oops", "field__port": "20514"})

    assert "not_a_setting" not in harness.config_text()
    assert harness.section().get("not_a_setting") is None
    assert harness.section()["port"] == 20514, "the declared field still saves"
    assert body


def test_the_plugin_name_is_validated_before_any_write(harness):
    before = harness.config_text()

    body = harness.save({"field__port": "20514"}, plugin="../../etc/passwd")

    assert "Unknown plugin" in body
    assert harness.config_text() == before


def test_an_unknown_plugin_renders_an_inline_error(harness):
    body = harness.save({"field__port": "1"}, plugin="does_not_exist")

    assert _levels(body) == ["error"]
    assert "Unknown plugin: does_not_exist" in body


def test_the_form_without_a_plugin_name_answers_inline(harness):
    body = harness.get(FORM_URL)

    assert "No plugin was named." in body
    assert "Error:" not in body, "an unnamed form is an operator mistake, not a 500"


# ═══════════════════════════════════════════════════════════════════════════
# 4. Secrets: set/unset only, written to .env, never rendered anywhere
# ═══════════════════════════════════════════════════════════════════════════


def test_a_secret_reports_set_or_unset_without_ever_showing_its_value(harness):
    harness.write_env({SECRET_VAR: SECRET_VALUE})

    body = harness.form()
    token = _field(body, "api_token")

    assert 'data-plugin-secret-state="set"' in token
    assert SECRET_VALUE not in token
    assert 'value=""' in token, "the input is write-only"
    assert f".env: {SECRET_VAR}" in token, "the reader is told which variable to set"
    assert "A value is stored; it is never displayed." in token


def test_an_unset_secret_says_so_instead_of_looking_configured(harness):
    body = harness.form()
    token = _field(body, "api_token")

    assert 'data-plugin-secret-state="unset"' in token
    assert "No value is stored yet." in token


def test_the_secret_value_never_appears_in_any_page_or_fragment(harness):
    """The sweep: one value, every response this feature serves."""
    harness.write_env({SECRET_VAR: SECRET_VALUE})

    for name, body in harness.every_fragment().items():
        assert SECRET_VALUE not in body, f"the secret leaked into the {name}"


def test_the_secret_value_never_appears_in_a_save_response(harness):
    harness.write_env({SECRET_VAR: SECRET_VALUE})

    body = harness.save({"secret__api_token": SECRET_VALUE})

    assert SECRET_VALUE not in body
    assert _levels(body)[0] == "success"
    assert "secret(s) written to .env" in body


def test_writing_a_secret_goes_to_env_and_never_into_config_toml(harness):
    before = harness.config_text()

    harness.save({"secret__api_token": SECRET_VALUE})

    assert f"{SECRET_VAR}={SECRET_VALUE}" in harness.env_text()
    assert harness.config_text() == before, "config.toml must not receive the credential"
    assert SECRET_VALUE not in harness.config_text()
    assert f"${{{SECRET_VAR}:-}}" in harness.config_text(), "the placeholder stays"


def test_an_empty_secret_field_keeps_the_stored_value(harness):
    harness.write_env({SECRET_VAR: SECRET_VALUE})

    body = harness.save({"secret__api_token": ""})

    assert f"{SECRET_VAR}={SECRET_VALUE}" in harness.env_text()
    assert SECRET_VALUE not in body
    assert "Nothing to save" in body


def test_a_secret_the_env_writer_refuses_is_reported_not_swallowed(harness, monkeypatch):
    from anteumbra.interfaces.web.blueprints import settings_bp as module

    def _explode(*args, **kwargs):
        raise OSError("disk is read-only")

    monkeypatch.setattr(module, "write_env_value", _explode)

    body = harness.save({"secret__api_token": SECRET_VALUE})

    assert _levels(body) == ["error"]
    assert ".env write failed" in body
    assert SECRET_VALUE not in body


def test_a_secret_held_as_a_literal_in_config_toml_is_called_out(harness):
    """A literal in config.toml wins over .env, so a silent "saved" would lie."""
    config = harness.config()
    config["plugins"][TYPED]["api_token"] = "inline-literal-token"
    harness.write_config(config)
    harness.runtime.config.reload()
    harness.manager.apply_plugin_config(config["plugins"])
    # Even when .env defines the name the field declares: the loader substitutes
    # placeholders only, so the literal is what the plugin actually receives.
    harness.write_env({SECRET_VAR: SECRET_VALUE})

    form = harness.form()
    token = _field(form, "api_token")
    assert 'data-plugin-field-inline-secret="api_token"' in token
    assert "inline-literal-token" not in form, "even an inline literal is not rendered"
    assert SECRET_VALUE not in form
    assert 'data-plugin-field-source="config"' in token, (
        "the effective value comes from config.toml, not from the .env variable"
    )

    body = harness.save({"secret__api_token": "a-new-token"})
    assert "warning" in _levels(body)
    assert "is not in effect" in body
    assert SECRET_VALUE not in body and "inline-literal-token" not in body


# ═══════════════════════════════════════════════════════════════════════════
# 5. The readability pass: filters, counters, warnings, navigation
# ═══════════════════════════════════════════════════════════════════════════


def test_the_non_default_filter_hides_fields_that_are_at_their_default(harness):
    body = harness.form(only="changed")

    assert 'data-plugin-field="host"' in body, "host differs from the plugin's default"
    assert 'data-plugin-field="port"' in body
    assert 'data-plugin-field="enabled"' not in body, "enabled matches its default"
    assert 'data-plugin-field="cooldown"' not in body, "cooldown is the declared default"
    assert 'data-plugin-form-filter="changed"' in body
    assert "field_count" not in body  # the count is reported, the key name is not


def test_the_shipped_filter_hides_fields_that_match_the_shipped_file(harness):
    body = harness.form(only="shipped")

    assert 'data-plugin-field="port"' in body, "1514 differs from the shipped 514"
    assert 'data-plugin-field="format"' in body, "json differs from the shipped cef"
    assert 'data-plugin-field="host"' not in body, (
        "0.0.0.0 is exactly what the shipped config.toml says"
    )


def test_a_filter_that_hides_everything_says_so_instead_of_looking_broken(harness):
    config = harness.config()
    config["plugins"][TYPED] = {"api_token": "${" + SECRET_VAR + ":-}"}
    harness.write_config(config)
    harness.runtime.config.reload()
    harness.manager.apply_plugin_config(config["plugins"])

    body = harness.form(only="shipped")

    assert "data-plugin-form-empty" in body
    assert "No setting is shown" in body


def test_the_filter_also_narrows_the_plugin_inventory(harness):
    body = harness.panel(only="shipped")

    assert _row(body, TYPED)
    assert "data-plugin-row=" + '"' + PLAIN + '"' not in body, (
        "plain_plugin has nothing that differs from the shipped file"
    )
    assert 'data-plugin-shown="1"' in body and 'data-plugin-hidden="1"' in body
    assert "differ from the shipped config.toml defaults" in body


def test_the_settings_page_offers_both_filters_a_jump_control_and_section_counts(harness):
    body = harness.page()

    for name in ("all", "changed", "shipped"):
        assert f'data-settings-filter="{name}"' in body
        assert f"only={name}" in body or name == "all", (
            "the filter has to survive a reload, so it lives in the URL"
        )
    assert 'data-settings-jump="1"' in body
    assert '<option value="/admin/settings' in body, "the jump control is a plain link list"
    assert 'data-settings-changed=' in body, "each section header counts its changes"


def test_the_plugin_section_counts_the_values_that_differ_from_defaults(harness):
    body = harness.page()
    header = body.split('data-settings-panel="plugins"', 1)[1].split("</button>", 1)[0]

    counts = re.findall(r'data-settings-changed="(\d+)"', header)
    assert counts and int(counts[0]) > 0, "the plugins section has changed values"


def test_the_settings_page_links_to_the_advanced_config_editor(harness):
    body = harness.page()

    assert 'href="/admin/config"' in body
    assert 'data-settings-advanced-editor-link="1"' in body

    from anteumbra.interfaces.web.pages import _NAV_TITLES

    assert _NAV_TITLES.get("config") == "Config Editor", (
        "/admin/config needs a shell title, or the nav shows a guessed one"
    )


def test_the_guarded_keys_render_with_their_value_source_and_risk(harness):
    body = harness.page()

    for key in (
        "quarantine.auto_quarantine_enabled",
        "ip_blocker.auto_block_enabled",
        "web_admin.allowed_ips",
        "web_admin.session_cookie_secure",
    ):
        assert f'data-settings-dangerous="{key}"' in body
    assert "Keys that remove a protection" in body
    assert "locks you out of the web interface" in body
    assert "sends the admin session cookie over plain HTTP" in body
    assert "current:" in body and "from" in body


# ═══════════════════════════════════════════════════════════════════════════
# 6. The password flow hashes instead of storing plaintext
# ═══════════════════════════════════════════════════════════════════════════


def _post_password(harness, **data):
    response = harness.client.post(PASSWORD_URL, data=data, headers={"HX-Request": "true"})
    assert response.status_code == 200, "a refused password change must render inline"
    return html.unescape(response.get_data(as_text=True))


def test_setting_a_new_password_stores_only_a_hash(harness):
    from werkzeug.security import check_password_hash

    body = _post_password(
        harness, new_password="correct-horse-battery", confirm_password="correct-horse-battery"
    )

    env_text = harness.env_text()
    assert "correct-horse-battery" not in env_text, "the plaintext must never reach disk"
    assert "correct-horse-battery" not in body, "nor the page it re-renders"
    stored = re.search(r"ANTEUMBRA_PASSWORD_HASH=(\S+)", env_text)
    assert stored, "the hash must be written to .env"
    assert check_password_hash(stored.group(1), "correct-horse-battery")
    assert "New password hash written to .env" in body


def test_the_password_flow_reports_a_mismatch_without_writing(harness):
    body = _post_password(
        harness, new_password="correct-horse-battery", confirm_password="something-else"
    )

    assert "do not match" in body
    assert "ANTEUMBRA_PASSWORD_HASH" not in harness.env_text()


def test_a_too_short_password_is_refused_without_writing(harness):
    body = _post_password(harness, new_password="short", confirm_password="short")

    assert "Password too short" in body
    assert "ANTEUMBRA_PASSWORD_HASH" not in harness.env_text()


def test_the_page_offers_the_password_form_instead_of_editing_the_hash(harness):
    body = harness.page()

    assert 'data-settings-password="1"' in body
    assert 'name="new_password"' in body and 'name="confirm_password"' in body
    assert "/admin/settings/password/save" in body
    assert 'name="web_admin.password_hash"' not in body, (
        "the hash is never offered as editable text"
    )


# ═══════════════════════════════════════════════════════════════════════════
# 7. Nothing existing was removed, and the surface stays authenticated
# ═══════════════════════════════════════════════════════════════════════════


def test_the_environment_section_reports_credentials_without_rendering_them(harness):
    already = "wechat-send-key-must-not-leak"
    harness.write_env({"ANTEUMBRA_WECHAT_API_KEY": already, "ANTEUMBRA_EMAIL_USERNAME": "ops@x"})

    body = harness.page()

    assert already not in body, "a stored credential must not sit in the page source"
    assert 'data-env-secret-state="set"' in body
    assert "ops@x" in body, "a non-secret address stays editable"


def test_the_legacy_config_editor_does_not_print_stored_credentials(harness):
    already = "webhook-secret-must-not-leak"
    harness.write_env({"ANTEUMBRA_WEBHOOK_SECRET": already})

    body = harness.get("/admin/settings/config/editor")

    assert already not in body
    assert 'data-env-secret-state="set"' in body
    assert 'id="env-pwd-input"' in body, "the hash generator must stay"


def test_the_plugin_form_and_panel_require_authentication(harness):
    with harness.client.session_transaction() as flask_session:
        flask_session.clear()

    for url, method in ((FORM_URL, "get"), (SAVE_URL, "post"), (PANEL_URL, "get")):
        response = getattr(harness.client, method)(url)
        assert response.status_code in (301, 302, 401, 403), f"{url} answered without a session"


def _parsed_tags(body: str) -> list[str]:
    """Every start tag an HTML parser finds in the fragment."""
    from html.parser import HTMLParser

    class _Collector(HTMLParser):
        def __init__(self) -> None:
            super().__init__(convert_charrefs=True)
            self.tags: list[str] = []

        def handle_starttag(self, tag, attrs):  # noqa: ANN001 - stdlib signature
            self.tags.append(tag)

    collector = _Collector()
    collector.feed(body)
    collector.close()
    return collector.tags


def test_the_served_fragments_are_real_markup_and_not_one_comment(harness):
    """The panel and the form must parse into elements, not into a comment node.

    ``plugin_status.html`` once opened an HTML comment and closed it with Jinja's
    comment terminator.  The endpoint still served the complete fragment, so every
    string assertion in this file passed, while a browser read the whole panel as
    one unterminated comment and rendered nothing.  Only a real parse catches it,
    which is why the browser suite is the other half of this guard.
    """
    for name, body in (("panel", harness.panel()), ("form", harness.form())):
        tags = _parsed_tags(body)
        assert "div" in tags, f"the {name} fragment parsed into no elements at all"
        assert len(tags) > 3, f"the {name} fragment parsed into {len(tags)} tag(s)"
    assert "form" in _parsed_tags(harness.form())


def test_the_summary_counts_stay_over_every_plugin_under_a_filter(harness):
    """A narrowed view must not claim the deployment has fewer plugins."""
    unfiltered = harness.panel()
    filtered = harness.panel(only="shipped")

    def total(body: str) -> str:
        return re.search(r"Loaded:</span>|<strong[^>]*>\d+</strong> / (\d+)", body).group(1)

    assert total(filtered) == total(unfiltered)
