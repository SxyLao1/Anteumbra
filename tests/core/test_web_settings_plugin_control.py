# -*- coding: utf-8 -*-
"""The plugin panel's controls: enable/disable and [plugins] builtin membership.

Every mutation must go through the same config path the CLI uses (load, set a
dotted key, write, validate), keep a timestamped backup, and then apply the
change to the running runtime - or say plainly that a restart is required.  The
tests drive the real endpoint against a throwaway config.toml and a real
PluginManager, because the interesting behaviour is exactly the interaction
between the file and the live plugin set.
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

CONTROL_URL = "/admin/settings/plugins/control"
PANEL_URL = "/admin/settings/plugin-status"

BASE_CONFIG: dict[str, Any] = {
    "website": {
        "name": "alpha",
        "path": ".",
        "port": 8080,
        "log_config": {"log_monitor_enabled": False},
    },
    "web_admin": {
        "port": 11111,
        "allowed_ips": ["127.0.0.1"],
        "password_hash": "scrypt:32768:8:1$test",
    },
    "plugins": {
        "enabled": True,
        "builtin": ["notifier_handler", "waf_adapters.fake_waf", "event_recorder"],
        "fake_waf": {"enabled": True},
    },
}


class _RecordingPlugin(Plugin):
    def __init__(self, name: str, *, events: tuple[str, ...] = ()) -> None:
        self._name = name
        self._events = list(events)
        self.received: list[DomainEvent] = []
        self.activated_with: list[dict[str, Any]] = []
        self.deactivated = 0

    @property
    def name(self) -> str:
        return self._name

    @property
    def version(self) -> str:
        return "4.5.6"

    @property
    def supported_events(self) -> list[str]:
        return list(self._events)

    def activate(self, config: dict[str, Any]) -> None:
        self.activated_with.append(dict(config))

    def deactivate(self) -> None:
        self.deactivated += 1

    def on_event(self, event: DomainEvent) -> None:
        self.received.append(event)
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
    def __init__(self, manager, runtime, client, tmp_path, built) -> None:
        self.manager = manager
        self.runtime = runtime
        self.client = client
        self.tmp_path = tmp_path
        self.built: dict[str, list[_RecordingPlugin]] = built

    @property
    def config_path(self):
        return self.tmp_path / "config.toml"

    def config(self) -> dict[str, Any]:
        with open(self.config_path, "rb") as handle:
            return tomllib.load(handle)

    def write_config(self, data: dict[str, Any]) -> None:
        self.config_path.write_text(tomli_w.dumps(data), encoding="utf-8")

    def loaded_names(self) -> list[str]:
        return sorted(row["name"] for row in self.manager.list_all())

    def latest(self, plugin_name: str) -> _RecordingPlugin:
        return self.built[plugin_name][-1]

    def post(self, plugin: str, action: str):
        response = self.client.post(
            CONTROL_URL,
            data={"plugin": plugin, "action": action},
            headers={"HX-Request": "true"},
        )
        assert response.status_code == 200, (
            "a refused or failed plugin change must render inline, not fail the request: "
            f"HTTP {response.status_code}"
        )
        return html.unescape(response.get_data(as_text=True))

    def panel(self) -> str:
        response = self.client.get(PANEL_URL, headers={"HX-Request": "true"})
        assert response.status_code == 200
        return html.unescape(response.get_data(as_text=True))


def _build_harness(tmp_path, monkeypatch, app) -> Harness:
    from anteumbra.interfaces.web.blueprints import settings_bp as module

    config_path = tmp_path / "config.toml"
    config_path.write_text(tomli_w.dumps(BASE_CONFIG), encoding="utf-8")
    runtime = _Runtime(_Config(config_path))

    built: dict[str, list[_RecordingPlugin]] = {}

    def factory(name: str, events: tuple[str, ...] = ()):
        def _make() -> _RecordingPlugin:
            plugin = _RecordingPlugin(name, events=events)
            built.setdefault(name, []).append(plugin)
            return plugin

        return _make

    manager = PluginManager()
    manager.set_plugin_factories(
        {
            "notifier_handler": factory("notifier_handler", ("alert_requested",)),
            "waf_adapters.fake_waf": factory("fake_waf", ("waf.event",)),
            "event_recorder": factory("event_recorder", ("test.event",)),
        }
    )
    manager.init_from_config(runtime.config.get())

    monkeypatch.setattr(module, "get_runtime", lambda: runtime)
    monkeypatch.setitem(app.extensions, "anteumbra.plugin_manager", manager)

    client = app.test_client()
    with client.session_transaction() as flask_session:
        flask_session["authenticated"] = True
        flask_session["username"] = "admin"
    return Harness(manager, runtime, client, tmp_path, built)


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
    """A settings panel whose runtime reads a throwaway config.toml."""
    created = _build_harness(tmp_path, monkeypatch, _app)
    yield created
    created.manager.shutdown()


def _notices(body: str) -> list[tuple[str, str]]:
    return re.findall(r'data-plugin-notice="(\w+)"[^>]*>(.*?)</div>', body, re.DOTALL)


def _assert_applied(levels: list[str], body: str, action: str) -> None:
    assert levels[0] == "success", f"{action} reported {levels} instead of success: {body}"
    assert "error" not in levels and "warning" not in levels


def _row(body: str, name: str) -> str:
    start = body.index(f'data-plugin-row="{name}"')
    end = body.find("data-plugin-row=", start + 1)
    return body[start : end if end != -1 else len(body)]


# ── disable ────────────────────────────────────────────────────────────────


def test_disable_writes_config_unloads_live_and_returns_the_row(harness):
    assert "fake_waf" in harness.loaded_names()

    body = harness.post("waf_adapters.fake_waf", "disable")

    assert harness.config()["plugins"]["fake_waf"]["enabled"] is False
    assert "fake_waf" not in harness.loaded_names(), "the running runtime must reflect the change"
    _assert_applied([level for level, _ in _notices(body)], body, "disable")
    assert "Switched off waf_adapters.fake_waf" in body
    row = _row(body, "waf_adapters.fake_waf")
    assert 'data-plugin-state="disabled"' in row
    assert 'data-plugin-loaded="false"' in row
    assert ".bak" in body, "the backup must be named for the operator"


def test_disable_keeps_a_timestamped_backup_of_the_previous_config(harness):
    before = harness.config_path.read_text(encoding="utf-8")

    harness.post("waf_adapters.fake_waf", "disable")

    backups = sorted(harness.tmp_path.glob("config.toml.*.bak"))
    assert len(backups) == 1, "exactly one backup per mutation"
    assert re.fullmatch(r"config\.toml\.\d{8}-\d{6}(-\d+)?\.bak", backups[0].name)
    assert backups[0].read_text(encoding="utf-8") == before


def test_disable_twice_keeps_a_backup_per_write(harness):
    harness.post("waf_adapters.fake_waf", "disable")
    harness.post("waf_adapters.fake_waf", "disable")

    backups = sorted(harness.tmp_path.glob("config.toml.*.bak"))
    assert len(backups) == 2, "same-second writes must not overwrite each other's backup"


def test_disabled_plugin_stops_receiving_events(harness):
    """The user-visible promise of the switch: no more events reach the plugin."""
    recorder = harness.latest("event_recorder")
    assert "event_recorder" in harness.loaded_names()

    harness.manager.dispatch(DomainEvent("test.event", 0.0, "unit", {"n": 1}))
    assert len(recorder.received) == 1

    harness.post("event_recorder", "disable")

    harness.manager.dispatch(DomainEvent("test.event", 0.0, "unit", {"n": 2}))
    assert len(recorder.received) == 1, "a switched-off plugin must stop receiving events"
    assert recorder.deactivated == 1, "the plugin must be deactivated, not just de-listed"
    assert harness.config()["plugins"]["event_recorder"]["enabled"] is False


# ── enable ─────────────────────────────────────────────────────────────────


def test_enable_writes_config_and_registers_in_the_running_runtime(harness):
    harness.post("waf_adapters.fake_waf", "disable")
    assert "fake_waf" not in harness.loaded_names()

    body = harness.post("waf_adapters.fake_waf", "enable")

    assert harness.config()["plugins"]["fake_waf"]["enabled"] is True
    assert "fake_waf" in harness.loaded_names(), "enable must re-register through the factory"
    _assert_applied([level for level, _ in _notices(body)], body, "enable")
    assert "Switched on waf_adapters.fake_waf" in body
    row = _row(body, "waf_adapters.fake_waf")
    assert 'data-plugin-state="active"' in row
    assert 'data-plugin-loaded="true"' in row


def test_enable_re_registers_with_the_config_now_on_disk(harness):
    harness.post("waf_adapters.fake_waf", "disable")
    config = harness.config()
    config["plugins"]["fake_waf"] = {"enabled": False, "host": "0.0.0.0", "port": 1514}
    harness.write_config(config)
    harness.runtime.config.reload()
    harness.manager.apply_plugin_config(config["plugins"])

    harness.post("waf_adapters.fake_waf", "enable")

    re_registered = harness.latest("fake_waf")
    assert re_registered.activated_with[-1] == {
        "enabled": True,
        "host": "0.0.0.0",
        "port": 1514,
    }, "the fresh instance must activate with the values on disk now"


# ── builtin membership ─────────────────────────────────────────────────────


def test_builtin_add_writes_the_list_and_loads_the_plugin(harness):
    config = harness.config()
    config["plugins"]["builtin"] = ["notifier_handler", "event_recorder"]
    harness.write_config(config)
    harness.runtime.config.reload()
    harness.manager.apply_plugin_config(config["plugins"])
    harness.manager.unregister("fake_waf")
    assert "fake_waf" not in harness.loaded_names()

    body = harness.post("waf_adapters.fake_waf", "builtin_add")

    builtin = harness.config()["plugins"]["builtin"]
    assert builtin == ["notifier_handler", "event_recorder", "waf_adapters.fake_waf"]
    assert "fake_waf" in harness.loaded_names()
    assert "Added waf_adapters.fake_waf to [plugins] builtin" in body


def test_builtin_remove_writes_the_list_and_unloads_the_plugin(harness):
    body = harness.post("waf_adapters.fake_waf", "builtin_remove")

    builtin = harness.config()["plugins"]["builtin"]
    assert "waf_adapters.fake_waf" not in builtin
    assert "notifier_handler" in builtin, "the rest of the list must survive"
    assert "fake_waf" not in harness.loaded_names()
    assert "Removed waf_adapters.fake_waf from [plugins] builtin" in body


def test_removing_from_builtin_reports_that_a_restart_will_not_load_it(harness):
    body = harness.post("waf_adapters.fake_waf", "builtin_remove")

    assert "no longer listed in [plugins] builtin" in body
    assert "a restart will not load it" in body


def test_switching_off_a_listed_plugin_warns_that_builtin_still_loads_it(harness):
    """Only the builtin list is re-read at startup, so say so instead of implying finality."""
    body = harness.post("waf_adapters.fake_waf", "disable")

    assert "still listed in [plugins] builtin" in body


# ── guard rails ────────────────────────────────────────────────────────────


def test_refuses_to_disable_the_plugin_that_delivers_alerts(harness):
    assert "notifier_handler" in harness.loaded_names()

    body = harness.post("notifier_handler", "disable")

    assert [level for level, _ in _notices(body)] == ["error"]
    assert "Refused" in body
    assert "silently drop every alert" in body
    assert "notifier_handler" in harness.loaded_names(), "the guard rail must not unload it"
    assert "enabled" not in harness.config()["plugins"].get("notifier_handler", {})


def test_refuses_to_remove_the_alert_delivery_plugin_from_builtin(harness):
    body = harness.post("notifier_handler", "builtin_remove")

    assert [level for level, _ in _notices(body)] == ["error"]
    assert "Refused" in body
    assert "notifier_handler" in harness.config()["plugins"]["builtin"]


def test_guarded_plugin_renders_its_controls_disabled_with_the_reason(harness):
    row = _row(harness.panel(), "notifier_handler")

    assert "disabled title=" in row
    assert "Protected:" in row
    assert "silently drop every alert" in row


# ── refusals and failures stay inline ──────────────────────────────────────


def test_enable_refuses_a_plugin_this_build_cannot_load(harness):
    config = harness.config()
    config["plugins"]["builtin"] = [*config["plugins"]["builtin"], "third_party_plugin"]
    harness.write_config(config)
    harness.runtime.config.reload()

    body = harness.post("third_party_plugin", "enable")

    assert [level for level, _ in _notices(body)] == ["error"]
    assert "this build has no implementation" in body
    assert "third_party_plugin" not in harness.config()["plugins"], "nothing may be written for it"


def test_unknown_plugin_renders_an_inline_error(harness):
    body = harness.post("does_not_exist", "disable")

    assert [level for level, _ in _notices(body)] == ["error"]
    assert "Unknown plugin: does_not_exist" in body


def test_unsupported_action_renders_an_inline_error(harness):
    body = harness.post("waf_adapters.fake_waf", "explode")

    assert [level for level, _ in _notices(body)] == ["error"]
    assert "Unsupported plugin action: explode" in body
    assert harness.config()["plugins"]["fake_waf"]["enabled"] is True


def test_an_unreadable_config_reports_inline_instead_of_crashing(harness):
    harness.config_path.write_text("[plugins\nbroken = ", encoding="utf-8")

    body = harness.post("waf_adapters.fake_waf", "disable")

    assert [level for level, _ in _notices(body)] == ["error"]
    assert "Config write failed" in body
    assert harness.config_path.read_text(encoding="utf-8") == "[plugins\nbroken = "
    assert "fake_waf" in harness.loaded_names(), "a failed write must not touch the runtime"


def test_a_plugin_system_that_is_off_says_a_restart_is_required(harness):
    harness.manager.shutdown()
    harness.manager._enabled = False

    body = harness.post("waf_adapters.fake_waf", "enable")

    assert harness.config()["plugins"]["fake_waf"]["enabled"] is True, "the config is still written"
    levels = [level for level, _ in _notices(body)]
    assert levels[0] == "warning"
    assert "A restart is required." in body
    assert harness.loaded_names() == [], "nothing may be registered while the system is off"


def test_control_requires_authentication(harness):
    with harness.client.session_transaction() as flask_session:
        flask_session.clear()

    response = harness.client.post(
        CONTROL_URL, data={"plugin": "waf_adapters.fake_waf", "action": "disable"}
    )

    assert response.status_code in (301, 302, 401, 403)
    assert harness.config()["plugins"]["fake_waf"]["enabled"] is True
    assert "fake_waf" in harness.loaded_names()


# ── CSRF: the header the shell's htmx helper sends ─────────────────────────


@pytest.fixture(scope="module")
def _csrf_app():
    os.environ.setdefault("ANTEUMBRA_TOOL_MODE", "true")

    from anteumbra.interfaces.web.factory import create_app

    app = create_app()
    app.config["TESTING"] = True
    return app


def test_control_takes_the_csrf_header_the_front_end_sends(
    monkeypatch, _csrf_app, tmp_path
):
    harness = _build_harness(tmp_path, monkeypatch, _csrf_app)
    try:
        shell = harness.client.get(
            "/admin/settings", headers={"Sec-Fetch-Dest": "document"}
        ).get_data(as_text=True)
        token = re.search(r'name="csrf-token" content="([^"]+)"', shell)
        assert token, "the shell rendered without a CSRF token"

        response = harness.client.post(
            CONTROL_URL,
            data={"plugin": "waf_adapters.fake_waf", "action": "disable"},
            headers={"HX-Request": "true", "X-CSRFToken": token.group(1)},
        )

        assert response.status_code == 200
        assert harness.config()["plugins"]["fake_waf"]["enabled"] is False
    finally:
        harness.manager.shutdown()


def test_control_without_a_csrf_token_is_rejected(monkeypatch, _csrf_app, tmp_path):
    harness = _build_harness(tmp_path, monkeypatch, _csrf_app)
    try:
        response = harness.client.post(
            CONTROL_URL,
            data={"plugin": "waf_adapters.fake_waf", "action": "disable"},
            headers={"HX-Request": "true"},
        )

        assert response.status_code == 400
        assert harness.config()["plugins"]["fake_waf"]["enabled"] is True
        assert "fake_waf" in harness.loaded_names()
    finally:
        harness.manager.shutdown()
