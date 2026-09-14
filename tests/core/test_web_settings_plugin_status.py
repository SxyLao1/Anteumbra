# -*- coding: utf-8 -*-
"""The plugin panel's effective status: one state per row, and no false comfort.

``available_plugins()`` answers "what could be loaded"; the operator's question
is "is this plugin actually installed and working".  These tests drive the panel
with a stub manager and assert the status matrix row by row - loaded and
running, registered but inert, switched off in config, missing from builtin,
missing from the build, never registered, and the plugin system itself off - plus
the one rule that matters most: an ``enabled`` value is never printed for a
plugin that is not loaded.
"""

from __future__ import annotations

import html
import os

import pytest

PANEL_URL = "/admin/settings/plugin-status"

NO_RUN_PROBE = object()

PLUGIN_CONFIG = {
    "enabled": True,
    "builtin": ["notifier_handler", "memory_shell_probe", "waf_adapters.syslog_waf"],
    "memory_shell_probe": {"enabled": True},
    "modsecurity": {"enabled": False},
    "syslog_waf": {"enabled": True},
}


class _Source:
    """Minimal EventSource surface; NO_RUN_PROBE hides ``is_running``."""

    def __init__(self, running=True):
        self._running = running

    def is_running(self):
        if self._running is NO_RUN_PROBE:
            raise AttributeError("is_running")
        return self._running


def _item(name, *, loaded=False, installed=True, in_builtin=True, enabled=True,
          registered_name=None, event_source=False, running=None):
    return {
        "name": name,
        "loaded": loaded,
        "installed": installed,
        "in_builtin": in_builtin,
        "enabled": enabled,
        "version": "1.2.3" if loaded else None,
        "type": "Plugin" if loaded else None,
        "events": ["waf.event"] if loaded else [],
        "registered_name": registered_name,
        "event_source": event_source,
        "running": running,
    }


class PluginManagerStub:
    def __init__(self, available, loaded=(), *, enabled=True, event_sources=None):
        self._available = [dict(item) for item in available]
        self._loaded = list(loaded)
        self._enabled = enabled
        self._event_sources = dict(event_sources or {})

    @property
    def is_enabled(self):
        return self._enabled

    def list_all(self):
        return [dict(item) for item in self._loaded]

    def available_plugins(self):
        return [dict(item) for item in self._available]

    @property
    def detectors(self):
        return {}

    @property
    def notifiers(self):
        return {}

    @property
    def event_sources(self):
        return dict(self._event_sources)


def _loaded_entry(name, version="1.2.3", plugin_type="Plugin", events=("waf.event",)):
    return {"name": name, "version": version, "type": plugin_type, "events": list(events)}


@pytest.fixture(scope="module")
def _app():
    os.environ.setdefault("ANTEUMBRA_TOOL_MODE", "true")

    from anteumbra.interfaces.web.factory import create_app

    app = create_app()
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False
    return app


@pytest.fixture
def make_client(monkeypatch, _app):
    from anteumbra.interfaces.web.blueprints import settings_bp as module

    def _make(manager, plugin_config=None):
        config = {"plugins": dict(PLUGIN_CONFIG if plugin_config is None else plugin_config)}
        runtime = type(
            "Runtime",
            (),
            {"config": type("Config", (), {"get": lambda self: config})()},
        )()
        monkeypatch.setattr(module, "get_runtime", lambda: runtime)
        monkeypatch.setitem(_app.extensions, "anteumbra.plugin_manager", manager)

        client = _app.test_client()
        with client.session_transaction() as flask_session:
            flask_session["authenticated"] = True
            flask_session["username"] = "admin"
        return client

    return _make


def _panel(client):
    response = client.get(PANEL_URL, headers={"HX-Request": "true"})
    assert response.status_code == 200
    return html.unescape(response.get_data(as_text=True))


def _row(body: str, name: str) -> str:
    start = body.index(f'data-plugin-row="{name}"')
    end = body.find("data-plugin-row=", start + 1)
    return body[start : end if end != -1 else len(body)]


def _config_line(body: str, name: str) -> str:
    """The one element that states a plugin's effective config, not the snippet."""
    row = _row(body, name)
    start = row.index('data-plugin-config="1"')
    end = row.index("</div>", start)
    return row[start:end]


def _state(body: str, name: str) -> str:
    return _row(body, name).split('data-plugin-state="', 1)[1].split('"', 1)[0]


# ── the matrix ─────────────────────────────────────────────────────────────


def test_loaded_plugin_reports_active_and_its_enabled_value(make_client):
    manager = PluginManagerStub(
        available=[_item("notifier_handler", loaded=True)],
        loaded=[_loaded_entry("notifier_handler")],
    )

    body = _panel(make_client(manager))
    row = _row(body, "notifier_handler")

    assert 'data-plugin-state="active"' in row
    assert ">Loaded<" in row
    assert "plugins.notifier_handler" in row, "the effective config section must be visible"
    assert "enabled = true" in _config_line(body, "notifier_handler")
    assert "not set explicitly" in _config_line(body, "notifier_handler")
    assert "Not loaded" not in row
    assert "Not registered" not in row


def test_loaded_event_source_reports_that_it_is_running(make_client):
    manager = PluginManagerStub(
        available=[
            _item(
                "waf_adapters.syslog_waf",
                loaded=True,
                registered_name="syslog_waf",
                event_source=True,
                running=True,
            )
        ],
        loaded=[_loaded_entry("syslog_waf")],
        event_sources={"syslog_waf": _Source(running=True)},
    )

    row = _row(_panel(make_client(manager)), "waf_adapters.syslog_waf")

    assert 'data-plugin-state="active"' in row
    assert ">Running<" in row, "an EventSource must report that it is actually running"


def test_registered_but_stopped_event_source_is_not_reported_as_active(make_client):
    manager = PluginManagerStub(
        available=[
            _item(
                "waf_adapters.syslog_waf",
                loaded=True,
                registered_name="syslog_waf",
                event_source=True,
                running=False,
            )
        ],
        loaded=[_loaded_entry("syslog_waf")],
        event_sources={"syslog_waf": _Source(running=False)},
    )

    body = _panel(make_client(manager))
    row = _row(body, "waf_adapters.syslog_waf")

    assert 'data-plugin-state="inactive"' in row
    assert ">Not running<" in row
    assert ">Running<" not in row


def test_event_source_without_a_run_probe_says_unknown(make_client):
    """Claiming a state that was never observed is exactly what this panel must not do."""
    manager = PluginManagerStub(
        available=[_item("waf_adapters.syslog_waf", loaded=True, registered_name="syslog_waf")],
        loaded=[_loaded_entry("syslog_waf")],
        event_sources={"syslog_waf": _Source(running=NO_RUN_PROBE)},
    )

    row = _row(_panel(make_client(manager)), "waf_adapters.syslog_waf")

    assert 'data-plugin-state="unverified"' in row
    assert "Run state unknown" in row


def test_switched_off_in_its_own_section_is_reported_as_disabled(make_client):
    manager = PluginManagerStub(
        available=[_item("modsecurity", loaded=False)],
        loaded=[],
    )

    body = _panel(make_client(manager))
    row = _row(body, "modsecurity")

    assert 'data-plugin-state="disabled"' in row
    assert "Disabled in config" in row
    assert "Installed but switched off in config.toml." in row
    assert "plugins.modsecurity" in row
    assert "enabled = " not in _config_line(body, "modsecurity"), (
        "a plugin that is not loaded has no enabled state to show"
    )
    assert "enabled is not reported" in _config_line(body, "modsecurity")


def test_missing_from_builtin_is_reported_as_not_listed(make_client):
    manager = PluginManagerStub(
        available=[_item("waf_adapters.modsecurity", loaded=False, in_builtin=False)],
        loaded=[],
    )

    row = _row(_panel(make_client(manager)), "waf_adapters.modsecurity")

    assert 'data-plugin-state="not_listed"' in row
    assert "Not in builtin" in row
    assert "Not loaded" in row


def test_missing_implementation_is_reported_and_offers_no_controls(make_client):
    manager = PluginManagerStub(
        available=[_item("third_party_plugin", loaded=False, installed=False)],
        loaded=[],
    )

    row = _row(_panel(make_client(manager)), "third_party_plugin")

    assert 'data-plugin-state="not_installed"' in row
    assert "Not installed" in row
    assert "Listed in config.toml, but this build has no implementation for it." in row
    assert "hx-post" not in row, "a plugin without an implementation cannot be switched"


def test_enabled_and_listed_but_never_registered_is_reported(make_client):
    manager = PluginManagerStub(
        available=[_item("memory_shell_probe", loaded=False)],
        loaded=[],
    )

    row = _row(_panel(make_client(manager)), "memory_shell_probe")

    assert 'data-plugin-state="not_registered"' in row
    assert "Not registered" in row
    assert "[plugins.memory_shell_probe]" not in row, "no config edit would fix this"


def test_plugin_system_off_outranks_the_per_plugin_reasons(make_client):
    manager = PluginManagerStub(
        available=[_item("memory_shell_probe", loaded=False)],
        loaded=[],
        enabled=False,
    )

    body = _panel(make_client(manager))

    assert 'data-plugin-state="system_off"' in _row(body, "memory_shell_probe")
    assert "Not registered" not in body
    assert "DISABLED" in body


# ── the enabled rule ───────────────────────────────────────────────────────


def test_loaded_but_configured_off_is_shown_honestly(make_client):
    """A registered plugin whose own section says enabled=false is inert, and says so."""
    manager = PluginManagerStub(
        available=[_item("modsecurity", loaded=True)],
        loaded=[_loaded_entry("modsecurity")],
    )

    body = _panel(make_client(manager))

    assert "enabled = false" in _config_line(body, "modsecurity")
    assert "not set explicitly" not in _config_line(body, "modsecurity")


def test_no_unloaded_row_claims_an_enabled_state(make_client):
    manager = PluginManagerStub(
        available=[
            _item("modsecurity", loaded=False),
            _item("waf_adapters.modsecurity", loaded=False, in_builtin=False),
            _item("third_party_plugin", loaded=False, installed=False),
            _item("memory_shell_probe", loaded=False),
        ],
        loaded=[],
    )

    body = _panel(make_client(manager))

    for name in ("modsecurity", "waf_adapters.modsecurity", "third_party_plugin",
                 "memory_shell_probe"):
        line = _config_line(body, name)
        assert "enabled = " not in line, f"{name} is not loaded but claims an enabled value"
        assert "enabled is not reported" in line


# ── controls ───────────────────────────────────────────────────────────────


def test_controls_offer_the_opposite_state_for_an_installed_plugin(make_client):
    manager = PluginManagerStub(
        available=[_item("quarantine_handler", loaded=True)],
        loaded=[_loaded_entry("quarantine_handler")],
    )

    row = _row(_panel(make_client(manager)), "quarantine_handler")

    assert '"action": "disable"' in row, "a switched-on plugin offers 关闭"
    assert '"action": "builtin_remove"' in row, "a listed plugin offers 移出 builtin"
    assert '"action": "enable"' not in row


def test_a_switched_off_plugin_offers_enabling(make_client):
    manager = PluginManagerStub(
        available=[_item("modsecurity", loaded=False)],
        loaded=[],
    )

    row = _row(_panel(make_client(manager)), "modsecurity")

    assert '"action": "enable"' in row, "a switched-off plugin offers 开启"
    assert '"action": "disable"' not in row


def test_control_buttons_target_the_panel_and_post_to_the_control_endpoint(make_client):
    manager = PluginManagerStub(
        available=[_item("modsecurity", loaded=True)],
        loaded=[_loaded_entry("modsecurity")],
    )

    row = _row(_panel(make_client(manager)), "modsecurity")

    assert 'hx-post="/admin/settings/plugins/control"' in row
    assert 'hx-target="#settings-plugins"' in row


def test_focus_row_is_marked_after_a_change(make_client):
    manager = PluginManagerStub(
        available=[_item("modsecurity", loaded=True)],
        loaded=[_loaded_entry("modsecurity")],
    )
    client = make_client(manager)

    body = html.unescape(
        client.post(
            "/admin/settings/plugins/control",
            data={"plugin": "modsecurity", "action": "explode"},
            headers={"HX-Request": "true"},
        ).get_data(as_text=True)
    )

    assert 'data-plugin-focus="1"' in _row(body, "modsecurity")
    assert 'data-plugin-notice="error"' in body
