# -*- coding: utf-8 -*-
"""The settings plugin panel must list plugins that are *not* running, with reasons.

``PluginManager.list_all()`` only reports what is registered, so an adapter that
is installed but missing from ``[plugins] builtin``, or switched off in its own
``[plugins.<name>]`` section, stayed invisible exactly when an operator was
looking for it.  These tests drive the panel with a stub manager: the real one
would need the whole runtime, and the interesting behaviour is the mapping from
manager state to visible reasons.
"""

from __future__ import annotations

import html
import os
import re

import pytest

PANEL_URL = "/admin/settings/plugin-status"

PLUGIN_CONFIG = {
    "enabled": True,
    "builtin": ["stdout_logger", "memory_shell_probe"],
    "stdout_logger": {"color": True},
    "memory_shell_probe": {"enabled": True},
    # the shipped WAF adapter sections: present, but switched off
    "modsecurity": {"enabled": False},
    "syslog_waf": {"enabled": False},
}


def _item(name, *, loaded=False, installed=True, in_builtin=True, enabled=True, version=None,
          plugin_type=None, events=None):
    return {
        "name": name,
        "loaded": loaded,
        "installed": installed,
        "in_builtin": in_builtin,
        "enabled": enabled,
        "version": version,
        "type": plugin_type,
        "events": list(events or []),
    }


def _loaded_entry(name, version="1.0.0", plugin_type="Plugin", events=("detection.new",)):
    return {"name": name, "version": version, "type": plugin_type, "events": list(events)}


class PluginManagerStub:
    """Only the read-only surface the panel is allowed to use."""

    def __init__(self, available, loaded=(), enabled=True, event_sources=()):
        self._available = [dict(item) for item in available]
        self._loaded = [dict(item) for item in loaded]
        self._enabled = enabled
        self._event_sources = {name: object() for name in event_sources}

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


# ── Flask test client fixtures ──────────────────────────────────────────────


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
    """Build a client whose settings panel sees ``manager`` and its config."""
    from anteumbra.interfaces.web.blueprints import settings_bp as module

    def _make(manager, plugin_config=None, *, authenticated=True):
        config = {"plugins": dict(PLUGIN_CONFIG if plugin_config is None else plugin_config)}
        runtime = type(
            "Runtime",
            (),
            {"config": type("Config", (), {"get": lambda self: config})()},
        )()
        monkeypatch.setattr(module, "get_runtime", lambda: runtime)
        monkeypatch.setitem(_app.extensions, "anteumbra.plugin_manager", manager)

        client = _app.test_client()
        if authenticated:
            with client.session_transaction() as flask_session:
                flask_session["authenticated"] = True
                flask_session["username"] = "admin"
        return client

    return _make


def _panel(client, query=""):
    response = client.get(PANEL_URL + query, headers={"HX-Request": "true"})
    assert response.status_code == 200
    # Jinja escapes the quotes inside the config snippet (the browser shows them
    # back as "), so compare the document the user actually reads.
    return html.unescape(response.get_data(as_text=True))


# ── inventory ───────────────────────────────────────────────────────────────


def test_unloaded_adapter_shows_both_reasons_and_the_config_lines(make_client):
    """An installed, unlisted, switched-off adapter must be visible and explained."""
    manager = PluginManagerStub(
        available=[
            _item("stdout_logger", loaded=True, version="1.2.3", plugin_type="Plugin"),
            # the manager's own `enabled` flag is True here: it looks the dotted
            # factory name up in [plugins] and finds no section, while the
            # adapter itself reads [plugins.modsecurity]
            _item("waf_adapters.modsecurity", loaded=False, in_builtin=False, enabled=True),
        ],
        loaded=[_loaded_entry("stdout_logger", version="1.2.3")],
    )

    body = _panel(make_client(manager))

    assert "waf_adapters.modsecurity" in body
    assert "Not loaded" in body
    assert "Not in builtin" in body, "missing from [plugins] builtin must be named"
    assert "Disabled in config" in body, "the plugin's own enabled=false must be named"
    assert "This build can load it, but [plugins] builtin does not list it." in body
    assert "Installed but switched off in config.toml." in body
    # the copyable snippet must contain both edits, and stay valid TOML
    assert "builtin = [" in body
    assert '"waf_adapters.modsecurity"' in body
    assert "[plugins.modsecurity]" in body
    assert "enabled = true" in body
    # the loaded plugin keeps its row and version
    assert "v1.2.3" in body


def test_loaded_adapter_is_matched_by_its_own_declared_name(make_client):
    """Factories are keyed ``waf_adapters.x``; instances register as ``x``."""
    manager = PluginManagerStub(
        available=[_item("waf_adapters.syslog_waf", loaded=False)],
        loaded=[_loaded_entry("syslog_waf", events=("waf.event",))],
        event_sources=["syslog_waf"],
    )

    body = _panel(make_client(manager))

    assert "v1.0.0" in body
    assert "Not loaded" not in body, "a running adapter must not be reported as unloaded"
    assert "Not registered" not in body
    assert "waf.event" in body


def test_listed_and_enabled_but_not_registered_is_reported_as_such(make_client):
    """No config change explains this one: the plugin simply never registered."""
    manager = PluginManagerStub(available=[_item("memory_shell_probe", loaded=False)], loaded=[])

    body = _panel(make_client(manager))

    assert "Not registered" in body
    assert "Enabled and listed, but the plugin is not registered — check the startup log." in body
    assert "[plugins.memory_shell_probe]" not in body, "no config edit would fix this"
    assert "Not in builtin" not in body
    assert "Disabled in config" not in body


def test_plugin_without_an_implementation_is_reported(make_client):
    manager = PluginManagerStub(
        available=[_item("third_party_plugin", loaded=False, installed=False, in_builtin=True)],
        loaded=[],
    )

    body = _panel(make_client(manager))

    assert "Not installed" in body
    assert "Listed in config.toml, but this build has no implementation for it." in body


def test_disabled_plugin_system_is_named_before_the_plugin_reasons(make_client):
    manager = PluginManagerStub(
        available=[_item("stdout_logger", loaded=False)],
        loaded=[],
        enabled=False,
    )

    body = _panel(make_client(manager))

    assert "DISABLED" in body
    assert "Plugin system off" in body
    assert "The plugin system is switched off; no plugin is loaded." in body
    assert "The [plugins] section is disabled, so nothing is loaded from builtin." in body
    # the system switch is the reason, not a failed registration
    assert "Not registered" not in body
    assert "[plugins]" in body and "enabled = true" in body


def test_missing_plugin_manager_still_renders(make_client):
    body = _panel(make_client(None))

    assert "DISABLED" in body
    assert "No plugin is available in this build." in body


def test_inventory_reports_loaded_over_available(make_client):
    manager = PluginManagerStub(
        available=[
            _item("stdout_logger", loaded=True),
            _item("memory_shell_probe", loaded=False, in_builtin=False),
        ],
        loaded=[_loaded_entry("stdout_logger")],
    )

    body = _panel(make_client(manager))

    assert "Loaded:" in body
    counted = re.search(r"Loaded:.*?>(\d+)</strong>\s*/\s*(\d+)", body, re.DOTALL)
    assert counted, "the header must count loaded and available plugins"
    assert counted.groups() == ("1", "2")


def test_panel_renders_in_chinese(make_client):
    manager = PluginManagerStub(
        available=[
            _item("stdout_logger", loaded=True),
            _item("waf_adapters.modsecurity", in_builtin=False),
        ],
        loaded=[_loaded_entry("stdout_logger")],
    )

    body = _panel(make_client(manager), "?lang=zh")

    assert "已加载：" in body
    assert "未加载" in body
    assert "未列入 builtin" in body
    assert "配置已关闭" in body
    assert "在 config.toml 中添加：" in body
