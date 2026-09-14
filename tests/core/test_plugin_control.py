# -*- coding: utf-8 -*-
"""PluginManager additions that the settings page drives.

The settings page switches a plugin off by unloading it and back on by building
a fresh instance through the same factory the runtime used at startup.  These
tests pin that contract: name resolution in both directions (dotted factory key
vs the short name the instance reports), the refusal to load anything while the
plugin system is off, refreshed config reaching a re-registered plugin, and the
inventory fields the panel reads to say whether an event source is *running*
rather than merely registered.

Factory keys deliberately point at names that are not real modules
(``waf_adapters.fake_waf``): the real adapters bind sockets in ``start()``, and
these tests are about the manager, not about an adapter's network behaviour.
"""

from __future__ import annotations

from typing import Any

import pytest

from anteumbra.application.plugin_manager import PluginManager
from anteumbra.domain.event_source import EventSource
from anteumbra.domain.plugin import DomainEvent, Plugin


class _RecordingPlugin(Plugin):
    def __init__(self, name: str, *, events: tuple[str, ...] = ("waf.event",)) -> None:
        self._name = name
        self._events = list(events)
        self.activated_with: dict[str, Any] | None = None
        self.received: list[DomainEvent] = []
        self.deactivated = False

    @property
    def name(self) -> str:
        return self._name

    @property
    def version(self) -> str:
        return "9.9.9"

    @property
    def supported_events(self) -> list[str]:
        return list(self._events)

    def activate(self, config: dict[str, Any]) -> None:
        self.activated_with = dict(config)

    def deactivate(self) -> None:
        self.deactivated = True

    def on_event(self, event: DomainEvent) -> None:
        self.received.append(event)
        return None


class _RecordingSource(_RecordingPlugin, EventSource):
    """An EventSource that reports its own run state."""

    def __init__(self, name: str, *, running: bool = True) -> None:
        super().__init__(name)
        self._running = running

    def start(self) -> None:
        self._running = True

    def stop(self) -> None:
        self._running = False

    def is_running(self) -> bool:
        return self._running


@pytest.fixture
def managers():
    """Track every manager so its emit worker never outlives the test."""
    created: list[PluginManager] = []

    def _make(plugin_config: dict[str, Any], factories: dict[str, Any] | None = None):
        manager = PluginManager()
        created.append(manager)
        if factories:
            manager.set_plugin_factories(factories)
        manager.init_from_config({"plugins": plugin_config})
        return manager

    yield _make
    for manager in created:
        manager.shutdown()


def test_load_plugin_resolves_both_key_directions(managers):
    """Factory keys are dotted, instances register short; both must work."""
    plugin = _RecordingPlugin("fake_waf")
    manager = managers(
        {"enabled": True, "builtin": []},
        {"waf_adapters.fake_waf": lambda: plugin},
    )

    assert manager.loaded_name("waf_adapters.fake_waf") is None
    assert manager.load_plugin("waf_adapters.fake_waf") is True
    assert manager.loaded_name("waf_adapters.fake_waf") == "fake_waf"
    assert [row["name"] for row in manager.list_all()] == ["fake_waf"]

    # Short name, already loaded: idempotent, not a duplicate registration.
    assert manager.load_plugin("fake_waf") is True
    assert len(manager.list_all()) == 1


def test_load_plugin_accepts_a_short_name_for_a_dotted_factory(managers):
    manager = managers(
        {"enabled": True, "builtin": []},
        {"waf_adapters.fake_waf": lambda: _RecordingPlugin("fake_waf")},
    )

    assert manager.load_plugin("fake_waf") is True
    assert manager.loaded_name("fake_waf") == "fake_waf"


def test_load_plugin_refuses_while_the_plugin_system_is_off(managers):
    manager = managers(
        {"enabled": False, "builtin": []},
        {"stdout_logger": lambda: _RecordingPlugin("stdout_logger")},
    )

    assert manager.load_plugin("stdout_logger") is False
    assert manager.list_all() == []


def test_load_plugin_reports_a_plugin_without_an_implementation(managers):
    manager = managers({"enabled": True, "builtin": []})

    assert manager.load_plugin("no_such_plugin_anywhere") is False
    assert manager.list_all() == []


def test_apply_plugin_config_reaches_a_re_registered_plugin(managers):
    """A live re-enable must activate with what is on disk now, not at startup."""
    instances: list[_RecordingPlugin] = []

    def factory() -> _RecordingPlugin:
        instance = _RecordingPlugin("fake_waf")
        instances.append(instance)
        return instance

    manager = managers(
        {"enabled": True, "builtin": ["fake_waf"], "fake_waf": {"port": 514}},
        {"fake_waf": factory},
    )
    assert [instance.activated_with for instance in instances] == [{"port": 514}]

    assert manager.unregister("fake_waf") is True
    manager.apply_plugin_config(
        {"enabled": True, "builtin": ["fake_waf"], "fake_waf": {"port": 1514}}
    )
    assert manager.load_plugin("fake_waf") is True
    assert instances[-1].activated_with == {"port": 1514}, "the fresh instance read the old config"


def test_apply_plugin_config_ignores_junk(managers):
    manager = managers(
        {"enabled": True, "builtin": []},
        {"stdout_logger": lambda: _RecordingPlugin("stdout_logger")},
    )

    manager.apply_plugin_config("not a table")  # type: ignore[arg-type]

    assert manager.load_plugin("stdout_logger") is True


def test_available_plugins_reports_run_state_and_registered_name(managers):
    source = _RecordingSource("fake_waf", running=True)
    handler = _RecordingPlugin("notifier_handler", events=("alert_requested",))
    manager = managers(
        {
            "enabled": True,
            "builtin": ["waf_adapters.fake_waf", "notifier_handler"],
            "fake_waf": {"host": "0.0.0.0"},
        },
        {
            "waf_adapters.fake_waf": lambda: source,
            "notifier_handler": lambda: handler,
        },
    )

    rows = {row["name"]: row for row in manager.available_plugins()}

    adapter = rows["waf_adapters.fake_waf"]
    assert adapter["loaded"] is True
    assert adapter["registered_name"] == "fake_waf"
    assert adapter["event_source"] is True
    assert adapter["running"] is True

    source.stop()
    stopped = {row["name"]: row for row in manager.available_plugins()}
    assert stopped["waf_adapters.fake_waf"]["running"] is False, (
        "a registered but stopped adapter must not be reported as running"
    )

    notifier = rows["notifier_handler"]
    assert notifier["event_source"] is False
    assert notifier["running"] is None, "a non-EventSource has no run state to report"


def test_unregistered_plugin_stops_receiving_events(managers):
    """What the settings page's 'disable' relies on, at the bus level."""
    handler = _RecordingPlugin("event_recorder", events=("test.event",))
    manager = managers(
        {"enabled": True, "builtin": ["event_recorder"]},
        {"event_recorder": lambda: handler},
    )

    manager.dispatch(DomainEvent("test.event", 0.0, "unit", {"n": 1}))
    assert len(handler.received) == 1

    assert manager.unregister("event_recorder") is True
    assert handler.deactivated is True

    manager.dispatch(DomainEvent("test.event", 0.0, "unit", {"n": 2}))
    assert len(handler.received) == 1, "an unloaded plugin must not keep receiving events"
