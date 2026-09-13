# -*- coding: utf-8 -*-
"""EventSource plugins must actually run, and their events must go somewhere.

Registration used to record an `EventSource` and never call `start()`, so a
listed WAF adapter was loadable but inert: it polled nothing, and its events
would have reached a bus whose only consumer was the JSONL pipeline fed by a
different poller. These tests pin the fixed contract.
"""

from __future__ import annotations

from typing import Any

from anteumbra.application.plugin_manager import PluginManager
from anteumbra.domain.event_source import EventSource
from anteumbra.domain.plugin import DomainEvent, Plugin


class _CapturingHandler(Plugin):
    def __init__(self) -> None:
        self.received: list[DomainEvent] = []

    @property
    def name(self) -> str:
        return "capture"

    @property
    def supported_events(self) -> list[str]:
        return ["waf.event"]

    def activate(self, config: dict[str, Any]) -> None:
        return None

    def deactivate(self) -> None:
        return None

    def on_event(self, event: DomainEvent) -> None:
        self.received.append(event)


class _FakeSource(Plugin, EventSource):
    """Records the lifecycle calls the manager is supposed to make."""

    def __init__(self) -> None:
        self.started = 0
        self.stopped = 0
        self.callback = None
        self.activated_with: dict[str, Any] | None = None

    @property
    def name(self) -> str:
        return "fake_waf"

    @property
    def supported_events(self) -> list[str]:
        return ["waf.event"]

    def activate(self, config: dict[str, Any]) -> None:
        self.activated_with = dict(config)

    def deactivate(self) -> None:
        return None

    def on_event(self, event: DomainEvent) -> None:
        return None

    def set_callback(self, callback) -> None:
        self.callback = callback

    def start(self) -> None:
        self.started += 1

    def stop(self) -> None:
        self.stopped += 1

    def is_running(self) -> bool:
        return bool(self.started and not self.stopped)


def _manager(*, enabled: bool = True) -> PluginManager:
    manager = PluginManager()
    manager.init_from_config({"plugins": {"enabled": enabled, "builtin": []}})
    return manager


def test_registration_starts_the_source_and_wires_its_callback():
    manager = _manager()
    source = _FakeSource()

    assert manager.register(source) is True

    assert source.started == 1, "an EventSource must be started at registration"
    assert callable(source.callback), "its callback must be wired to the manager"
    assert source.activated_with == {}, "the per-plugin config slice is passed through"
    assert manager.event_sources["fake_waf"] is source


def test_source_events_reach_subscribers_and_the_sink():
    manager = _manager()
    handler = _CapturingHandler()
    manager.register(handler)
    sink_calls: list[tuple[str, dict[str, Any]]] = []
    manager.set_event_sink(lambda event_type, payload: sink_calls.append((event_type, payload)))

    source = _FakeSource()
    manager.register(source)
    source.callback({"src_ip": "203.0.113.9", "url": "/x.php", "waf_rule_id": "942100"})

    assert sink_calls, "a waf.event must be handed to the sink"
    event_type, payload = sink_calls[0]
    assert event_type == "waf.event"
    assert payload["src_ip"] == "203.0.113.9"

    manager.dispatch(
        DomainEvent(event_type="waf.event", timestamp=0.0, source="fake_waf", payload=payload)
    )
    assert handler.received and handler.received[0].event_type == "waf.event"


def test_domain_event_callback_is_normalised():
    manager = _manager()
    sink_calls: list[tuple[str, dict[str, Any]]] = []
    manager.set_event_sink(lambda event_type, payload: sink_calls.append((event_type, payload)))
    source = _FakeSource()
    manager.register(source)

    source.callback(
        DomainEvent(event_type="waf.alert", timestamp=1.0, source="syslog",
                   payload={"src_ip": "198.51.100.7"})
    )

    assert sink_calls == [("waf.alert", {"src_ip": "198.51.100.7"})]


def test_non_waf_events_are_not_written_to_the_waf_sink():
    manager = _manager()
    sink_calls: list[tuple[str, dict[str, Any]]] = []
    manager.set_event_sink(lambda event_type, payload: sink_calls.append((event_type, payload)))
    source = _FakeSource()
    manager.register(source)

    source.callback({"event_type": "metrics.tick", "value": 1})

    assert sink_calls == []


def test_broken_source_degrades_instead_of_failing_registration():
    class _BrokenSource(_FakeSource):
        def start(self) -> None:
            raise RuntimeError("adapter cannot start")

    manager = _manager()
    broken = _BrokenSource()

    assert manager.register(broken) is True, "a broken adapter must not break startup"
    assert manager.event_sources["fake_waf"] is broken


def test_unregister_stops_the_source():
    manager = _manager()
    source = _FakeSource()
    manager.register(source)

    assert manager.unregister("fake_waf") is True
    assert source.stopped == 1
    assert manager.event_sources == {}


def test_available_plugins_resolves_dotted_factory_names():
    """Factory keys are dotted, plugin names are not; the inventory must cope."""
    manager = PluginManager()
    source = _FakeSource()
    manager.set_plugin_factories({"waf_adapters.fake_waf": lambda: source})
    manager.init_from_config(
        {
            "plugins": {
                "enabled": True,
                "builtin": ["waf_adapters.fake_waf"],
                "fake_waf": {"enabled": False},
            }
        }
    )

    rows = {row["name"]: row for row in manager.available_plugins()}
    row = rows["waf_adapters.fake_waf"]

    assert row["loaded"] is True, "a running adapter registered under its short name"
    assert row["in_builtin"] is True
    assert row["enabled"] is False, "[plugins.fake_waf] enabled = false must be visible"
    assert row["events"] == ["waf.event"]
    assert source.started == 1
