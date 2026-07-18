"""Tests for core/plugin_manager.py"""
import pytest
import queue
from anteumbra.domain.plugin import Plugin, DomainEvent
from anteumbra.domain.notifier import Notifier, AlertMessage, AlertLevel
from anteumbra.application.plugin_manager import PluginManager, get_plugin_manager


class _TestPlugin(Plugin):
    """Minimal plugin for testing."""
    def __init__(self, name="test_plugin"):
        self._name = name
        self.activated = False
        self.deactivated = False
        self.events = []

    @property
    def name(self): return self._name

    @property
    def version(self): return "0.1.0"

    @property
    def supported_events(self): return ["test.event"]

    def activate(self, config): self.activated = True
    def deactivate(self): self.deactivated = True
    def on_event(self, event):
        self.events.append(event)
        return [DomainEvent("test.response", 0, self._name, {"echo": event.payload})]


class _TestNotifier(Plugin, Notifier):
    def __init__(self, name="test_notifier"):
        self._name = name
        self.sent = []

    @property
    def name(self): return self._name
    @property
    def version(self): return "0.1.0"
    @property
    def supported_events(self): return ["alert.send"]
    def activate(self, c): pass
    def deactivate(self): pass
    def on_event(self, e): return None
    def send(self, msg): self.sent.append(msg); return True


class TestPluginManager:
    def test_singleton(self):
        pm1 = get_plugin_manager()
        pm2 = get_plugin_manager()
        assert pm1 is pm2

    def test_register_and_list(self):
        pm = PluginManager()
        pm._enabled = True
        plugin = _TestPlugin("my_plugin")
        assert pm.register(plugin) is True
        plugins = pm.list_all()
        assert len(plugins) == 1
        assert plugins[0]["name"] == "my_plugin"

    def test_duplicate_register(self):
        pm = PluginManager()
        pm._enabled = True
        p1 = _TestPlugin("dup")
        assert pm.register(p1) is True
        assert pm.register(p1) is False  # Already registered

    def test_unregister(self):
        pm = PluginManager()
        pm._enabled = True
        p = _TestPlugin("temp")
        pm.register(p)
        assert pm.unregister("temp") is True
        assert pm.unregister("nonexistent") is False

    def test_dispatch_event(self):
        pm = PluginManager()
        pm._enabled = True
        p = _TestPlugin("handler")
        pm.register(p)
        event = DomainEvent("test.event", 1234567890.0, "test_source", {"msg": "hello"})
        new_events = pm.dispatch(event)
        assert len(new_events) == 1
        assert new_events[0].event_type == "test.response"

    def test_emit_convenience(self):
        """v2.0: emit() is Fire-and-Forget — returns None, events go to queue."""
        pm = PluginManager()
        pm._enabled = True
        pm.register(_TestPlugin("emitter"))
        # emit() returns None (async Fire-and-Forget)
        assert pm.emit("test.event", "unit_test", {"data": 42}) is None
        # Event should be in the queue
        assert pm._event_queue.qsize() == 1

    def test_full_event_queue_uses_synchronous_fallback(self, monkeypatch):
        pm = PluginManager()
        pm._enabled = True
        pm._event_queue = queue.Queue(maxsize=1)
        pm._event_queue.put(object())
        dispatched = []
        monkeypatch.setattr(pm, "dispatch", lambda event: dispatched.append(event))

        assert pm.emit("test.event", "unit_test", {"data": 42}) is None

        assert len(dispatched) == 1
        assert dispatched[0].event_type == "test.event"

    def test_disabled_manager(self):
        pm = PluginManager()
        pm._enabled = False
        assert pm.register(_TestPlugin("ghost")) is False
        assert pm.dispatch(DomainEvent("x", 0, "y", {})) == []

    def test_notifier_registration(self):
        pm = PluginManager()
        pm._enabled = True
        n = _TestNotifier("email")
        pm.register(n)
        assert "email" in pm.notifiers
        assert pm.notifiers["email"] is n

    def test_init_from_config_disabled(self):
        pm = PluginManager()
        pm.init_from_config({"plugins": {"enabled": False}})
        assert pm.is_enabled is False
        assert len(pm.list_all()) == 0

    def test_init_from_config_enabled(self):
        pm = PluginManager()
        # stdout_logger should load from plugins/ directory
        pm.init_from_config({
            "plugins": {
                "enabled": True,
                "builtin": ["stdout_logger"],
                "stdout_logger": {"color": False, "verbose": False}
            }
        })
        assert pm.is_enabled is True
        plugins = pm.list_all()
        assert any(p["name"] == "stdout_logger" for p in plugins)

    def test_shutdown(self):
        pm = PluginManager()
        pm._enabled = True
        pm.register(_TestPlugin("a"))
        pm.register(_TestPlugin("b"))
        pm.shutdown()
        assert len(pm.list_all()) == 0
