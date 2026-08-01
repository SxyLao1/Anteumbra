# -*- coding: utf-8 -*-
"""
Anteumbra Plugin Manager

插件生命周期管理：加载 → 激活 → 事件分发 → 停用。
通过 config.toml [plugins] 控制启停。

架构：
  PluginManager (每个 RuntimeContainer 独立拥有)
    ├── 内置插件 (plugins/ 目录)
    │   ├── stdout_logger    — 将事件输出到终端
    │   └── ...              — 更多内置插件
    └── 第三方插件 (pip install)
"""

import importlib
import logging
import queue
import threading
from collections.abc import Callable, Mapping
from typing import Any, Dict, List, Optional

from anteumbra.domain import Detector, DomainEvent, EventSource, Notifier, Plugin


class PluginManager:
    """Own plugin lifecycle and event dispatch for one application runtime."""

    def __init__(
        self,
        *,
        metric_recorder: Callable[[str], None] | None = None,
        plugin_factories: Mapping[str, Callable[[], Plugin]] | None = None,
        log: logging.Logger | None = None,
    ) -> None:
        self._rwlock = threading.RLock()  # Thread-safe access to all dicts
        self._plugins: Dict[str, Plugin] = {}  # name → Plugin 实例
        self._detectors: Dict[str, Detector] = {}  # name → Detector
        self._notifiers: Dict[str, Notifier] = {}  # name → Notifier
        self._event_sources: Dict[str, EventSource] = {}  # name → EventSource
        self._event_handlers: Dict[str, List[Plugin]] = {}  # event_type → [plugins]
        self._enabled: bool = False
        self._config: Dict[str, Any] = {}
        self._dispatch_timeout = 30.0  # Max seconds per plugin on_event
        self._event_queue: queue.Queue = queue.Queue(maxsize=1000)
        self._event_enqueue_timeout = 0.25
        self._max_abandoned_threads = 8
        self._worker_running: bool = False
        self._worker_thread: Optional[threading.Thread] = None
        self._abandoned_threads: List[tuple[str, threading.Thread]] = []
        self._metric_recorder = metric_recorder
        self._plugin_factories = dict(plugin_factories or {})
        self._logger = log or logging.getLogger(__name__)

    def set_plugin_factories(
        self,
        factories: Mapping[str, Callable[[], Plugin]],
    ) -> None:
        """Set built-in factories before runtime initialization."""
        if self._plugins:
            raise RuntimeError("plugin factories cannot change after registration")
        self._plugin_factories = dict(factories)

    # ── 初始化 ──────────────────────────────────────────

    def init_from_config(self, config: Dict[str, Any]) -> None:
        """从配置初始化插件系统"""
        plugin_cfg = config.get("plugins", {})
        self._enabled = plugin_cfg.get("enabled", False)
        self._config = plugin_cfg
        self._dispatch_timeout = _positive_float(
            plugin_cfg.get("dispatch_timeout_seconds", 30),
            default=30.0,
        )
        self._event_enqueue_timeout = _positive_float(
            plugin_cfg.get("event_enqueue_timeout_seconds", 0.25),
            default=0.25,
        )
        self._max_abandoned_threads = _positive_int(
            plugin_cfg.get("max_abandoned_handlers", 8),
            default=8,
        )
        queue_size = _positive_int(
            plugin_cfg.get("event_queue_size", 1000),
            default=1000,
        )
        if not self._worker_running:
            self._event_queue = queue.Queue(maxsize=queue_size)

        if not self._enabled:
            self._logger.info("PluginManager: 插件系统已关闭（设置 [plugins] enabled = true 启用）")
            return

        # 加载内置插件
        builtin_plugins = plugin_cfg.get("builtin", [])
        for name in builtin_plugins:
            self._load_builtin(name)

        self._logger.info(
            "PluginManager: 初始化完成 — %d 插件已加载 (%d detector, %d notifier, %d event_source)",
            len(self._plugins),
            len(self._detectors),
            len(self._notifiers),
            len(self._event_sources),
        )

        # Start the Fire-and-Forget event worker
        self._start_worker()

    # ── Worker Thread ──────────────────────────────────

    def _start_worker(self) -> None:
        """Start the background worker that dispatches emit()-queued events."""
        if self._worker_running:
            return
        self._worker_running = True
        self._worker_thread = threading.Thread(
            target=self._event_worker,
            name="PluginManager-EmitWorker",
            daemon=True,
        )
        self._worker_thread.start()
        self._logger.info("PluginManager: emit worker thread started")

    def _event_worker(self) -> None:
        """Background worker: consume emit queue and dispatch to handlers."""
        while self._worker_running:
            try:
                event = self._event_queue.get(timeout=1.0)
            except queue.Empty:
                continue
            try:
                if event is None:
                    break
                self.dispatch(event)
            except Exception as e:
                self._logger.error(
                    "PluginManager: emit worker dispatch error: %s", e, exc_info=True
                )
            finally:
                self._event_queue.task_done()

    # ── 注册 / 卸载 ────────────────────────────────────

    def register(self, plugin: Plugin) -> bool:
        """注册插件并激活（线程安全）"""
        if not self._enabled:
            return False
        with self._rwlock:
            name = plugin.name
            if name in self._plugins:
                self._logger.warning("PluginManager: 插件 '%s' 已注册，跳过", name)
                return False

            try:
                plugin_config = self._config.get(name, {})
                plugin.activate(plugin_config)
                self._plugins[name] = plugin

                if isinstance(plugin, Detector):
                    self._detectors[name] = plugin
                if isinstance(plugin, Notifier):
                    self._notifiers[name] = plugin
                if isinstance(plugin, EventSource):
                    self._event_sources[name] = plugin

                for event_type in plugin.supported_events:
                    self._event_handlers.setdefault(event_type, []).append(plugin)

                self._logger.info("PluginManager: 插件 '%s' v%s 已注册", name, plugin.version)
                return True
            except Exception as e:
                self._logger.error("PluginManager: 插件 '%s' 激活失败: %s", name, e)
                return False

    def unregister(self, name: str) -> bool:
        """卸载插件（线程安全）"""
        with self._rwlock:
            plugin = self._plugins.pop(name, None)
            if plugin is None:
                return False
            try:
                plugin.deactivate()
            except Exception as e:
                self._logger.error("PluginManager: 插件 '%s' 停用失败: %s", name, e)
            self._detectors.pop(name, None)
            self._notifiers.pop(name, None)
            self._event_sources.pop(name, None)
            for handlers in self._event_handlers.values():
                handlers[:] = [h for h in handlers if h.name != name]
            self._logger.info("PluginManager: 插件 '%s' 已卸载", name)
            return True

    # ── 事件分发 ────────────────────────────────────────

    def dispatch(self, event: DomainEvent) -> List[DomainEvent]:
        """分发事件到所有订阅插件（线程安全，带超时）

        v1.0.8 fix: _dispatch_timeout was declared but never applied.
        Each handler now runs in a daemon thread with join(timeout).
        If a plugin hangs or deadloops, it is skipped after the timeout.

        v1.1.0: Track abandoned threads to prevent zombie accumulation.
        """
        # Clean up previously abandoned threads
        self._reap_abandoned()
        if not self._enabled:
            return []
        new_events: List[DomainEvent] = []
        with self._rwlock:
            handlers = list(self._event_handlers.get(event.event_type, []))
        for plugin in handlers:
            if self._has_abandoned_handler(plugin.name):
                self._logger.error(
                    "PluginManager: plugin '%s' remains unhealthy; skipping event '%s'",
                    plugin.name,
                    event.event_type,
                )
                self._record_metric("plugin_handler_skipped")
                continue
            if len(self._abandoned_threads) >= self._max_abandoned_threads:
                self._logger.error(
                    "PluginManager: abandoned handler limit reached; skipping plugin '%s'",
                    plugin.name,
                )
                self._record_metric("plugin_handler_skipped")
                continue
            result_container = []
            exc_container = []

            def _call(
                pl=plugin,
                ev=event,
                results=result_container,
                errors=exc_container,
            ):
                try:
                    results.append(pl.on_event(ev))
                except Exception as e:
                    errors.append(e)

            t = threading.Thread(target=_call, daemon=True)
            t.start()
            t.join(timeout=self._dispatch_timeout)
            if t.is_alive():
                self._logger.error(
                    "PluginManager: 插件 '%s' 处理事件 '%s' 超时 (%ss)，跳过",
                    plugin.name,
                    event.event_type,
                    self._dispatch_timeout,
                )
                self._abandoned_threads.append((plugin.name, t))
                self._record_metric("plugin_handler_timeout")
                continue
            if exc_container:
                self._logger.error(
                    "PluginManager: 插件 '%s' 处理事件 '%s' 失败: %s",
                    plugin.name,
                    event.event_type,
                    exc_container[0],
                )
            elif result_container and result_container[0]:
                new_events.extend(result_container[0])
        return new_events

    def _reap_abandoned(self):
        """清理已完成的被遗弃线程（防止僵尸线程累积）"""
        self._abandoned_threads = [
            (name, thread) for name, thread in self._abandoned_threads if thread.is_alive()
        ]
        if self._abandoned_threads:
            self._logger.warning(
                "PluginManager: %d abandoned plugin threads still alive",
                len(self._abandoned_threads),
            )

    def emit(self, event_type: str, source: str, payload: Dict[str, Any]) -> None:
        """Queue an event; use bounded synchronous fallback under overload."""
        import time

        event = DomainEvent(
            event_type=event_type,
            timestamp=time.time(),
            source=source,
            payload=payload,
        )
        if not self._enabled:
            return None
        try:
            self._event_queue.put(event, timeout=self._event_enqueue_timeout)
        except queue.Full:
            self._logger.error(
                "PluginManager: event queue full; dispatching '%s' synchronously",
                event_type,
            )
            self._record_metric("plugin_queue_overflow")
            self.dispatch(event)
        return None

    def publish(
        self,
        event_type: str,
        source: str,
        payload: Mapping[str, Any],
    ) -> None:
        """Implement the runtime event-publisher port."""
        self.emit(event_type, source, dict(payload))

    def _has_abandoned_handler(self, plugin_name: str) -> bool:
        return any(name == plugin_name for name, _ in self._abandoned_threads)

    # ── 查询 ────────────────────────────────────────────

    @property
    def detectors(self) -> Dict[str, Detector]:
        with self._rwlock:
            return dict(self._detectors)

    @property
    def notifiers(self) -> Dict[str, Notifier]:
        with self._rwlock:
            return dict(self._notifiers)

    @property
    def event_sources(self) -> Dict[str, EventSource]:
        with self._rwlock:
            return dict(self._event_sources)

    @property
    def is_enabled(self) -> bool:
        return self._enabled

    def list_all(self) -> List[Dict[str, Any]]:
        """列出所有已注册插件（线程安全）"""
        with self._rwlock:
            result = []
            for name, p in self._plugins.items():
                result.append(
                    {
                        "name": name,
                        "version": p.version,
                        "type": type(p).__bases__[0].__name__ if type(p).__bases__ else "Plugin",
                        "events": p.supported_events,
                    }
                )
            return result

    def shutdown(self) -> None:
        """停用所有插件（线程安全）"""
        # Stop the emit worker thread first
        if self._worker_running:
            self._worker_running = False
            try:
                self._event_queue.put_nowait(None)
            except queue.Full:
                # The worker observes _worker_running after its current event.
                pass
            if self._worker_thread and self._worker_thread.is_alive():
                self._worker_thread.join(timeout=3.0)
            self._logger.info("PluginManager: emit worker thread stopped")

        with self._rwlock:
            names = list(self._plugins.keys())
        for name in names:
            self.unregister(name)
        self._logger.info("PluginManager: 所有插件已停用")

    # ── 内部 ────────────────────────────────────────────

    def _load_builtin(self, name: str) -> Optional[Plugin]:
        """加载内置插件（从 plugins/ 目录）"""
        try:
            factory = self._plugin_factories.get(name)
            if factory is not None:
                instance = factory()
                self.register(instance)
                return instance

            module = importlib.import_module(f"anteumbra.plugins.{name}")
            # 查找模块中第一个 Plugin 子类
            plugin_cls = None
            for attr_name in dir(module):
                attr = getattr(module, attr_name)
                if isinstance(attr, type) and issubclass(attr, Plugin) and attr is not Plugin:
                    plugin_cls = attr
                    break
            if plugin_cls is None:
                self._logger.warning("PluginManager: 内置插件 '%s' 未找到 Plugin 子类", name)
                return None
            instance = plugin_cls()
            self.register(instance)
            return instance
        except ImportError:
            self._logger.info("PluginManager: 内置插件 '%s' 未安装或不可用", name)
            return None
        except Exception as e:
            self._logger.error("PluginManager: 加载内置插件 '%s' 失败: %s", name, e)
            return None

    def _record_metric(self, name: str) -> None:
        if self._metric_recorder is None:
            return
        try:
            self._metric_recorder(name)
        except Exception:
            self._logger.debug("PluginManager: failed to record metric %s", name, exc_info=True)


def _positive_int(value: Any, *, default: int) -> int:
    try:
        return max(1, int(value))
    except (TypeError, ValueError):
        return default


def _positive_float(value: Any, *, default: float) -> float:
    try:
        return max(0.01, float(value))
    except (TypeError, ValueError):
        return default
