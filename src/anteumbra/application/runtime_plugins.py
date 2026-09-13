"""Construct official plugins from runtime-owned dependencies."""

from __future__ import annotations

import logging
from typing import Any, Callable, Mapping

from anteumbra.domain.runtime import EventPublisherPort, RuntimeMetricsPort
from anteumbra.domain.service_ports import (
    NotifierPort,
    PluginManagerPort,
    SIEMExporterPort,
    ThreatGraphPort,
)

logger = logging.getLogger(__name__)


def _start_plugins(
    config: dict[str, Any],
    warnings: list[str],
    metrics: RuntimeMetricsPort,
    notifier: NotifierPort,
    siem_exporter: SIEMExporterPort,
    threat_graph: ThreatGraphPort,
    quarantine,
    logger_factory: Callable[[str], logging.Logger],
    *,
    alert_formatter: Callable[[dict[str, object]], str],
    memory_shell: Any | None = None,
) -> PluginManagerPort | None:
    manager = None
    try:
        from anteumbra.application.plugin_manager import PluginManager

        manager = PluginManager(
            metric_recorder=lambda name: metrics.increment(name),
            log=logger_factory("plugin_manager"),
        )
        manager.set_plugin_factories(
            _build_builtin_plugin_factories(
                config,
                manager,
                notifier,
                siem_exporter,
                threat_graph,
                quarantine,
                logger_factory,
                alert_formatter=alert_formatter,
                memory_shell=memory_shell,
            )
        )
        manager.set_event_sink(_build_waf_event_sink(config, logger_factory))
        manager.init_from_config(config)
        if manager.is_enabled:
            plugins = manager.list_all()
            names = ", ".join(plugin["name"] for plugin in plugins)
            print(f"[OK] Plugins: {len(plugins)} loaded ({names})")
        return manager
    except Exception as exc:
        logger.exception("Plugin startup failed")
        warnings.append(f"Plugin system failed: {exc}")
        if manager is not None:
            try:
                manager.shutdown()
            except Exception:
                logger.exception("Partially initialized plugin manager shutdown failed")
        return None


def _build_waf_event_sink(
    config: dict[str, Any],
    logger_factory: Callable[[str], logging.Logger],
) -> Callable[[str, Mapping[str, Any]], None]:
    """Persist adapter-produced WAF events where the threat graph reads them.

    WAF adapter plugins publish `waf.event` on the bus, but the runtime's
    threat-graph pipeline consumes WAF events from `data/waf_events.jsonl`
    (written by the runtime poller and tailed by `JsonlEventTailer`). Without
    this sink an enabled adapter would collect events that nothing ever reads.
    """
    import json
    import threading
    from pathlib import Path

    paths = config.get("paths", {}) if isinstance(config, Mapping) else {}
    data_dir = Path(str(paths.get("data_dir", "data")))  # type: ignore[arg-type]
    target = data_dir / "waf_events.jsonl"
    lock = threading.Lock()
    sink_logger = logger_factory("plugin.waf_event_sink")

    def sink(event_type: str, payload: Mapping[str, Any]) -> None:
        record = dict(payload)
        record.setdefault("event_type", event_type)
        line = json.dumps(record, ensure_ascii=False, default=str)
        with lock:
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")
        sink_logger.debug("WAF event appended: %s", event_type)

    return sink


def _build_builtin_plugin_factories(
    config: dict[str, Any],
    event_publisher: EventPublisherPort,
    notifier: NotifierPort,
    siem_exporter: SIEMExporterPort,
    threat_graph: ThreatGraphPort,
    quarantine,
    logger_factory: Callable[[str], logging.Logger],
    *,
    alert_formatter: Callable[[dict[str, object]], str],
    memory_shell: Any | None = None,
) -> dict[str, Callable[[], Any]]:
    """Wire official plugins without allowing them to locate runtime services."""
    from anteumbra.plugins.notifier_handler import NotifierHandlerPlugin
    from anteumbra.plugins.quarantine_handler import QuarantineHandlerPlugin
    from anteumbra.plugins.siem_handler import SIEMHandlerPlugin
    from anteumbra.plugins.stdout_logger import StdoutLoggerPlugin
    from anteumbra.plugins.threat_graph_handler import ThreatGraphHandlerPlugin

    factories: dict[str, Callable[[], Any]] = {
        "stdout_logger": lambda: StdoutLoggerPlugin(
            log=logger_factory("plugin.stdout_logger"),
        ),
        "notifier_handler": lambda: NotifierHandlerPlugin(
            notifier,
            alert_formatter,
            config,
            log=logger_factory("plugin.notifier_handler"),
        ),
        "quarantine_handler": lambda: QuarantineHandlerPlugin(
            quarantine_file=quarantine.quarantine_file,
            recently_restored=quarantine.is_recently_restored,
            events=event_publisher,
            runtime_config=config,
            log=logger_factory("plugin.quarantine_handler"),
        ),
        "siem_handler": lambda: SIEMHandlerPlugin(
            siem_exporter,
            log=logger_factory("plugin.siem_handler"),
        ),
        "threat_graph_handler": lambda: ThreatGraphHandlerPlugin(
            threat_graph,
            event_publisher,
            log=logger_factory("plugin.threat_graph_handler"),
        ),
    }
    if memory_shell is not None:
        from anteumbra.plugins.memory_shell_probe import MemoryShellProbePlugin

        factories["memory_shell_probe"] = lambda: MemoryShellProbePlugin(
            memory_shell,
            log=logger_factory("plugin.memory_shell_probe"),
        )
    factories.update(_build_waf_adapter_factories())
    return factories


def _build_waf_adapter_factories() -> dict[str, Callable[[], Any]]:
    """Register the loadable WAF adapters documented in ``[plugins]``.

    Each adapter reads its own settings from ``[plugins.<name>]`` through
    ``activate()``, and each builds only from the standard library, so no
    runtime service has to be injected here.
    """
    from anteumbra.plugins.waf_adapters.aws_adapter import AWSWAFAdapter
    from anteumbra.plugins.waf_adapters.cloudflare_adapter import CloudflareAdapter
    from anteumbra.plugins.waf_adapters.modsecurity_adapter import ModSecurityAdapter
    from anteumbra.plugins.waf_adapters.syslog_receiver import SyslogWAFReceiver

    return {
        "waf_adapters.modsecurity": ModSecurityAdapter,
        "waf_adapters.cloudflare": CloudflareAdapter,
        "waf_adapters.aws_waf": AWSWAFAdapter,
        "waf_adapters.syslog_waf": SyslogWAFReceiver,
    }
