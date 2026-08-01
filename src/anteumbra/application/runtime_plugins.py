"""Construct official plugins from runtime-owned dependencies."""

from __future__ import annotations

import logging
from typing import Any, Callable

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
            )
        )
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
) -> dict[str, Callable[[], Any]]:
    """Wire official plugins without allowing them to locate runtime services."""
    from anteumbra.plugins.notifier_handler import NotifierHandlerPlugin
    from anteumbra.plugins.quarantine_handler import QuarantineHandlerPlugin
    from anteumbra.plugins.siem_handler import SIEMHandlerPlugin
    from anteumbra.plugins.stdout_logger import StdoutLoggerPlugin
    from anteumbra.plugins.threat_graph_handler import ThreatGraphHandlerPlugin

    return {
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
