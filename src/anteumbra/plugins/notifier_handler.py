# -*- coding: utf-8 -*-
"""
v2.0: Notifier Handler Plugin — bridges event bus to concrete notifier module.

Subscribes to ``alert_requested`` events emitted by monitor.py and other
components. Formats the alert message using the existing ``format_alert_message()``
and dispatches it through the concrete ``Notifier`` instance.

This plugin replaces inline notifier calls that
were previously scattered across FileMonitorHandler.
"""
import logging
from collections.abc import Callable, Mapping
from typing import List, Optional, Dict, Any

from anteumbra.domain import Plugin, DomainEvent
from anteumbra.domain.service_ports import NotifierPort


class NotifierHandlerPlugin(Plugin):
    """Bridge plugin: subscribes to alert_requested and delegates to concrete Notifier."""

    def __init__(
        self,
        notifier: NotifierPort,
        formatter: Callable[[dict[str, Any]], str],
        runtime_config: Mapping[str, Any],
        *,
        log: logging.Logger,
    ) -> None:
        super().__init__()
        self._notifier = notifier
        self._formatter = formatter
        self._runtime_config = runtime_config
        self._logger = log

    @property
    def name(self) -> str:
        return "notifier_handler"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def supported_events(self) -> List[str]:
        return ["alert_requested"]

    def activate(self, config: Dict[str, Any]) -> None:
        self._logger.info("NotifierHandler: 已激活")

    def deactivate(self) -> None:
        self._logger.info("NotifierHandler: 已停用")
        shutdown = getattr(self._notifier, "shutdown", None)
        if callable(shutdown):
            shutdown()

    def on_event(self, event: DomainEvent) -> Optional[List[DomainEvent]]:
        """Handle alert_requested — format and send via concrete Notifier."""
        payload = event.payload or {}
        alert_type = payload.get("alert_type", "unknown")
        level = payload.get("level", "WARNING")
        self._logger.info(
            "NotifierHandler: received alert_requested type=%s level=%s source=%s file=%s",
            alert_type, level, event.source, payload.get("file_path", ""),
        )

        # Build context dict for format_alert_message()
        ctx = dict(payload)

        # Enrich with system status
        ctx["auto_quarantine_enabled"] = self._runtime_config.get(
            "quarantine", {}
        ).get("auto_quarantine_enabled", True)
        blocker_cfg = self._runtime_config.get("ip_blocker", {})
        ctx["auto_block_enabled"] = blocker_cfg.get("auto_block_enabled", False)
        ctx["block_device_count"] = len(blocker_cfg.get("devices", []))

        # Format message
        try:
            message = self._formatter(ctx)
        except Exception as e:
            self._logger.warning("NotifierHandler: format_alert_message 失败: %s", e)
            message = f"[Anteumbra {level}] {alert_type}"

        # Send via concrete Notifier
        self._send(message, level, payload.get("site_id"))

        return None

    # -- Internal --

    def _send(self, message: str, level: str, site_id: str | None = None) -> None:
        """Send alert through concrete Notifier instance (best-effort)."""
        try:
            self._notifier.enqueue_alert(message, level=level, site_id=site_id)
            self._logger.info("NotifierHandler: queued alert level=%s", level)
        except Exception as e:
            self._logger.warning("NotifierHandler: enqueue_alert 失败: %s", e)
