# -*- coding: utf-8 -*-
"""
v2.0: Notifier Handler Plugin — bridges event bus to concrete notifier module.

Subscribes to ``alert_requested`` events emitted by monitor.py and other
components. Formats the alert message using the existing ``format_alert_message()``
and dispatches it through the concrete ``Notifier`` instance.

This plugin replaces the inline ``self.notifier._safe_notify()`` calls that
were previously scattered across FileMonitorHandler.
"""
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import List, Optional, Dict, Any

from anteumbra.domain import Plugin, DomainEvent

logger = logging.getLogger(__name__)

# v1.0.10: Ensure plugin log messages are captured to a file
if not logger.handlers:
    _log_dir = Path("logs/Anteumbra")
    _log_dir.mkdir(parents=True, exist_ok=True)
    _fh = RotatingFileHandler(
        _log_dir / "plugins.log",
        maxBytes=10 * 1024 * 1024,
        backupCount=3,
        encoding="utf-8",
    )
    _fh.setLevel(logging.DEBUG)
    _fh.setFormatter(logging.Formatter('[%(asctime)s] %(levelname)s - [%(name)s] %(message)s'))
    logger.addHandler(_fh)
    logger.setLevel(logging.DEBUG)
    logger.propagate = False


class NotifierHandlerPlugin(Plugin):
    """Bridge plugin: subscribes to alert_requested and delegates to concrete Notifier."""

    def __init__(self):
        super().__init__()
        self._notifier = None
        self._logger = None

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
        # Lazy-init notifier on first alert to avoid config dependency at import time
        logger.info("NotifierHandler: 已激活")
        self._logger = logger

    def deactivate(self) -> None:
        logger.info("NotifierHandler: 已停用")
        self._notifier = None

    def on_event(self, event: DomainEvent) -> Optional[List[DomainEvent]]:
        """Handle alert_requested — format and send via concrete Notifier."""
        payload = event.payload or {}
        alert_type = payload.get("alert_type", "unknown")
        level = payload.get("level", "WARNING")
        logger.info(
            "NotifierHandler: received alert_requested type=%s level=%s source=%s file=%s",
            alert_type, level, event.source, payload.get("file_path", ""),
        )

        # Build context dict for format_alert_message()
        ctx = dict(payload)

        # Enrich with system status
        try:
            from anteumbra.infrastructure.config.registry import ConfigRegistry
            cfg = ConfigRegistry.get_raw_config()
            ctx["auto_quarantine_enabled"] = cfg.get("quarantine", {}).get("auto_quarantine_enabled", True)
            blocker_cfg = cfg.get("ip_blocker", {})
            ctx["auto_block_enabled"] = blocker_cfg.get("auto_block_enabled", False)
            ctx["block_device_count"] = len(blocker_cfg.get("devices", []))
        except Exception:
            pass

        # Format message
        try:
            from anteumbra.infrastructure.monitoring.notifier import format_alert_message
            message = format_alert_message(ctx)
        except Exception as e:
            logger.warning("NotifierHandler: format_alert_message 失败: %s", e)
            message = f"[Anteumbra {level}] {alert_type}"

        # Send via concrete Notifier
        self._send(message, level)

        return None

    # -- Internal --

    def _send(self, message: str, level: str) -> None:
        """Send alert through concrete Notifier instance (best-effort)."""
        try:
            if self._notifier is None:
                from anteumbra.infrastructure.monitoring.notifier import get_notifier
                self._notifier = get_notifier(self._logger or logging.getLogger("monitor.notifier"))
            self._notifier._safe_notify(message, level=level)
            logger.info("NotifierHandler: queued alert level=%s", level)
        except Exception as e:
            logger.warning("NotifierHandler: _safe_notify 失败: %s", e)
