# -*- coding: utf-8 -*-
"""
v2.0: Quarantine Handler Plugin — bridges event bus to concrete quarantine module.

Subscribes to ``file_quarantined`` events emitted by monitor.py.
Calls the existing ``quarantine_file()`` function and handles all
post-quarantine bookkeeping:
  - mark_quarantined() in registry
  - emit alert_requested for success/failure/skip notifications
  - batch notification aggregation

This plugin replaces the inline quarantine logic that was previously
embedded in FileMonitorHandler._do_scan().
"""
import logging
import time
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


class QuarantineHandlerPlugin(Plugin):
    """Bridge plugin: subscribes to file_quarantined and delegates to concrete quarantine."""

    # -- Batch notification state (moved from FileMonitorHandler) --
    _batch_queued: int = 0
    _batch_threshold: int = 50
    _batch_last_flush: float = 0.0

    @property
    def name(self) -> str:
        return "quarantine_handler"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def supported_events(self) -> List[str]:
        return ["file_quarantined"]

    def activate(self, config: Dict[str, Any]) -> None:
        self._batch_queued = 0
        self._batch_threshold = config.get("batch_threshold", 50)
        self._batch_last_flush = time.time()
        logger.info("QuarantineHandler: 已激活 (batch_threshold=%d)", self._batch_threshold)

    def deactivate(self) -> None:
        # Flush any pending batch notifications on shutdown
        self._flush_batch()
        logger.info("QuarantineHandler: 已停用")

    def on_event(self, event: DomainEvent) -> Optional[List[DomainEvent]]:
        """Handle file_quarantined event — perform quarantine + bookkeeping."""
        payload = event.payload or {}
        file_path = payload.get("file_path", "")
        rule_name = payload.get("rule_name", "unknown")
        features = payload.get("features", [])
        original_path = payload.get("original_path", file_path)
        first_seen_ip = payload.get("first_seen_ip", "127.0.0.1")

        import time as _time
        ts = _time.strftime("%Y-%m-%d %H:%M:%S")

        # -- Check quarantine config --
        quarantine_enabled = True
        try:
            from anteumbra.infrastructure.config.registry import ConfigRegistry
            quarantine_enabled = ConfigRegistry.get_raw_config().get(
                "quarantine", {}
            ).get("auto_quarantine_enabled", True)
        except Exception as exc:
            logger.warning(
                "[QUARANTINE] unable to read auto-quarantine config; skipping %s: %s",
                file_path,
                exc,
                exc_info=True,
            )
            self._emit_alert(
                "quarantine_skipped",
                ts,
                file_path,
                first_seen_ip,
                features,
                "WARNING",
                reason=f"config unavailable: {exc}",
            )
            return None

        # -- Check recently-restored whitelist --
        try:
            from anteumbra.infrastructure.quarantine import is_recently_restored
            if is_recently_restored(file_path):
                logger.info("[QUARANTINE] 跳过刚恢复文件: %s", file_path)
                return None
        except Exception as exc:
            logger.warning(
                "[QUARANTINE] unable to check recently restored files; skipping %s: %s",
                file_path,
                exc,
                exc_info=True,
            )
            self._emit_alert(
                "quarantine_skipped",
                ts,
                file_path,
                first_seen_ip,
                features,
                "WARNING",
                reason=f"restore guard unavailable: {exc}",
            )
            return None

        if not quarantine_enabled:
            # Emit skipped alert
            self._emit_alert("quarantine_skipped", ts, file_path,
                             first_seen_ip, features, "WARNING",
                             reason="auto_quarantine_disabled")
            return None

        # -- Perform quarantine --
        try:
            from anteumbra.application.quarantine_service import quarantine_registered_file
            result = quarantine_registered_file(
                file_path=file_path,
                rule_name=rule_name,
                features=features,
                original_path=original_path,
            )
        except Exception as e:
            logger.warning("[QUARANTINE] quarantine_file() 调用失败: %s", e)
            self._emit_alert("quarantine_failed", ts, file_path,
                             first_seen_ip, features, "WARNING",
                             reason=f"quarantine_file exception: {e}")
            return None

        if result is not None:
            # -- Success: application service committed quarantine + Registry --
            # Batch notification (aggregated, not per-file)
            self._batch_queued += 1
            elapsed = _time.time() - self._batch_last_flush
            if self._batch_queued >= self._batch_threshold or elapsed > 300:
                self._flush_batch()
        else:
            # -- Failure: immediate notification --
            self._emit_alert("quarantine_failed", ts, file_path,
                             first_seen_ip, features, "WARNING",
                             reason="文件可能已被删除或权限不足")

        return None

    # -- Internal helpers --

    def _emit_alert(self, alert_type: str, timestamp: str, file_path: str,
                    first_seen_ip: str, features: list, level: str,
                    **extra) -> None:
        """Emit alert_requested event through PluginManager (best-effort)."""
        try:
            from anteumbra.application.plugin_manager import get_plugin_manager
            pm = get_plugin_manager()
            if pm.is_enabled:
                pm.emit("alert_requested", self.name, {
                    "alert_type": alert_type,
                    "timestamp": timestamp,
                    "file_path": file_path,
                    "first_seen_ip": first_seen_ip,
                    "features": features,
                    "level": level,
                    "engine": "QuarantineHandler",
                    **extra,
                })
        except Exception:
            logger.warning(
                "[QUARANTINE] failed to emit alert type=%s for %s",
                alert_type,
                file_path,
                exc_info=True,
            )

    def _flush_batch(self) -> None:
        """Send aggregated batch quarantine-success notification."""
        if self._batch_queued <= 0:
            return
        count = self._batch_queued
        self._batch_queued = 0
        self._batch_last_flush = time.time()
        try:
            from anteumbra.application.plugin_manager import get_plugin_manager
            pm = get_plugin_manager()
            if pm.is_enabled:
                pm.emit("alert_requested", self.name, {
                    "alert_type": "quarantine_batch",
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "batch_count": count,
                    "level": "INFO",
                })
        except Exception:
            logger.warning(
                "[QUARANTINE] failed to emit batch alert for %d files",
                count,
                exc_info=True,
            )
