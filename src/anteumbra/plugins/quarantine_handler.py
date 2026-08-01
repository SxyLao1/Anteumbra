# -*- coding: utf-8 -*-
"""
v2.0: Quarantine Handler Plugin — bridges event bus to concrete quarantine module.

Subscribes to ``file_quarantined`` events emitted by monitor.py.
Calls the existing ``quarantine_file()`` function and handles all
post-quarantine bookkeeping:
  - mark_quarantined() in registry
  - emit alert_requested for success/failure/skip notifications
  - batch notification aggregation

The application DetectionWorkflow emits quarantine requests; this plugin
owns the infrastructure side effects listed above.
"""
import logging
import time
from collections.abc import Callable, Mapping
from typing import Any, Dict, List, Optional

from anteumbra.domain import DomainEvent, Plugin
from anteumbra.domain.runtime import EventPublisherPort


class QuarantineHandlerPlugin(Plugin):
    """Bridge plugin: subscribes to file_quarantined and delegates to concrete quarantine."""

    def __init__(
        self,
        *,
        quarantine_file: Callable[..., Optional[Dict[str, Any]]],
        recently_restored: Callable[[str], bool],
        events: EventPublisherPort,
        runtime_config: Mapping[str, Any],
        log: logging.Logger,
    ) -> None:
        self._batch_threshold = 50
        self._batch_state: Dict[str, Dict[str, Any]] = {}
        self._quarantine_file = quarantine_file
        self._recently_restored = recently_restored
        self._events = events
        self._runtime_config = runtime_config
        self._logger = log

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
        try:
            self._batch_threshold = max(1, int(config.get("batch_threshold", 50)))
        except (TypeError, ValueError):
            self._batch_threshold = 50
        self._batch_state = {}
        self._logger.info(
            "QuarantineHandler: 已激活 (batch_threshold=%d)", self._batch_threshold
        )

    def deactivate(self) -> None:
        # Flush any pending batch notifications on shutdown
        for site_id in tuple(self._batch_state):
            self._flush_batch(site_id)
        self._logger.info("QuarantineHandler: 已停用")

    def on_event(self, event: DomainEvent) -> Optional[List[DomainEvent]]:
        """Handle file_quarantined event — perform quarantine + bookkeeping."""
        payload = event.payload or {}
        file_path = payload.get("file_path", "")
        rule_name = payload.get("rule_name", "unknown")
        features = payload.get("features", [])
        original_path = payload.get("original_path", file_path)
        first_seen_ip = payload.get("first_seen_ip", "127.0.0.1")
        site_id = payload.get("site_id")
        site_name = payload.get("site_name")

        import time as _time
        ts = _time.strftime("%Y-%m-%d %H:%M:%S")

        # -- Check quarantine config --
        quarantine_enabled = self._runtime_config.get("quarantine", {}).get(
            "auto_quarantine_enabled", True
        )

        # -- Check recently-restored whitelist --
        try:
            if self._recently_restored(file_path):
                self._logger.info("[QUARANTINE] 跳过刚恢复文件: %s", file_path)
                return None
        except Exception as exc:
            self._logger.warning(
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
                site_id=site_id,
                site_name=site_name,
            )
            return None

        if not quarantine_enabled:
            # Emit skipped alert
            self._emit_alert("quarantine_skipped", ts, file_path,
                             first_seen_ip, features, "WARNING",
                             reason="auto_quarantine_disabled",
                             site_id=site_id, site_name=site_name)
            return None

        # -- Perform quarantine --
        try:
            result = self._quarantine_file(
                file_path=file_path,
                rule_name=rule_name,
                features=features,
                original_path=original_path,
                site_id=site_id,
                site_name=site_name,
            )
        except Exception as e:
            self._logger.warning("[QUARANTINE] quarantine_file() 调用失败: %s", e)
            self._emit_alert("quarantine_failed", ts, file_path,
                             first_seen_ip, features, "WARNING",
                             reason=f"quarantine_file exception: {e}",
                             site_id=site_id, site_name=site_name)
            return None

        if result is not None:
            # -- Success: application service committed quarantine + Registry --
            # Batch notifications are isolated by site. Combining detections
            # from different website roots would make both the alert and its
            # metrics impossible to attribute safely.
            batch_site_id = str(site_id or "legacy").strip().lower() or "legacy"
            batch_site_name = str(
                site_name
                or ("Legacy / unassigned" if batch_site_id == "legacy" else batch_site_id)
            ).strip()
            state = self._batch_state.setdefault(
                batch_site_id,
                {"count": 0, "last_flush": _time.time(), "site_name": batch_site_name},
            )
            state["site_name"] = batch_site_name
            state["count"] += 1
            elapsed = _time.time() - state["last_flush"]
            if state["count"] >= self._batch_threshold or elapsed > 300:
                self._flush_batch(batch_site_id)
        else:
            # -- Failure: immediate notification --
            self._emit_alert("quarantine_failed", ts, file_path,
                             first_seen_ip, features, "WARNING",
                             reason="文件可能已被删除或权限不足",
                             site_id=site_id, site_name=site_name)

        return None

    # -- Internal helpers --

    def _emit_alert(self, alert_type: str, timestamp: str, file_path: str,
                    first_seen_ip: str, features: list, level: str,
                    site_id: Optional[str] = None,
                    site_name: Optional[str] = None,
                    **extra) -> None:
        """Emit alert_requested through the injected runtime event port."""
        try:
            self._events.publish("alert_requested", self.name, {
                "alert_type": alert_type,
                "timestamp": timestamp,
                "file_path": file_path,
                "first_seen_ip": first_seen_ip,
                "features": features,
                "level": level,
                "site_id": site_id,
                "site_name": site_name,
                "engine": "QuarantineHandler",
                **extra,
            })
        except Exception:
            self._logger.warning(
                "[QUARANTINE] failed to emit alert type=%s for %s",
                alert_type,
                file_path,
                exc_info=True,
            )

    def _flush_batch(self, site_id: str) -> None:
        """Send one site's aggregated quarantine-success notification."""
        state = self._batch_state.get(site_id)
        if not state or state["count"] <= 0:
            return
        count = state["count"]
        state["count"] = 0
        state["last_flush"] = time.time()
        try:
            self._events.publish("alert_requested", self.name, {
                "alert_type": "quarantine_batch",
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "batch_count": count,
                "level": "INFO",
                "site_id": site_id,
                "site_name": state["site_name"],
            })
        except Exception:
            self._logger.warning(
                "[QUARANTINE] failed to emit batch alert for %d files at site %s",
                count,
                site_id,
                exc_info=True,
            )
