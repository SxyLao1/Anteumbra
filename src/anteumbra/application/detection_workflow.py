"""Application orchestration for one filesystem-triggered detection."""

from __future__ import annotations

import logging
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from anteumbra.domain.entities import ScanResult
from anteumbra.domain.quarantine import QuarantineGuardPort
from anteumbra.domain.runtime import DetectionRegistryPort, EventPublisherPort, MetricsPort
from anteumbra.domain.site import SiteIdentity

ScanCallable = Callable[[Path], ScanResult | None]
AttributionResolver = Callable[[Path], str]
AlertEmitter = Callable[..., None]
QuarantineEmitter = Callable[..., None]
DetectionReporter = Callable[[ScanResult], None]
ScanErrorReporter = Callable[[Path, Exception], None]


class DetectionWorkflow:
    """Preserve detection side-effect ordering behind domain-facing ports."""

    def __init__(
        self,
        *,
        config: Mapping[str, Any],
        registry: DetectionRegistryPort,
        metrics: MetricsPort,
        events: EventPublisherPort,
        quarantine: QuarantineGuardPort,
        site: SiteIdentity,
        logger: logging.Logger,
    ) -> None:
        self._config = config
        self._registry = registry
        self._metrics = metrics
        self._events = events
        self._quarantine = quarantine
        self._site = site
        self._logger = logger

    def execute(
        self,
        event_path: Path,
        event_type: str,
        *,
        scan: ScanCallable,
        resolve_first_seen_ip: AttributionResolver,
        emit_alert: AlertEmitter,
        emit_file_quarantined: QuarantineEmitter,
        report_detection: DetectionReporter | None = None,
        report_scan_error: ScanErrorReporter | None = None,
    ) -> None:
        """Run one scan and its ordered detection side effects."""
        if self._is_recently_restored(event_path, before_scan=True):
            return

        try:
            scan_result = scan(event_path)
            self._metrics.increment_site("scan_total", self._site.site_id)
            self._publish_scan_result(event_path, event_type, scan_result)
            if not scan_result or not scan_result.is_suspicious:
                return

            if report_detection is not None:
                report_detection(scan_result)
            self._handle_detection(
                event_path,
                scan_result,
                resolve_first_seen_ip=resolve_first_seen_ip,
                emit_alert=emit_alert,
                emit_file_quarantined=emit_file_quarantined,
            )
        except Exception as exc:
            if report_scan_error is not None:
                report_scan_error(event_path, exc)
            else:
                self._logger.error("[SCAN] %s: %s", event_path, exc)

    def _publish_scan_result(
        self,
        event_path: Path,
        event_type: str,
        scan_result: ScanResult | None,
    ) -> None:
        try:
            self._events.publish(
                "file_scanned",
                "monitor",
                {
                    "file_path": str(event_path),
                    "event_type": event_type,
                    "is_suspicious": scan_result.is_suspicious if scan_result else False,
                    "engine": scan_result.engine if scan_result else "unknown",
                    "features": scan_result.features if scan_result else [],
                    "score": getattr(scan_result, "score", 0) if scan_result else 0,
                    **self._site.as_dict(),
                },
            )
        except Exception:
            self._logger.debug("PluginManager emit file_scanned failed", exc_info=True)

    def _handle_detection(
        self,
        event_path: Path,
        scan_result: ScanResult,
        *,
        resolve_first_seen_ip: AttributionResolver,
        emit_alert: AlertEmitter,
        emit_file_quarantined: QuarantineEmitter,
    ) -> None:
        try:
            first_seen_ip = resolve_first_seen_ip(event_path)
            emit_alert(
                "local_detection",
                str(event_path),
                scan_result.engine,
                scan_result.features,
                first_seen_ip,
                "CRITICAL",
            )
            self._registry.add(
                event_path,
                scan_result.features,
                first_seen_ip=first_seen_ip,
                detection_source="passive",
                site=self._site,
            )
            self._handle_quarantine(
                event_path,
                scan_result,
                first_seen_ip=first_seen_ip,
                emit_alert=emit_alert,
                emit_file_quarantined=emit_file_quarantined,
            )
        except Exception as exc:
            self._logger.warning(
                "[QUARANTINE] 隔离失败: %s | %s",
                event_path.name,
                exc,
            )

    def _handle_quarantine(
        self,
        event_path: Path,
        scan_result: ScanResult,
        *,
        first_seen_ip: str,
        emit_alert: AlertEmitter,
        emit_file_quarantined: QuarantineEmitter,
    ) -> None:
        if not self._auto_quarantine_enabled():
            self._logger.info("[QUARANTINE] 总开关关闭，跳过隔离: %s", event_path.name)
            emit_alert(
                "quarantine_skipped",
                str(event_path),
                scan_result.engine,
                scan_result.features,
                first_seen_ip,
                "WARNING",
                reason="auto_quarantine_disabled",
            )
            return

        if self._is_recently_restored(event_path):
            self._logger.info("[QUARANTINE] 跳过刚恢复文件: %s", event_path.name)
            return

        rule_name = scan_result.features[0] if scan_result.features else "unknown"
        emit_file_quarantined(
            file_path=str(event_path),
            rule_name=rule_name,
            features=scan_result.features,
            original_path=str(event_path),
            first_seen_ip=first_seen_ip,
        )

    def _auto_quarantine_enabled(self) -> bool:
        try:
            quarantine = self._config.get("quarantine", {})
            return quarantine.get("auto_quarantine_enabled", True)
        except Exception:
            self._logger.debug("Failed to read quarantine config", exc_info=True)
            return True

    def _is_recently_restored(self, event_path: Path, *, before_scan: bool = False) -> bool:
        try:
            restored = self._quarantine.is_recently_restored(str(event_path))
        except Exception:
            if before_scan:
                self._logger.debug(
                    "Failed to check restored-file guard before scanning",
                    exc_info=True,
                )
                return False
            raise

        if restored and before_scan:
            self._logger.info(
                "[RESTORE][SKIP] Recently restored file: %s",
                event_path.name,
            )
        return restored


__all__ = ["DetectionWorkflow"]
