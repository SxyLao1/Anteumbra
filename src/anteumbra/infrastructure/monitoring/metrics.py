"""Runtime-owned aggregate and per-site metrics collection."""

from __future__ import annotations

import copy
import json
import logging
import os
import threading
import time
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


logger = logging.getLogger("monitor.metrics")

_COUNTER_DEFAULTS: dict[str, Any] = {
    "scan_total": 0,
    "scan_suspicious": 0,
    "alert_total": 0,
    "alert_cooldown_suppressed": 0,
    "notification_attempted": 0,
    "notification_success": 0,
    "notification_failed": 0,
    "notification_skipped": 0,
    "last_notification_status": "never",
    "last_notification_error": "",
    "last_notification_at": "",
    "registry_size": 0,
    "log_lines_processed": 0,
    "scan_queue_overflow": 0,
    "baseline_runs": 0,
    "baseline_files_queued": 0,
    "plugin_queue_overflow": 0,
    "plugin_handler_timeout": 0,
    "plugin_handler_skipped": 0,
    "wechat_failures": 0,
}


class MetricsCollector:
    """Own persisted process metrics and optional Registry-derived gauges."""

    def __init__(
        self,
        data_path: str | Path,
        *,
        registry_reader: Callable[..., list[dict[str, Any]]] | None = None,
    ) -> None:
        self.data_path = Path(data_path)
        self._registry_reader = registry_reader
        self._lock = threading.RLock()
        self._lifecycle_lock = threading.RLock()
        self._stats = {**_COUNTER_DEFAULTS, "uptime_seconds": 0, "memory_mb": 0}
        self._site_stats: dict[str, dict[str, Any]] = {}
        self._start_time = time.time()
        self._stop_event = threading.Event()
        self._worker: threading.Thread | None = None

    @property
    def is_running(self) -> bool:
        """Return whether the persistence worker is alive."""
        with self._lifecycle_lock:
            return bool(self._worker and self._worker.is_alive())

    def increment(
        self,
        metric: str,
        value: int = 1,
        *,
        site_id: str | None = None,
    ) -> None:
        """Increment an aggregate counter and optionally its site bucket."""
        with self._lock:
            self._stats[metric] = self._stats.get(metric, 0) + value
            if site_id:
                bucket = self._site_bucket(site_id)
                bucket[metric] = bucket.get(metric, 0) + value

    def increment_site(self, metric: str, site_id: str, value: int = 1) -> None:
        """Increment a site-only counter without changing the aggregate."""
        with self._lock:
            bucket = self._site_bucket(site_id)
            bucket[metric] = bucket.get(metric, 0) + value

    def record_notification(
        self,
        status: str,
        error: str = "",
        *,
        site_id: str | None = None,
    ) -> None:
        """Record one notification outcome and its last-known diagnostics."""
        normalized_status = str(status).lower()
        metric = {
            "attempted": "notification_attempted",
            "success": "notification_success",
            "failed": "notification_failed",
            "partial": "notification_failed",
            "skipped": "notification_skipped",
            "queued": "notification_attempted",
        }.get(normalized_status)
        timestamp = datetime.now(timezone.utc).isoformat()
        with self._lock:
            if metric:
                self._stats[metric] = self._stats.get(metric, 0) + 1
            self._stats.update(
                last_notification_status=normalized_status,
                last_notification_error=str(error)[:500],
                last_notification_at=timestamp,
            )
            if site_id:
                bucket = self._site_bucket(site_id)
                if metric:
                    bucket[metric] = bucket.get(metric, 0) + 1
                bucket.update(
                    last_notification_status=normalized_status,
                    last_notification_error=str(error)[:500],
                    last_notification_at=timestamp,
                )

    def record_wechat_failure(self, *, site_id: str | None = None) -> None:
        """Record one WeChat notification failure."""
        self.increment("wechat_failures", site_id=site_id)

    def record_memory_usage(self) -> None:
        """Sample the current process resident memory in MB."""
        import psutil

        memory_mb = psutil.Process().memory_info().rss / 1024 / 1024
        with self._lock:
            self._stats["memory_mb"] = memory_mb

    def get(self, site_id: str | None = None) -> dict[str, Any]:
        """Return an aggregate or site-specific defensive snapshot."""
        self._refresh_registry_gauges()
        with self._lock:
            self._stats["uptime_seconds"] = time.time() - self._start_time
            if site_id:
                return copy.deepcopy(
                    self._site_stats.get(self._normalize_site_id(site_id), {})
                )
            snapshot = copy.deepcopy(self._stats)
            snapshot["sites"] = copy.deepcopy(self._site_stats)
            return snapshot

    def start(self) -> None:
        """Load persisted state and start the persistence worker once."""
        with self._lifecycle_lock:
            if self._worker is not None and self._worker.is_alive():
                return
            self.load_persisted()
            try:
                self.record_memory_usage()
            except Exception:
                logger.warning("Initial memory metrics sample failed", exc_info=True)
            self._stop_event.clear()
            self._worker = threading.Thread(
                target=self._persistence_worker,
                daemon=True,
                name="MetricsPersistence",
            )
            self._worker.start()

    def stop(self, timeout: float = 2.0, persist: bool = True) -> bool:
        """Stop the worker and optionally persist one final snapshot."""
        with self._lifecycle_lock:
            worker = self._worker
            self._stop_event.set()
        if worker is not None and worker is not threading.current_thread():
            worker.join(timeout=max(0.0, timeout))
        stopped = worker is None or not worker.is_alive()
        if persist:
            self.persist()
        with self._lifecycle_lock:
            if self._worker is worker and stopped:
                self._worker = None
        return stopped

    def persist(self) -> None:
        """Atomically persist the current metrics snapshot."""
        content = json.dumps(self.get(), ensure_ascii=False, indent=2)
        temporary = self.data_path.with_name(f".{self.data_path.name}.tmp")
        try:
            self.data_path.parent.mkdir(parents=True, exist_ok=True)
            temporary.write_text(content, encoding="utf-8")
            os.replace(temporary, self.data_path)
        finally:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                logger.debug("Cannot remove temporary metrics file", exc_info=True)

    def load_persisted(self) -> None:
        """Load compatible aggregate counters and site buckets from disk."""
        if not self.data_path.exists():
            return
        try:
            saved = json.loads(self.data_path.read_text(encoding="utf-8"))
            if not isinstance(saved, dict):
                raise ValueError("metrics root must be an object")
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            raise RuntimeError(f"cannot load metrics from {self.data_path}: {exc}") from exc

        with self._lock:
            for key in self._stats:
                value = saved.get(key)
                if isinstance(value, (int, float, str)):
                    self._stats[key] = value
            saved_sites = saved.get("sites", {})
            if isinstance(saved_sites, dict):
                for site_id, values in saved_sites.items():
                    if not isinstance(values, dict):
                        continue
                    bucket = self._site_bucket(site_id)
                    for key, value in values.items():
                        if isinstance(value, (int, float, str)):
                            bucket[key] = value

    def _refresh_registry_gauges(self) -> None:
        if self._registry_reader is None:
            return
        try:
            active = self._registry_reader(
                include_deleted=False,
                include_false_positive=False,
            )
            all_records = self._registry_reader(
                include_deleted=True,
                include_false_positive=True,
            )
        except Exception as exc:
            logger.warning("Registry metrics probe failed: %s", exc, exc_info=True)
            with self._lock:
                self._stats["registry_probe_status"] = "error"
                self._stats["registry_probe_error"] = str(exc)[:500]
            return

        active_by_site = self._counts_by_site(active)
        total_by_site = self._counts_by_site(all_records)
        with self._lock:
            self._stats["scan_suspicious"] = len(active)
            self._stats["registry_size"] = len(all_records)
            self._stats["registry_probe_status"] = "ok"
            self._stats["registry_probe_error"] = ""
            site_ids = set(active_by_site) | set(total_by_site) | set(self._site_stats)
            for site_id in site_ids:
                bucket = self._site_bucket(site_id)
                bucket["scan_suspicious"] = active_by_site.get(site_id, 0)
                bucket["registry_size"] = total_by_site.get(site_id, 0)

    def _persistence_worker(self) -> None:
        while not self._stop_event.wait(60.0):
            try:
                self.persist()
            except Exception:
                logger.exception("Metrics persistence failed")

    def _site_bucket(self, site_id: str) -> dict[str, Any]:
        normalized = self._normalize_site_id(site_id)
        return self._site_stats.setdefault(normalized, dict(_COUNTER_DEFAULTS))

    @staticmethod
    def _normalize_site_id(site_id: str) -> str:
        normalized = str(site_id).strip().lower()
        if not normalized:
            raise ValueError("site_id must not be empty")
        return normalized

    @staticmethod
    def _counts_by_site(records: list[dict[str, Any]]) -> dict[str, int]:
        counts: dict[str, int] = {}
        for record in records:
            site_id = str(record.get("site_id") or "legacy").strip().lower()
            counts[site_id] = counts.get(site_id, 0) + 1
        return counts
