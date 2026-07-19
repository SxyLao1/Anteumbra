"""Runtime-owned client and poller for structured WAF events."""

from __future__ import annotations

import json
import logging
import threading
from collections import deque
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import requests

from anteumbra.domain import WAFEvent, WAFEventSource
from anteumbra.domain.runtime import ConfigProviderPort


logger = logging.getLogger("monitor.waf_client")


class MockWAFSource(WAFEventSource):
    """Pull structured events from the local mock WAF HTTP API."""

    def __init__(self, base_url: str = "http://127.0.0.1:9999") -> None:
        self.base_url = str(base_url).rstrip("/")

    def get_name(self) -> str:
        return "MockWAF"

    def is_available(self) -> bool:
        try:
            response = requests.get(f"{self.base_url}/status", timeout=3)
            return response.status_code == 200
        except requests.RequestException:
            return False

    def pull_events(
        self,
        start_time: datetime,
        end_time: datetime,
    ) -> list[WAFEvent]:
        try:
            response = requests.get(
                f"{self.base_url}/api/open/events",
                params={
                    "start": start_time.isoformat(),
                    "end": end_time.isoformat(),
                },
                timeout=10,
            )
            response.raise_for_status()
            raw_events = response.json()
            if not isinstance(raw_events, list):
                raise ValueError("WAF event response must be a JSON array")
            return [self._parse_event(item) for item in raw_events]
        except (requests.RequestException, ValueError, TypeError, KeyError) as exc:
            logger.warning("WAF event pull failed: %s", exc)
            return []

    @staticmethod
    def _parse_event(raw: dict[str, Any]) -> WAFEvent:
        if not isinstance(raw, dict):
            raise TypeError("WAF event must be a JSON object")
        return WAFEvent(
            event_id=str(raw.get("event_id", "")),
            src_ip=str(raw.get("src_ip", "")),
            timestamp=str(raw.get("timestamp", "")),
            http_method=str(raw.get("http_method", raw.get("method", ""))),
            url=str(raw.get("url", "")),
            user_agent=str(raw.get("user_agent", "")),
            waf_rule_id=str(raw.get("waf_rule_id", "")),
            waf_score=float(raw.get("waf_score", 0)),
            attack_type=str(raw.get("attack_type", "unknown")),
        )


class WAFPoller:
    """Poll one WAF source and append deduplicated events to a JSONL cache."""

    def __init__(
        self,
        source: WAFEventSource,
        config: ConfigProviderPort,
        cache_path: str | Path,
        *,
        default_interval: float = 10.0,
        log: logging.Logger | None = None,
    ) -> None:
        if default_interval <= 0:
            raise ValueError("default_interval must be positive")
        self.source = source
        self._config = config
        self._cache_path = Path(cache_path)
        self._default_interval = float(default_interval)
        self._logger = log or logger
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._lock = threading.RLock()
        self._last_poll_time: datetime | None = None
        self._seen_event_keys: set[str] = set()

    def start(self) -> None:
        """Start one interruptible worker; repeated calls are idempotent."""
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return
            self._cache_path.parent.mkdir(parents=True, exist_ok=True)
            self._load_checkpoint()
            self._stop_event.clear()
            self._thread = threading.Thread(
                target=self._poll_loop,
                daemon=True,
                name="WAFPoller",
            )
            self._thread.start()
        self._logger.info(
            "WAF poller started: source=%s interval=%ss",
            self.source.get_name(),
            self._poll_interval(),
        )

    def stop(self, timeout: float = 5.0) -> None:
        """Stop the worker without waiting for the full poll interval."""
        self._stop_event.set()
        with self._lock:
            thread = self._thread
        if thread is not None and thread.is_alive():
            thread.join(timeout=timeout)
        if thread is not None and thread.is_alive():
            raise TimeoutError("WAF poller did not stop before timeout")
        with self._lock:
            self._thread = None

    @property
    def is_running(self) -> bool:
        with self._lock:
            return bool(
                self._thread is not None
                and self._thread.is_alive()
                and not self._stop_event.is_set()
            )

    def poll_once(self, now: datetime | None = None) -> int:
        """Perform one poll and return the number of newly cached events."""
        settings = self._settings()
        if not settings["enabled"]:
            return 0
        self._reload_source_url(settings["url"])
        end_time = self._as_utc(now or datetime.now(timezone.utc))
        with self._lock:
            start_time = self._last_poll_time or (
                end_time - timedelta(seconds=settings["poll_interval"])
            )
        events = self.source.pull_events(start_time, end_time)
        written = self._append_cache(events)
        with self._lock:
            self._last_poll_time = end_time
        return written

    def get_cached_events(self, limit: int = 100) -> list[dict[str, Any]]:
        """Return the newest valid cache records."""
        if limit < 0:
            raise ValueError("limit must not be negative")
        if limit == 0 or not self._cache_path.exists():
            return []
        records: deque[dict[str, Any]] = deque(maxlen=limit)
        with self._lock:
            try:
                with self._cache_path.open("r", encoding="utf-8") as handle:
                    for line_number, line in enumerate(handle, 1):
                        if not line.strip():
                            continue
                        try:
                            value = json.loads(line)
                        except json.JSONDecodeError:
                            self._logger.warning(
                                "Skipping malformed WAF cache line %d", line_number
                            )
                            continue
                        if isinstance(value, dict):
                            records.append(value)
            except OSError as exc:
                self._logger.warning("Cannot read WAF cache %s: %s", self._cache_path, exc)
                return []
        return list(records)

    def _poll_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                written = self.poll_once()
                if written:
                    self._logger.debug("Cached %d new WAF events", written)
            except Exception:
                self._logger.warning("WAF polling iteration failed", exc_info=True)
            self._stop_event.wait(self._poll_interval())

    def _append_cache(self, events: list[WAFEvent]) -> int:
        if not events:
            return 0
        self._cache_path.parent.mkdir(parents=True, exist_ok=True)
        written = 0
        with self._lock:
            with self._cache_path.open("a", encoding="utf-8") as handle:
                for event in events:
                    key = self._event_key(event)
                    if key in self._seen_event_keys:
                        continue
                    handle.write(
                        json.dumps(self._event_payload(event), ensure_ascii=False) + "\n"
                    )
                    self._seen_event_keys.add(key)
                    written += 1
                handle.flush()
        return written

    def _load_checkpoint(self) -> None:
        self._seen_event_keys.clear()
        self._last_poll_time = None
        if not self._cache_path.exists():
            return
        recent_lines: deque[str] = deque(maxlen=2000)
        try:
            with self._cache_path.open("r", encoding="utf-8") as handle:
                for line in handle:
                    if line.strip():
                        recent_lines.append(line)
        except OSError as exc:
            self._logger.warning("Cannot load WAF checkpoint %s: %s", self._cache_path, exc)
            return

        newest_time: datetime | None = None
        for line in recent_lines:
            try:
                raw = json.loads(line)
                event = MockWAFSource._parse_event(raw)
                timestamp = self._parse_timestamp(event.timestamp)
            except (json.JSONDecodeError, TypeError, ValueError, KeyError):
                continue
            self._seen_event_keys.add(self._event_key(event))
            if timestamp is not None and (newest_time is None or timestamp > newest_time):
                newest_time = timestamp
        self._last_poll_time = newest_time

    def _settings(self) -> dict[str, Any]:
        try:
            raw = self._config.get().get("waf_source", {})
            interval = float(raw.get("poll_interval", self._default_interval))
            if interval <= 0:
                raise ValueError("poll_interval must be positive")
            return {
                "enabled": bool(raw.get("enabled", False)),
                "url": str(raw.get("url", "")).rstrip("/"),
                "poll_interval": interval,
            }
        except (AttributeError, TypeError, ValueError):
            self._logger.warning("Invalid WAF poller settings; using safe defaults")
            return {
                "enabled": True,
                "url": "",
                "poll_interval": self._default_interval,
            }

    def _poll_interval(self) -> float:
        return float(self._settings()["poll_interval"])

    def _reload_source_url(self, url: str) -> None:
        if not url or not hasattr(self.source, "base_url"):
            return
        old_url = str(getattr(self.source, "base_url"))
        if old_url != url:
            setattr(self.source, "base_url", url)
            self._logger.info("WAF source URL reloaded: %s -> %s", old_url, url)

    @staticmethod
    def _event_payload(event: WAFEvent) -> dict[str, Any]:
        return {
            "event_id": event.event_id,
            "src_ip": event.src_ip,
            "timestamp": event.timestamp,
            "http_method": event.http_method,
            "url": event.url,
            "user_agent": event.user_agent,
            "waf_rule_id": event.waf_rule_id,
            "waf_score": event.waf_score,
            "attack_type": event.attack_type,
        }

    @classmethod
    def _event_key(cls, event: WAFEvent) -> str:
        if event.event_id:
            return f"id:{event.event_id}"
        return "fallback:" + "|".join(
            [
                event.timestamp,
                event.src_ip,
                event.http_method,
                event.url,
                event.waf_rule_id,
            ]
        )

    @staticmethod
    def _parse_timestamp(value: str) -> datetime | None:
        try:
            return WAFPoller._as_utc(datetime.fromisoformat(value.replace("Z", "+00:00")))
        except ValueError:
            return None

    @staticmethod
    def _as_utc(value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)


def build_waf_poller(
    config: ConfigProviderPort,
    cache_path: str | Path,
    *,
    log: logging.Logger | None = None,
) -> WAFPoller | None:
    """Build a poller from one explicit configuration snapshot."""
    raw = config.get().get("waf_source", {})
    if not raw.get("enabled", False):
        return None
    source_type = str(raw.get("type", "mock")).strip().lower()
    if source_type != "mock":
        (log or logger).warning("Unsupported WAF source type: %s", source_type)
        return None
    try:
        interval = float(raw.get("poll_interval", 10))
    except (TypeError, ValueError):
        interval = 10.0
    if interval <= 0:
        interval = 10.0
    source = MockWAFSource(str(raw.get("url", "http://127.0.0.1:9999")))
    return WAFPoller(
        source,
        config,
        cache_path,
        default_interval=interval,
        log=log,
    )


__all__ = ["MockWAFSource", "WAFPoller", "build_waf_poller"]
