"""Runtime-owned IP blocking devices and retry coordination."""

from __future__ import annotations

import json
import logging
import os
import threading
import time
import uuid
from abc import ABC, abstractmethod
from collections.abc import Collection, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from anteumbra.domain.blocking import BlockDecision, BlockResult, canonical_ip
from anteumbra.domain.site import SiteIdentity


logger = logging.getLogger("monitor.ip_blocker")


class IPBlockerDisabledError(RuntimeError):
    """No blocking devices are enabled for this runtime."""


class BlockDevice(ABC):
    """Adapter contract implemented by each firewall or WAF integration."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Return the stable configured device name."""

    @abstractmethod
    def block(self, decision: BlockDecision) -> BlockResult:
        """Execute one block decision."""

    @abstractmethod
    def unblock(self, ip: str) -> BlockResult:
        """Remove one address from the device blocklist."""

    @abstractmethod
    def is_available(self) -> bool:
        """Return whether the device currently accepts operations."""

    def get_name(self) -> str:
        """Return the device name for templates that predate the property API."""
        return self.name


class StdoutDevice(BlockDevice):
    """Log blocking decisions without changing an external system."""

    def __init__(self, name: str = "stdout") -> None:
        self._name = str(name)

    @property
    def name(self) -> str:
        return self._name

    def is_available(self) -> bool:
        return True

    def block(self, decision: BlockDecision) -> BlockResult:
        logger.info(
            "[BLOCK][%s] ip=%s site=%s reason=%s profile=%s",
            self.name,
            decision.ip,
            decision.site.site_id,
            decision.reason,
            decision.profile_id[:8],
        )
        return BlockResult(self.name, True, "logged", decision.ip)

    def unblock(self, ip: str) -> BlockResult:
        canonical = canonical_ip(ip)
        logger.info("[UNBLOCK][%s] ip=%s", self.name, canonical)
        return BlockResult(self.name, True, "logged", canonical)


class MockDevice(BlockDevice):
    """In-memory device for deterministic integration tests."""

    def __init__(self, name: str = "mock") -> None:
        self._name = str(name)
        self._blocklist: set[str] = set()
        self._lock = threading.Lock()

    @property
    def name(self) -> str:
        return self._name

    def is_available(self) -> bool:
        return True

    def block(self, decision: BlockDecision) -> BlockResult:
        with self._lock:
            self._blocklist.add(decision.ip)
        return BlockResult(self.name, True, "blocked (mock)", decision.ip)

    def unblock(self, ip: str) -> BlockResult:
        canonical = canonical_ip(ip)
        with self._lock:
            self._blocklist.discard(canonical)
        return BlockResult(self.name, True, "unblocked (mock)", canonical)

    def is_blocked(self, ip: str) -> bool:
        with self._lock:
            return canonical_ip(ip) in self._blocklist

    def list_all(self) -> list[str]:
        with self._lock:
            return sorted(self._blocklist)


class HTTPDevice(BlockDevice):
    """Send block and unblock requests to a configured HTTP API."""

    def __init__(self, name: str, url: str, api_key: str = "") -> None:
        self._name = str(name)
        self.url = str(url).rstrip("/")
        self.api_key = str(api_key)

    @property
    def name(self) -> str:
        return self._name

    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    def is_available(self) -> bool:
        import requests

        try:
            response = requests.get(
                f"{self.url.rsplit('/', 1)[0]}/ping",
                headers=self._headers(),
                timeout=3,
            )
            return response.status_code == 200
        except requests.RequestException:
            return False

    def block(self, decision: BlockDecision) -> BlockResult:
        import requests

        payload = {
            "ip": decision.ip,
            "comment": f"Anteumbra: {decision.reason} (profile: {decision.profile_id[:8]})",
            "permanent": decision.permanent,
            "duration": decision.duration_seconds,
            "risk_score": decision.risk_score,
            **decision.site.as_dict(),
        }
        try:
            response = requests.post(
                self.url,
                json=payload,
                headers=self._headers(),
                timeout=10,
            )
            success = response.status_code < 400
            message = "blocked" if success else response.text[:200]
            return BlockResult(self.name, success, message, decision.ip)
        except requests.RequestException as exc:
            return BlockResult(self.name, False, str(exc), decision.ip)

    def unblock(self, ip: str) -> BlockResult:
        import requests

        canonical = canonical_ip(ip)
        url = self.url.replace("/block", "/unblock")
        try:
            response = requests.post(
                url,
                json={"ip": canonical},
                headers=self._headers(),
                timeout=10,
            )
            success = response.status_code < 400
            message = "unblocked" if success else response.text[:200]
            return BlockResult(self.name, success, message, canonical)
        except requests.RequestException as exc:
            return BlockResult(self.name, False, str(exc), canonical)


@dataclass
class RetryItem:
    """One failed decision and only the devices that still need it."""

    decision: BlockDecision
    pending_devices: tuple[str, ...]
    attempts: int = 1
    max_attempts: int = 5
    next_retry_at: float = 0.0
    last_error: str = ""

    @property
    def key(self) -> str:
        return f"{self.decision.site.site_id}|{self.decision.ip}"


class IPBlocker:
    """Broadcast IP decisions and own their bounded background retry worker."""

    def __init__(
        self,
        devices: Sequence[BlockDevice] = (),
        *,
        enabled: bool = True,
        auto_block_enabled: bool = False,
        auto_block_min_score: float = 0.8,
        retry_path: str | Path | None = None,
        retry_interval: float = 30.0,
        max_retry_attempts: int = 5,
        log: logging.Logger | None = None,
    ) -> None:
        if not 0.0 <= float(auto_block_min_score) <= 1.0:
            raise ValueError("auto_block_min_score must be between 0 and 1")
        if retry_interval <= 0:
            raise ValueError("retry_interval must be positive")
        if max_retry_attempts < 1:
            raise ValueError("max_retry_attempts must be positive")

        self._devices = tuple(devices)
        self._enabled = bool(enabled)
        self._auto_block_enabled = bool(auto_block_enabled)
        self._auto_block_min_score = float(auto_block_min_score)
        self._retry_path = Path(retry_path).resolve() if retry_path else None
        self._retry_interval = float(retry_interval)
        self._max_retry_attempts = int(max_retry_attempts)
        self._logger = log or logger
        self._history: list[BlockResult] = []
        self._retry_queue: dict[str, RetryItem] = {}
        self._retry_thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._lock = threading.RLock()
        self._queue_loaded = False
        self._last_persistence_error: str | None = None

    @classmethod
    def from_config(
        cls,
        config: Mapping[str, Any],
        *,
        retry_path: str | Path,
        log: logging.Logger | None = None,
    ) -> "IPBlocker":
        """Build a blocker from one runtime-owned configuration snapshot."""
        enabled = bool(config.get("enabled", False))
        devices: list[BlockDevice] = []
        if enabled:
            for raw in config.get("devices", []):
                if not isinstance(raw, Mapping):
                    raise ValueError("each ip_blocker device must be a table")
                device_type = str(raw.get("type", "stdout")).strip().lower()
                name = str(raw.get("name") or device_type)
                if device_type == "mock":
                    devices.append(MockDevice(name))
                elif device_type == "http":
                    url = str(raw.get("url") or "").strip()
                    if not url:
                        raise ValueError(f"HTTP blocking device {name!r} requires a URL")
                    devices.append(HTTPDevice(name, url, str(raw.get("api_key") or "")))
                elif device_type == "stdout":
                    devices.append(StdoutDevice(name))
                else:
                    raise ValueError(f"unsupported IP blocking device type: {device_type!r}")
            if not devices:
                devices.append(StdoutDevice())

        return cls(
            devices,
            enabled=enabled,
            auto_block_enabled=bool(config.get("auto_block_enabled", False)),
            auto_block_min_score=float(config.get("auto_block_min_score", 0.8)),
            retry_path=retry_path,
            retry_interval=float(config.get("retry_interval_seconds", 30)),
            max_retry_attempts=int(config.get("max_retry_attempts", 5)),
            log=log,
        )

    @property
    def enabled(self) -> bool:
        return self._enabled and bool(self._devices)

    @property
    def auto_block_enabled(self) -> bool:
        return self._auto_block_enabled

    @property
    def auto_block_min_score(self) -> float:
        return self._auto_block_min_score

    @property
    def devices(self) -> tuple[BlockDevice, ...]:
        """Return an immutable device inventory for status rendering."""
        return self._devices

    @property
    def device_count(self) -> int:
        return len(self._devices)

    @property
    def device_names(self) -> tuple[str, ...]:
        return tuple(device.name for device in self._devices)

    @property
    def is_running(self) -> bool:
        with self._lock:
            return self._retry_thread is not None and self._retry_thread.is_alive()

    @property
    def last_persistence_error(self) -> str | None:
        with self._lock:
            return self._last_persistence_error

    def start(self) -> None:
        """Start the retry worker exactly once when blocking is enabled."""
        if not self.enabled:
            return
        with self._lock:
            if self._retry_thread is not None and self._retry_thread.is_alive():
                return
            if not self._queue_loaded:
                self._load_retry_queue_locked()
                self._queue_loaded = True
            self._stop_event.clear()
            self._retry_thread = threading.Thread(
                target=self._retry_loop,
                daemon=True,
                name="BlockRetry",
            )
            self._retry_thread.start()

    def stop(self) -> None:
        """Stop and join the retry worker, then persist its final queue."""
        with self._lock:
            thread = self._retry_thread
            self._stop_event.set()
        if thread is not None and thread.is_alive():
            thread.join(timeout=12.0)
        if thread is not None and thread.is_alive():
            self._logger.warning("IP blocker retry worker did not stop within 12 seconds")
        with self._lock:
            self._persist_retry_queue_locked()
            self._retry_thread = None

    def block(
        self,
        ips: Sequence[str],
        *,
        reason: str,
        site: SiteIdentity,
        profile_id: str = "",
        risk_score: float = 0.0,
        permanent: bool = False,
        device_names: Collection[str] | None = None,
    ) -> list[BlockResult]:
        """Block validated addresses on all or selected devices."""
        devices = self._select_devices(device_names)
        canonical_ips = self._canonical_ips(ips)
        results: list[BlockResult] = []
        for ip in canonical_ips:
            decision = BlockDecision(
                ip=ip,
                reason=reason,
                site=site,
                profile_id=profile_id,
                risk_score=risk_score,
                permanent=permanent,
            )
            current, failed_devices = self._execute_block(decision, devices)
            results.extend(current)
            if failed_devices:
                self._enqueue_retry(decision, failed_devices, current)
        return results

    def unblock(
        self,
        ips: Sequence[str],
        *,
        device_names: Collection[str] | None = None,
    ) -> list[BlockResult]:
        """Unblock validated addresses on all or selected devices."""
        devices = self._select_devices(device_names)
        results: list[BlockResult] = []
        for ip in self._canonical_ips(ips):
            for device in devices:
                try:
                    result = device.unblock(ip)
                except Exception as exc:
                    result = BlockResult(device.name, False, str(exc), ip)
                results.append(result)
        self._append_history(results)
        return results

    def auto_block(
        self,
        profile_id: str,
        ips: Sequence[str],
        risk_score: float,
        *,
        site: SiteIdentity,
        reason: str = "",
    ) -> list[BlockResult]:
        """Apply automatic blocking only when enabled and above threshold."""
        if not self._auto_block_enabled or risk_score < self._auto_block_min_score:
            return []
        return self.block(
            ips,
            reason=reason,
            site=site,
            profile_id=profile_id,
            risk_score=risk_score,
        )

    def get_blocklist(self) -> list[dict[str, str]]:
        """Return addresses known by in-memory devices."""
        result: list[dict[str, str]] = []
        for device in self._devices:
            if isinstance(device, MockDevice):
                result.extend({"ip": ip, "source": device.name} for ip in device.list_all())
        return result

    def get_history(self, limit: int = 50) -> list[dict[str, object]]:
        """Return a defensive snapshot of recent device outcomes."""
        if limit < 0:
            raise ValueError("limit must not be negative")
        with self._lock:
            history = list(self._history[-limit:]) if limit else []
        return [
            {
                "device": item.device_name,
                "ip": item.ip,
                "success": item.success,
                "message": item.message,
                "time": item.timestamp.isoformat(),
            }
            for item in history
        ]

    def get_retry_queue_status(self) -> dict[str, object]:
        """Return a defensive status snapshot for operators."""
        with self._lock:
            items = sorted(self._retry_queue.values(), key=lambda item: item.next_retry_at)
            return {
                "pending": len(items),
                "items": [
                    {
                        "ip": item.decision.ip,
                        **item.decision.site.as_dict(),
                        "reason": item.decision.reason,
                        "devices": list(item.pending_devices),
                        "attempts": item.attempts,
                        "max_attempts": item.max_attempts,
                        "next_retry_at": datetime.fromtimestamp(item.next_retry_at).isoformat(),
                        "last_error": item.last_error,
                    }
                    for item in items[:20]
                ],
                "persistence_error": self._last_persistence_error,
            }

    def device_status(self) -> list[dict[str, object]]:
        """Return names and availability without exposing private device state."""
        return [
            {"name": device.name, "available": device.is_available()}
            for device in self._devices
        ]

    def _execute_block(
        self,
        decision: BlockDecision,
        devices: Sequence[BlockDevice],
    ) -> tuple[list[BlockResult], tuple[str, ...]]:
        results: list[BlockResult] = []
        failed: list[str] = []
        for device in devices:
            try:
                result = device.block(decision)
            except Exception as exc:
                result = BlockResult(device.name, False, str(exc), decision.ip)
            results.append(result)
            if not result.success:
                failed.append(device.name)
        self._append_history(results)
        return results, tuple(failed)

    def _enqueue_retry(
        self,
        decision: BlockDecision,
        failed_devices: tuple[str, ...],
        results: Sequence[BlockResult],
    ) -> None:
        errors = "; ".join(item.message for item in results if not item.success)
        key = f"{decision.site.site_id}|{decision.ip}"
        with self._lock:
            existing = self._retry_queue.get(key)
            if existing is not None:
                existing.pending_devices = tuple(
                    sorted(set(existing.pending_devices) | set(failed_devices))
                )
                existing.last_error = errors or existing.last_error
            else:
                self._retry_queue[key] = RetryItem(
                    decision=decision,
                    pending_devices=failed_devices,
                    attempts=1,
                    max_attempts=self._max_retry_attempts,
                    next_retry_at=time.time() + self._retry_interval,
                    last_error=errors or "Initial block failed",
                )
            self._persist_retry_queue_locked()

    def _retry_loop(self) -> None:
        while not self._stop_event.wait(min(self._retry_interval, 1.0)):
            now = time.time()
            with self._lock:
                due = [item for item in self._retry_queue.values() if item.next_retry_at <= now]
            for item in due:
                try:
                    devices = self._select_devices(item.pending_devices)
                except (IPBlockerDisabledError, ValueError) as exc:
                    self._logger.error("Cannot retry %s: %s", item.key, exc)
                    with self._lock:
                        if self._retry_queue.get(item.key) is item:
                            del self._retry_queue[item.key]
                            self._persist_retry_queue_locked()
                    continue
                results, failed = self._execute_block(item.decision, devices)
                with self._lock:
                    current = self._retry_queue.get(item.key)
                    if current is not item:
                        continue
                    if not failed:
                        del self._retry_queue[item.key]
                    elif item.attempts >= item.max_attempts:
                        self._logger.error(
                            "[RETRY] site=%s ip=%s abandoned after %d attempts",
                            item.decision.site.site_id,
                            item.decision.ip,
                            item.max_attempts,
                        )
                        del self._retry_queue[item.key]
                    else:
                        item.attempts += 1
                        item.pending_devices = failed
                        item.last_error = "; ".join(
                            result.message for result in results if not result.success
                        )
                        item.next_retry_at = now + self._retry_interval * (2 ** (item.attempts - 1))
                    self._persist_retry_queue_locked()

    def _select_devices(
        self,
        names: Collection[str] | None,
    ) -> tuple[BlockDevice, ...]:
        if not self.enabled:
            raise IPBlockerDisabledError("IP blocking is disabled")
        if names is None:
            return self._devices
        requested = {str(name) for name in names}
        selected = tuple(device for device in self._devices if device.name in requested)
        missing = requested - {device.name for device in selected}
        if missing:
            raise ValueError(f"unknown blocking devices: {', '.join(sorted(missing))}")
        if not selected:
            raise ValueError("at least one blocking device must be selected")
        return selected

    @staticmethod
    def _canonical_ips(ips: Sequence[str]) -> tuple[str, ...]:
        if isinstance(ips, (str, bytes)) or not ips:
            raise ValueError("ips must be a non-empty sequence")
        return tuple(dict.fromkeys(canonical_ip(ip) for ip in ips))

    def _append_history(self, results: Sequence[BlockResult]) -> None:
        with self._lock:
            self._history.extend(results)
            del self._history[:-1000]

    def _persist_retry_queue_locked(self) -> None:
        if self._retry_path is None:
            return
        temporary = self._retry_path.with_name(
            f".{self._retry_path.name}.{uuid.uuid4().hex}.tmp"
        )
        payload = [self._retry_to_dict(item) for item in self._retry_queue.values()]
        try:
            self._retry_path.parent.mkdir(parents=True, exist_ok=True)
            temporary.write_text(json.dumps(payload, indent=2), encoding="utf-8")
            os.replace(temporary, self._retry_path)
            self._last_persistence_error = None
        except OSError as exc:
            self._last_persistence_error = str(exc)
            self._logger.warning("Failed to persist IP block retry queue: %s", exc)
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                self._logger.debug("Failed to remove retry queue temp file", exc_info=True)

    def _load_retry_queue_locked(self) -> None:
        if self._retry_path is None or not self._retry_path.exists():
            return
        try:
            raw = json.loads(self._retry_path.read_text(encoding="utf-8"))
            if not isinstance(raw, list):
                raise ValueError("retry queue root must be a list")
            loaded: dict[str, RetryItem] = {}
            for item in raw:
                retry = self._retry_from_dict(item)
                loaded[retry.key] = retry
            self._retry_queue = loaded
            self._last_persistence_error = None
        except (OSError, TypeError, ValueError) as exc:
            self._last_persistence_error = str(exc)
            self._logger.warning("Failed to load IP block retry queue: %s", exc)

    @staticmethod
    def _retry_to_dict(item: RetryItem) -> dict[str, object]:
        return {
            "ip": item.decision.ip,
            **item.decision.site.as_dict(),
            "reason": item.decision.reason,
            "profile_id": item.decision.profile_id,
            "risk_score": item.decision.risk_score,
            "duration_seconds": item.decision.duration_seconds,
            "permanent": item.decision.permanent,
            "pending_devices": list(item.pending_devices),
            "attempts": item.attempts,
            "max_attempts": item.max_attempts,
            "next_retry_at": item.next_retry_at,
            "last_error": item.last_error,
        }

    @staticmethod
    def _retry_from_dict(raw: Mapping[str, Any]) -> RetryItem:
        if not isinstance(raw, Mapping):
            raise ValueError("retry queue item must be an object")
        site = SiteIdentity.from_values(
            str(raw.get("site_id") or "legacy"),
            str(raw.get("site_name") or "Legacy / unassigned"),
        )
        decision = BlockDecision(
            ip=str(raw.get("ip") or ""),
            reason=str(raw.get("reason") or ""),
            site=site,
            profile_id=str(raw.get("profile_id") or ""),
            risk_score=float(raw.get("risk_score", 0.0)),
            duration_seconds=int(raw.get("duration_seconds", 86400)),
            permanent=bool(raw.get("permanent", False)),
        )
        pending = raw.get("pending_devices", ())
        if not isinstance(pending, list) or not pending:
            raise ValueError("retry queue item requires pending_devices")
        return RetryItem(
            decision=decision,
            pending_devices=tuple(str(name) for name in pending),
            attempts=int(raw.get("attempts", 1)),
            max_attempts=int(raw.get("max_attempts", 5)),
            next_retry_at=float(raw.get("next_retry_at", 0.0)),
            last_error=str(raw.get("last_error") or ""),
        )
