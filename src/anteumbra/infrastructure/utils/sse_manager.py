"""Runtime-owned Server-Sent Events client and log history manager."""

from __future__ import annotations

import json
import logging
import os
import queue
import threading
from collections import deque
from pathlib import Path
from typing import Any

from anteumbra.domain.runtime import ConfigProviderPort


class SSECapacityError(RuntimeError):
    """Raised when an SSE connection would exceed configured limits."""


class LogBuffer:
    """Bounded, thread-safe log history persisted with atomic replacement."""

    def __init__(
        self,
        path: str | Path,
        *,
        max_size: int = 100,
        logger: logging.Logger | None = None,
    ) -> None:
        if max_size < 1:
            raise ValueError("max_size must be positive")
        self.path = Path(path)
        self.max_size = max_size
        self._logger = logger or logging.getLogger("monitor.sse")
        self._items: deque[str] = deque(maxlen=max_size)
        self._lock = threading.RLock()
        self._load()

    def push(self, log_line: str) -> bool:
        """Persist a new line, returning false when it is already buffered."""
        line = str(log_line).strip()
        if not line:
            return False
        with self._lock:
            if line in self._items:
                return False
            self._items.append(line)
            self._save_locked()
            return True

    def get_all(self) -> list[str]:
        """Return a defensive snapshot ordered from oldest to newest."""
        with self._lock:
            return list(self._items)

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            value = json.loads(self.path.read_text(encoding="utf-8"))
            if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
                raise ValueError("log buffer must be a JSON array of strings")
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            corrupt = self.path.with_name(f"{self.path.name}.corrupt")
            try:
                os.replace(self.path, corrupt)
            except OSError:
                self._logger.error(
                    "Cannot preserve corrupt SSE log history at %s",
                    self.path,
                    exc_info=True,
                )
            self._logger.warning("SSE log history was corrupt and moved to %s: %s", corrupt, exc)
            return
        with self._lock:
            self._items.extend(value[-self.max_size :])

    def _save_locked(self) -> None:
        temporary = self.path.with_name(f".{self.path.name}.tmp")
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            temporary.write_text(
                json.dumps(list(self._items), ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            os.replace(temporary, self.path)
        except OSError:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                self._logger.debug("Cannot remove temporary SSE buffer", exc_info=True)
            raise


class SSEManager:
    """Own SSE clients, update fan-out, worker lifetime, and log history."""

    _STOP = object()
    _REGISTRY_UPDATE = "registry_update"

    def __init__(
        self,
        config: ConfigProviderPort,
        log_buffer_path: str | Path,
        *,
        log_buffer_size: int = 100,
        client_queue_size: int = 100,
        logger: logging.Logger | None = None,
    ) -> None:
        if client_queue_size < 1:
            raise ValueError("client_queue_size must be positive")
        self._config = config
        self._logger = logger or logging.getLogger("monitor.sse")
        self._client_queue_size = client_queue_size
        self._updates: queue.Queue[object] = queue.Queue(maxsize=1)
        self._clients: list[queue.Queue[str | None]] = []
        self._clients_lock = threading.RLock()
        self._lifecycle_lock = threading.RLock()
        self._stop_event = threading.Event()
        self._worker: threading.Thread | None = None
        self._log_buffer = LogBuffer(
            log_buffer_path,
            max_size=log_buffer_size,
            logger=self._logger,
        )

    @property
    def is_running(self) -> bool:
        """Return whether the fan-out worker is alive."""
        with self._lifecycle_lock:
            return bool(self._worker and self._worker.is_alive())

    @property
    def worker(self) -> threading.Thread | None:
        """Expose the owned thread for diagnostics and lifecycle tests."""
        with self._lifecycle_lock:
            return self._worker

    def get_limits(self) -> dict[str, int]:
        """Read connection limits from the hot-reloadable provider."""
        web_admin = self._config.get().get("web_admin", {})
        return {
            "per_ip": self._positive_int(web_admin.get("sse_max_clients_per_ip", 5), "per_ip"),
            "total": self._positive_int(web_admin.get("sse_max_total_clients", 20), "total"),
        }

    def start(self) -> None:
        """Start the fan-out worker once."""
        with self._lifecycle_lock:
            if self._worker is not None and self._worker.is_alive():
                return
            self._drain_updates()
            self._stop_event.clear()
            self._worker = threading.Thread(
                target=self._run,
                daemon=True,
                name="RegistrySSEWorker",
            )
            self._worker.start()

    def stop(self, timeout: float = 2.0) -> bool:
        """Stop the worker and disconnect all clients within a bound."""
        with self._lifecycle_lock:
            worker = self._worker
            self._stop_event.set()
            self._drain_updates()
            self._updates.put_nowait(self._STOP)

        if worker is not None and worker is not threading.current_thread():
            worker.join(timeout=max(0.0, timeout))
        stopped = worker is None or not worker.is_alive()
        self.cleanup_connections()

        with self._lifecycle_lock:
            if self._worker is worker and stopped:
                self._worker = None
        return stopped

    def register_client(self, client_ip: str | None = None) -> queue.Queue[str | None]:
        """Register one bounded client queue while enforcing current limits."""
        normalized_ip = str(client_ip or "").strip()
        limits = self.get_limits()
        with self._clients_lock:
            if len(self._clients) >= limits["total"]:
                raise SSECapacityError("SSE total client limit reached")
            if normalized_ip and self._count_ip_locked(normalized_ip) >= limits["per_ip"]:
                raise SSECapacityError(f"SSE client limit reached for IP {normalized_ip}")
            client: queue.Queue[str | None] = queue.Queue(maxsize=self._client_queue_size)
            client.client_ip = normalized_ip  # type: ignore[attr-defined]
            self._clients.append(client)
            return client

    def unregister_client(
        self,
        client: queue.Queue[str | None],
        *,
        drain: bool = True,
    ) -> bool:
        """Remove one client and optionally drain stale signals."""
        with self._clients_lock:
            if client not in self._clients:
                return False
            self._clients.remove(client)
        if drain:
            self._drain_client(client)
        return True

    def cleanup_connections(self, client_ip: str | None = None) -> int:
        """Disconnect all clients, or only clients belonging to one IP."""
        normalized_ip = str(client_ip or "").strip()
        with self._clients_lock:
            selected = [
                client
                for client in self._clients
                if not normalized_ip or getattr(client, "client_ip", "") == normalized_ip
            ]
            for client in selected:
                self._clients.remove(client)

        for client in selected:
            self._drain_client(client)
            try:
                client.put_nowait(None)
            except queue.Full:
                self._logger.error("Cannot signal SSE client disconnect")
        return len(selected)

    def trigger_registry_update(self) -> bool:
        """Coalesce and queue a Registry update notification."""
        try:
            self._updates.put_nowait(self._REGISTRY_UPDATE)
            return True
        except queue.Full:
            return False

    def connected_client_count(self) -> int:
        """Return the total registered client count."""
        with self._clients_lock:
            return len(self._clients)

    def ip_client_count(self, client_ip: str) -> int:
        """Return the registered client count for one IP."""
        with self._clients_lock:
            return self._count_ip_locked(str(client_ip).strip())

    def ip_clients(self, client_ip: str) -> list[queue.Queue[str | None]]:
        """Return a defensive list of queues registered to one IP."""
        normalized_ip = str(client_ip).strip()
        with self._clients_lock:
            return [
                client
                for client in self._clients
                if getattr(client, "client_ip", "") == normalized_ip
            ]

    def remove_dead_clients(self, clients: list[queue.Queue[str | None]]) -> int:
        """Remove queues that could not accept a fan-out signal."""
        removed = 0
        with self._clients_lock:
            for client in clients:
                if client in self._clients:
                    self._clients.remove(client)
                    removed += 1
        return removed

    def persist_log_line(self, log_line: str) -> bool:
        """Append one unique log line to persistent history."""
        return self._log_buffer.push(log_line)

    def get_log_buffer(self) -> list[str]:
        """Return all persisted history lines."""
        return self._log_buffer.get_all()

    def _run(self) -> None:
        self._logger.debug("SSE fan-out worker started")
        while not self._stop_event.is_set():
            try:
                signal = self._updates.get(timeout=0.5)
            except queue.Empty:
                continue
            if signal is self._STOP:
                break
            if signal != self._REGISTRY_UPDATE:
                self._logger.warning("Ignoring unknown SSE signal: %r", signal)
                continue

            with self._clients_lock:
                clients = list(self._clients)
            dead: list[queue.Queue[str | None]] = []
            for client in clients:
                try:
                    client.put_nowait(self._REGISTRY_UPDATE)
                except queue.Full:
                    dead.append(client)
            if dead:
                self.remove_dead_clients(dead)
                self._logger.warning("Removed %d stalled SSE clients", len(dead))
        self._logger.debug("SSE fan-out worker stopped")

    def _count_ip_locked(self, client_ip: str) -> int:
        return sum(1 for client in self._clients if getattr(client, "client_ip", "") == client_ip)

    def _drain_updates(self) -> None:
        try:
            while True:
                self._updates.get_nowait()
        except queue.Empty:
            return

    @staticmethod
    def _drain_client(client: queue.Queue[str | None]) -> None:
        try:
            while True:
                client.get_nowait()
        except queue.Empty:
            return

    @staticmethod
    def _positive_int(value: Any, name: str) -> int:
        try:
            parsed = int(str(value).split("#", 1)[0].strip())
        except (TypeError, ValueError) as exc:
            raise ValueError(f"invalid SSE {name} limit: {value!r}") from exc
        if parsed < 1:
            raise ValueError(f"SSE {name} limit must be positive")
        return parsed
