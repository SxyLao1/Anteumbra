"""Runtime-owned state for manual scan jobs and in-memory results."""

from __future__ import annotations

import threading
import time
from typing import Any


class ScanRuntimeState:
    """Coordinate manual scan jobs without process-global dictionaries."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._jobs: dict[str, dict[str, Any]] = {}
        self._results: dict[str, Any] = {}
        self._closed = False

    def register_job(self, scan_id: str, job: dict[str, Any]) -> None:
        """Register a newly created scan job."""
        with self._lock:
            if self._closed:
                raise RuntimeError("scan runtime state is closed")
            if scan_id in self._jobs:
                raise ValueError(f"duplicate scan job: {scan_id}")
            self._jobs[scan_id] = job

    def get_job(self, scan_id: str) -> dict[str, Any] | None:
        """Return a shallow job snapshot."""
        with self._lock:
            job = self._jobs.get(scan_id)
            return dict(job) if job is not None else None

    def update_job(self, scan_id: str, **changes: Any) -> bool:
        """Apply one atomic set of job field changes."""
        with self._lock:
            job = self._jobs.get(scan_id)
            if job is None:
                return False
            job.update(changes)
            return True

    def cleanup_jobs(self, max_age: float, *, now: float | None = None) -> int:
        """Remove completed jobs older than the retention window."""
        cutoff = (time.time() if now is None else now) - max(0.0, max_age)
        with self._lock:
            stale = [
                scan_id
                for scan_id, job in self._jobs.items()
                if job.get("completed_at") is not None
                and float(job["completed_at"]) < cutoff
            ]
            for scan_id in stale:
                del self._jobs[scan_id]
            return len(stale)

    def cancel(self, scan_id: str | None = None) -> int:
        """Signal cancellation for one active job or every active job."""
        with self._lock:
            if self._closed:
                return 0
            jobs = (
                [self._jobs.get(scan_id)]
                if scan_id
                else list(self._jobs.values())
            )
            cancelled = 0
            for job in jobs:
                if job and job.get("completed_at") is None:
                    job["cancel_flag"]["cancelled"] = True
                    cancelled += 1
            return cancelled

    def put_result(self, scan_id: str, result: Any) -> bool:
        """Cache a completed result while this runtime remains active."""
        with self._lock:
            if self._closed:
                return False
            self._results[scan_id] = result
            return True

    def get_result(self, scan_id: str) -> Any | None:
        """Return one cached scan result."""
        with self._lock:
            return self._results.get(scan_id)

    def cleanup_results(
        self,
        max_age: float,
        *,
        now: float | None = None,
    ) -> int:
        """Remove completed results older than the retention window."""
        reference = time.time() if now is None else now
        with self._lock:
            stale = [
                scan_id
                for scan_id, result in self._results.items()
                if getattr(result, "end_time", None) is not None
                and reference - float(result.end_time) > max(0.0, max_age)
            ]
            for scan_id in stale:
                del self._results[scan_id]
            return len(stale)

    def shutdown(self, timeout: float = 5.0) -> None:
        """Cancel active jobs, wait briefly for workers, and release state."""
        with self._lock:
            if self._closed:
                return
            self._closed = True
            jobs = list(self._jobs.values())
            for job in jobs:
                if job.get("completed_at") is None:
                    job["cancel_flag"]["cancelled"] = True

        deadline = time.monotonic() + max(0.0, timeout)
        current = threading.current_thread()
        for job in jobs:
            thread = job.get("thread")
            if (
                thread is None
                or thread is current
                or not thread.is_alive()
            ):
                continue
            thread.join(timeout=max(0.0, deadline - time.monotonic()))

        with self._lock:
            self._jobs.clear()
            self._results.clear()


__all__ = ["ScanRuntimeState"]
