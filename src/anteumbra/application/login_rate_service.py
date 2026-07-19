"""Runtime-owned login attempt throttling."""

from __future__ import annotations

import math
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass


@dataclass(frozen=True)
class LoginRateDecision:
    """Result of recording one login attempt."""

    allowed: bool
    retry_after_seconds: int = 0


class LoginRateLimiter:
    """Apply a fixed-window attempt limit without process-global state."""

    def __init__(
        self,
        *,
        window_seconds: float = 60.0,
        max_attempts: int = 5,
        clock: Callable[[], float] | None = None,
    ) -> None:
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        if max_attempts <= 0:
            raise ValueError("max_attempts must be positive")
        self.window_seconds = float(window_seconds)
        self.max_attempts = int(max_attempts)
        self._clock = clock or time.monotonic
        self._attempts: dict[str, tuple[int, float]] = {}
        self._lock = threading.RLock()

    def check_and_record(self, client_key: str) -> LoginRateDecision:
        """Record one attempt and return whether it may proceed."""
        key = str(client_key or "unknown").strip() or "unknown"
        now = self._clock()
        with self._lock:
            self._remove_expired(now)
            count, started_at = self._attempts.get(key, (0, now))
            if now - started_at >= self.window_seconds:
                count, started_at = 0, now
            if count >= self.max_attempts:
                retry_after = max(
                    1,
                    math.ceil(self.window_seconds - (now - started_at)),
                )
                return LoginRateDecision(False, retry_after)
            self._attempts[key] = (count + 1, started_at)
            return LoginRateDecision(True)

    def reset(self, client_key: str | None = None) -> None:
        """Clear one client's attempts, or all attempts when no key is supplied."""
        with self._lock:
            if client_key is None:
                self._attempts.clear()
            else:
                key = str(client_key or "unknown").strip() or "unknown"
                self._attempts.pop(key, None)

    def _remove_expired(self, now: float) -> None:
        expired = [
            key
            for key, (_count, started_at) in self._attempts.items()
            if now - started_at >= self.window_seconds
        ]
        for key in expired:
            del self._attempts[key]
