# -*- coding: utf-8 -*-
"""Tracks files Anteumbra creates inside directories it is watching.

The memory-shell probe has an awkward property: the defender's own tool writes
a file into the very web root the defender is guarding, then requests it over
HTTP. Both actions look exactly like an intrusion, so both must be recognised
as self-inflicted without weakening detection for anything else.

Two design rules keep this honest:

* Registration is *time boxed*. An entry lives only for the probe run (a few
  seconds), so it can never become a permanent blind spot.
* Matching is by recorded path and URL fragment, never by a name pattern. A
  name pattern such as ``*probe*`` would be a documented bypass: an attacker
  could simply name a webshell ``probe-x.jsp``.
"""

from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

DEFAULT_TTL_SECONDS = 180.0


def normalize_path(path: str | Path) -> str:
    """Case-folded absolute path, so Windows spelling differences match."""
    try:
        return os.path.normcase(os.path.abspath(str(path)))
    except (OSError, ValueError):  # pragma: no cover - defensive
        return os.path.normcase(str(path))


@dataclass(frozen=True)
class _Entry:
    path: str
    url_fragment: str
    expires_at: float


class InMemoryInternalArtifactRegistry:
    """Thread-safe, time-boxed registry of Anteumbra's own artifacts."""

    def __init__(
        self,
        *,
        clock: Callable[[], float] = time.monotonic,
        default_ttl: float = DEFAULT_TTL_SECONDS,
    ) -> None:
        self._lock = threading.RLock()
        self._entries: dict[str, _Entry] = {}
        self._clock = clock
        self._default_ttl = float(default_ttl)

    # ── registration ────────────────────────────────────────────────
    def register(
        self,
        *,
        path: str | Path,
        url_fragment: str,
        ttl: float | None = None,
    ) -> None:
        """Mark one path (probe file or its directory) as self-created."""
        key = normalize_path(path)
        lifetime = self._default_ttl if ttl is None else float(ttl)
        entry = _Entry(
            path=key,
            url_fragment=(url_fragment or "").strip(),
            expires_at=self._clock() + max(lifetime, 0.0),
        )
        with self._lock:
            self._entries[key] = entry

    def release(self, path: str | Path) -> None:
        """Drop an entry as soon as the artifact is gone."""
        key = normalize_path(path)
        with self._lock:
            self._entries.pop(key, None)

    def release_url_fragment(self, url_fragment: str) -> None:
        fragment = (url_fragment or "").strip()
        if not fragment:
            return
        with self._lock:
            for key, entry in list(self._entries.items()):
                if entry.url_fragment == fragment:
                    self._entries.pop(key, None)

    # ── queries ─────────────────────────────────────────────────────
    def is_internal_path(self, path: str | Path) -> bool:
        """True for a registered path or anything inside a registered directory."""
        key = normalize_path(path)
        with self._lock:
            self._purge_locked()
            if key in self._entries:
                return True
            for entry in self._entries.values():
                if entry.path.endswith(os.sep) and key.startswith(entry.path):
                    return True
                if key.startswith(entry.path + os.sep):
                    return True
        return False

    def contains_url(self, url: str) -> bool:
        if not url:
            return False
        with self._lock:
            self._purge_locked()
            fragments = [entry.url_fragment for entry in self._entries.values()]
        return any(fragment and fragment in url for fragment in fragments)

    def snapshot(self) -> list[dict[str, object]]:
        """Current entries, for diagnostics and tests."""
        with self._lock:
            self._purge_locked()
            now = self._clock()
            return [
                {
                    "path": entry.path,
                    "url_fragment": entry.url_fragment,
                    "ttl_remaining": round(max(entry.expires_at - now, 0.0), 3),
                }
                for entry in self._entries.values()
            ]

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()

    # ── internals ───────────────────────────────────────────────────
    def _purge_locked(self) -> None:
        now = self._clock()
        expired = [key for key, entry in self._entries.items() if entry.expires_at <= now]
        for key in expired:
            self._entries.pop(key, None)


__all__ = [
    "DEFAULT_TTL_SECONDS",
    "InMemoryInternalArtifactRegistry",
    "normalize_path",
]
