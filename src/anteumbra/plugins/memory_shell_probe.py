# -*- coding: utf-8 -*-
"""Memory-shell detection plugin.

A file-based webshell can be deleted; a memory shell cannot, because it never
existed as a file. This plugin therefore reacts to a detection by asking the
servlet container itself what it has registered in memory, using a short-lived
probe that Anteumbra deploys and removes on its own.

It deliberately owns no policy: the injected service decides whether a site is
eligible, whether the cooldown has elapsed, how long the probe may live, and
what to do with the findings. The plugin only translates the event bus into
that service.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from anteumbra.domain.plugin import DomainEvent, Plugin

# Alerts that mean "a webshell was seen here" and therefore justify a probe.
TRIGGER_ALERT_TYPES = frozenset({"local_detection", "webshell_access"})


class MemoryShellProbePlugin(Plugin):
    """Probe the servlet container's memory after a webshell detection."""

    def __init__(self, service: Any, *, log: logging.Logger | None = None) -> None:
        self._service = service
        self._logger = log or logging.getLogger(__name__)
        self._enabled = True

    # ── Plugin contract ─────────────────────────────────────────────
    @property
    def name(self) -> str:
        return "memory_shell_probe"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def supported_events(self) -> List[str]:
        return ["alert_requested"]

    def activate(self, config: Dict[str, Any]) -> None:
        self._enabled = bool(config.get("enabled", True))
        self._logger.info(
            "Memory-shell plugin %s (auto probe on detection: %s)",
            "enabled" if self._enabled else "disabled",
            config.get("auto_probe_on_detection", True),
        )

    def deactivate(self) -> None:
        self._logger.info("Memory-shell plugin deactivated")

    def on_event(self, event: DomainEvent) -> Optional[List[DomainEvent]]:
        if not self._enabled or event.event_type != "alert_requested":
            return None
        payload = event.payload or {}
        alert_type = str(payload.get("alert_type") or "")
        if alert_type not in TRIGGER_ALERT_TYPES:
            return None
        try:
            self._service.handle_detection(payload)
        except Exception:  # noqa: BLE001 - a probe must never break alerting
            self._logger.exception("Memory-shell auto probe failed")
        return None
