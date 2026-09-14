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

from anteumbra.domain.memory_shell import (
    DEFAULT_FORENSICS_HISTORY,
    DEFAULT_FORENSICS_MAX_DUMP_MB,
    DEFAULT_FORENSICS_TIMEOUT_SECONDS,
)
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

    @classmethod
    def config_schema(cls) -> List[Dict[str, Any]]:
        """``[plugins.memory_shell_probe]``: the settings this plugin's service reads.

        The injected service owns the policy and reads the same keys from
        ``[plugins.memory_shell_probe]`` (``MemoryShellService.DEFAULT_CONFIG``),
        so the defaults and bounds declared here mirror the ones the probe
        actually applies - including the cooldown, the probe timeouts and the
        forensics budgets, which were previously reachable only by hand-editing
        ``config.toml``.
        """
        return [
            {
                "name": "enabled",
                "type": "toggle",
                "default": True,
                "label": "Probe enabled",
                "description": (
                    "Master switch: off means neither automatic nor manual "
                    "probing is performed."
                ),
            },
            {
                "name": "auto_probe_on_detection",
                "type": "toggle",
                "default": True,
                "label": "Probe automatically on detection",
                "description": (
                    "After a webshell detection, ask the servlet container of the "
                    "same site what it has registered in memory."
                ),
            },
            {
                "name": "trigger_extensions",
                "type": "list",
                "default": [".jsp", ".jspx", ".jspf", ".jsw", ".jsv"],
                "label": "Trigger extensions",
                "description": "File extensions that make a detection probe-worthy.",
            },
            {
                "name": "site_ids",
                "type": "list",
                "default": [],
                "label": "Sites to probe",
                "description": (
                    "site_id list; empty means every enabled site. Site ids use "
                    "lowercase letters, digits and dashes."
                ),
                "item_pattern": r"^[a-z0-9][a-z0-9_-]*$",
                "item_pattern_hint": "a lowercase site id",
            },
            {
                "name": "cooldown_seconds",
                "type": "number",
                "default": 300,
                "min": 0,
                "max": 86400,
                "label": "Cooldown between probes (seconds)",
                "description": "Minimum interval between two probes of the same site.",
            },
            {
                "name": "http_timeout_seconds",
                "type": "number",
                "default": 8,
                "min": 1,
                "max": 600,
                "label": "Probe HTTP timeout (seconds)",
                "description": "Budget for the single request that reads the probe back.",
            },
            {
                "name": "artifact_ttl_seconds",
                "type": "number",
                "default": 120,
                "min": 1,
                "max": 86400,
                "label": "Probe artifact TTL (seconds)",
                "description": (
                    "How long the probe file may stay in the registry as a fallback; "
                    "the normal path removes it when the probe ends."
                ),
            },
            {
                "name": "directory_prefix",
                "type": "text",
                "default": "mb-",
                "required": True,
                "allow_empty": False,
                "pattern": r"^[A-Za-z0-9_-]{1,32}$",
                "pattern_hint": "1-32 letters, digits, dashes or underscores",
                "label": "Probe directory prefix",
                "description": "Prefix of the randomly named directory written under the site root.",
            },
            {
                "name": "history_size",
                "type": "number",
                "default": 50,
                "min": 1,
                "max": 1000,
                "label": "Probe history kept",
                "description": "Probe records the panel keeps for review.",
            },
            {
                "name": "alert_on_suspects",
                "type": "toggle",
                "default": True,
                "label": "Alert on suspicious components",
                "description": "Raise an alert when the probe finds suspicious in-memory components.",
            },
            {
                "name": "host",
                "type": "text",
                "default": "127.0.0.1",
                "required": True,
                "allow_empty": False,
                "pattern": r"^[A-Za-z0-9._-]+$",
                "pattern_hint": "a host name or IP address",
                "label": "Probe host",
                "description": "Host used to reach the probe over HTTP.",
            },
            {
                "name": "scheme",
                "type": "select",
                "default": "http",
                "choices": ("http", "https"),
                "label": "Probe scheme",
                "description": "Scheme used for the probe request.",
            },
            {
                "name": "forensics_enabled",
                "type": "toggle",
                "default": True,
                "label": "Forensics enabled",
                "description": "Allow evidence collection from a probed container.",
            },
            {
                "name": "heap_dump_enabled",
                "type": "toggle",
                "default": True,
                "label": "Heap dumps enabled",
                "description": (
                    "Allow a heap dump as part of forensics; it is the slowest and "
                    "most resource-hungry action the probe can take."
                ),
            },
            {
                "name": "forensics_history",
                "type": "number",
                "default": DEFAULT_FORENSICS_HISTORY,
                "min": 1,
                "max": 10000,
                "label": "Forensics records kept",
                "description": "How many forensics entries the store retains.",
            },
            {
                "name": "forensics_max_dump_mb",
                "type": "number",
                "default": DEFAULT_FORENSICS_MAX_DUMP_MB,
                "min": 1,
                "max": 102400,
                "label": "Max heap dump size (MB)",
                "description": "Dumps larger than this are refused before they fill the disk.",
            },
            {
                "name": "forensics_timeout_seconds",
                "type": "number",
                "default": DEFAULT_FORENSICS_TIMEOUT_SECONDS,
                "min": 1,
                "max": 3600,
                "label": "Forensics request timeout (seconds)",
                "description": (
                    "Budget for a dump or kill request; a heap dump answers slowly, "
                    "so this is separate from the plain probe timeout."
                ),
            },
        ]

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
