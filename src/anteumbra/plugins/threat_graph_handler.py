# -*- coding: utf-8 -*-
"""
v2.0: Threat Graph Handler Plugin — bridges event bus to ThreatGraph engine.

Subscribes to ``record_added`` and ``registry_changed`` events and forwards
them to ``ThreatGraph.ingest_registry_entry()``.  This eliminates the need
for monitor.py to call threat_graph directly — the graph stays in sync
automatically via the event bus.

When a significant profile change is detected (new profile created or
risk score crosses threshold), emits ``threat_graph_updated``.
"""
import logging
import time
from typing import List, Optional, Dict, Any

from anteumbra.domain import DomainEvent, Plugin
from anteumbra.domain.runtime import EventPublisherPort


class ThreatGraphHandlerPlugin(Plugin):
    """Bridge plugin: subscribes to registry events and updates ThreatGraph."""

    def __init__(
        self,
        graph: object,
        events: EventPublisherPort,
        *,
        log: logging.Logger,
    ) -> None:
        self._graph = graph
        self._events = events
        self._logger = log

    @property
    def name(self) -> str:
        return "threat_graph_handler"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def supported_events(self) -> List[str]:
        return ["record_added", "registry_changed"]

    def activate(self, config: Dict[str, Any]) -> None:
        self._profile_count_before = 0
        self._logger.info("ThreatGraphHandler: 已激活")

    def deactivate(self) -> None:
        self._logger.info("ThreatGraphHandler: 已停用")

    def on_event(self, event: DomainEvent) -> Optional[List[DomainEvent]]:
        """Forward record_added / registry_changed to ThreatGraph."""
        payload = event.payload or {}

        # Build an entry dict that ingest_registry_entry understands
        entry = {
            "file_path": payload.get("file_path", ""),
            "features": payload.get("features", []),
            "first_seen_ip": payload.get("first_seen_ip", "127.0.0.1"),
            "detected_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "detection_source": payload.get("detection_source", "passive"),
        }
        # registry_changed carries flat fields — extract quota/file state directly
        for key in ("quarantine_id", "file_exists", "marked_false_positive"):
            if key in payload:
                entry[key] = payload[key]

        try:
            graph = self._graph
            old_count = len(graph.get_active_profiles())
            graph.ingest_registry_entry(entry)
            new_count = len(graph.get_active_profiles())

            # Emit threat_graph_updated if a new profile was created
            if new_count > old_count:
                self._emit_updated(graph)
        except Exception as e:
            self._logger.warning("ThreatGraphHandler: ingest_registry_entry 失败: %s", e)

        return None

    # -- Internal --

    def _emit_updated(self, graph) -> None:
        """Emit threat_graph_updated through the injected runtime port."""
        try:
            active = graph.get_active_profiles()
            self._events.publish("threat_graph_updated", self.name, {
                "active_profile_count": len(active),
                "top_profile_id": active[0].profile_id if active else None,
                "top_risk_score": active[0].risk_score if active else 0,
            })
        except Exception:
            self._logger.debug("ThreatGraphHandler: _emit_updated failed", exc_info=True)
