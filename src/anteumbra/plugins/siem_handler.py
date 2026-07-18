"""Bridge Registry detections to the configured SIEM exporter."""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from anteumbra.domain import DomainEvent, Plugin


logger = logging.getLogger(__name__)


class SIEMHandlerPlugin(Plugin):
    """Export every suspicious-registry detection without coupling Registry to SIEM."""

    def __init__(self, exporter: object) -> None:
        self._exporter = exporter

    @property
    def name(self) -> str:
        return "siem_handler"

    @property
    def supported_events(self) -> List[str]:
        return ["record_added"]

    def activate(self, config: Dict[str, Any]) -> None:
        self._enabled = bool(config.get("enabled", True))
        logger.info("SIEMHandler: %s", "enabled" if self._enabled else "disabled")

    def deactivate(self) -> None:
        logger.info("SIEMHandler: stopped")

    def on_event(self, event: DomainEvent) -> Optional[List[DomainEvent]]:
        if not getattr(self, "_enabled", True):
            return None
        try:
            self._exporter.emit_detection(dict(event.payload or {}))
        except Exception:
            logger.exception("SIEMHandler: failed to export record_added event")
        return None
