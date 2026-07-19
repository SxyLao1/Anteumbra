"""Concrete runtime adapters assembled only by the composition root."""

from __future__ import annotations

import logging
import threading
from typing import Any, Mapping

from anteumbra.domain.runtime import EventPublisherPort


logger = logging.getLogger(__name__)


class EventPublisherRouter:
    """Route events to a late-bound publisher without process-global state."""

    def __init__(self, publisher: EventPublisherPort | None = None) -> None:
        self._lock = threading.RLock()
        self._publisher = publisher

    def bind(self, publisher: EventPublisherPort | None) -> None:
        """Replace the target event bus atomically."""
        with self._lock:
            self._publisher = publisher

    def publish(
        self,
        event_type: str,
        source: str,
        payload: Mapping[str, Any],
    ) -> None:
        """Publish to the bound bus, or log when startup has not bound it yet."""
        with self._lock:
            publisher = self._publisher
        if publisher is None:
            logger.debug("Ignoring unbound event %s from %s", event_type, source)
            return
        publisher.publish(event_type, source, payload)
