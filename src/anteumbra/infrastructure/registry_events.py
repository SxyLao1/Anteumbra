"""Best-effort Registry event and refresh notification adapter."""

from __future__ import annotations

import logging
from collections.abc import Callable, Mapping
from typing import Any

from anteumbra.domain.runtime import EventPublisherPort


class RegistryEventNotifier:
    def __init__(
        self,
        publisher: EventPublisherPort,
        logger: logging.Logger,
        change_callback: Callable[[], Any] | None = None,
    ) -> None:
        self._publisher = publisher
        self._logger = logger
        self._change_callback = change_callback

    def notify(self, event_type: str, payload: Mapping[str, Any]) -> None:
        try:
            self._publisher.publish(event_type, "suspicious_registry", dict(payload))
        except Exception:
            self._logger.warning("Registry event publish failed: %s", event_type, exc_info=True)
        if self._change_callback is not None:
            try:
                self._change_callback()
            except Exception:
                self._logger.warning("Registry change callback failed", exc_info=True)
