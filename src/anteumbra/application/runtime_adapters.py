"""Application-level adapters assembled by the runtime composition root."""

from __future__ import annotations

import logging
from typing import Any, Iterable, Mapping

from anteumbra.domain.runtime import RuntimeContext, RuntimeServices
from anteumbra.infrastructure.runtime_adapters import MetricsAdapter, SuspiciousRegistryAdapter


logger = logging.getLogger(__name__)


class PluginEventPublisher:
    """Adapt the application event bus to the monitor event-publisher port."""

    def publish(self, event_type: str, source: str, payload: Mapping[str, Any]) -> None:
        try:
            from anteumbra.application.plugin_manager import get_plugin_manager

            manager = get_plugin_manager()
            if manager.is_enabled:
                manager.emit(event_type, source, dict(payload))
        except Exception:
            logger.debug(
                "Event publish failed for %s from %s", event_type, source, exc_info=True
            )


def build_runtime_services(
    config: Mapping[str, Any], websites: Iterable[object]
) -> RuntimeServices:
    """Build explicitly wired services for the normal application runtime."""
    context = RuntimeContext.from_websites(config, list(websites))
    return RuntimeServices(
        context=context,
        registry=SuspiciousRegistryAdapter(),
        metrics=MetricsAdapter(),
        events=PluginEventPublisher(),
    )
