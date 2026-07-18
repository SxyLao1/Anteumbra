"""Application-level adapters assembled by the runtime composition root."""

from __future__ import annotations

from typing import Iterable, Mapping

from anteumbra.domain.runtime import EventPublisherPort, RuntimeContext, RuntimeServices
from anteumbra.infrastructure.runtime_adapters import MetricsAdapter, SuspiciousRegistryAdapter


def build_runtime_services(
    config: Mapping[str, object],
    websites: Iterable[object],
    *,
    event_publisher: EventPublisherPort,
    metrics,
) -> RuntimeServices:
    """Build explicitly wired services for the normal application runtime."""
    context = RuntimeContext.from_websites(config, list(websites))
    return RuntimeServices(
        context=context,
        registry=SuspiciousRegistryAdapter(event_publisher),
        metrics=MetricsAdapter(metrics),
        events=event_publisher,
    )
