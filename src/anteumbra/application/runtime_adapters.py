"""Application-level adapters assembled by the runtime composition root."""

from __future__ import annotations

from typing import Iterable, Mapping

from anteumbra.domain.quarantine import QuarantineGuardPort
from anteumbra.domain.runtime import (
    DetectionRegistryPort,
    EventPublisherPort,
    MetricsPort,
    RuntimeContext,
    RuntimeServices,
)


def build_runtime_services(
    config: Mapping[str, object],
    websites: Iterable[object],
    *,
    event_publisher: EventPublisherPort,
    registry: DetectionRegistryPort,
    metrics: MetricsPort,
    quarantine: QuarantineGuardPort,
) -> RuntimeServices:
    """Build explicitly wired services for the normal application runtime."""
    context = RuntimeContext.from_websites(config, list(websites))
    return RuntimeServices(
        context=context,
        registry=registry,
        metrics=metrics,
        events=event_publisher,
        quarantine=quarantine,
    )
