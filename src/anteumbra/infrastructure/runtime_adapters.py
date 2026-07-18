"""Concrete adapters wired by the launcher into the monitoring pipeline."""

from __future__ import annotations

import logging
import threading
from pathlib import Path
from typing import Any, Iterable, Mapping

from anteumbra.domain.runtime import EventPublisherPort, RuntimeContext, RuntimeServices
from anteumbra.domain.site import SiteIdentity


logger = logging.getLogger(__name__)


class SuspiciousRegistryAdapter:
    """Adapt the legacy registry module to the explicit detection port."""

    def __init__(self, event_publisher: EventPublisherPort) -> None:
        self._events = event_publisher

    def add(
        self,
        file_path: Path,
        features: list[str],
        *,
        first_seen_ip: str | None,
        detection_source: str,
        site: SiteIdentity,
    ) -> None:
        from anteumbra.infrastructure.suspicious_registry import add

        add(
            file_path,
            features,
            first_seen_ip=first_seen_ip,
            detection_source=detection_source,
            site_id=site.site_id,
            site_name=site.site_name,
            event_publisher=self._events,
        )

    def remove(self, file_path: Path, *, site: SiteIdentity) -> bool:
        """Mark a Registry record removed without crossing site boundaries."""
        from anteumbra.infrastructure.suspicious_registry import remove

        return remove(
            file_path,
            site_id=site.site_id,
            event_publisher=self._events,
        )


class MetricsAdapter:
    """Adapt the process metrics singleton to the injected metrics port."""

    def __init__(self, metrics) -> None:
        self._metrics = metrics

    def increment(
        self,
        metric: str,
        value: int = 1,
        *,
        site_id: str | None = None,
    ) -> None:
        self._metrics.increment(metric, value, site_id=site_id)

    def increment_site(self, metric: str, site_id: str, value: int = 1) -> None:
        """Record site-only data for legacy producers that already increment totals."""
        self._metrics.increment_site(metric, site_id, value)


class NullEventPublisher:
    """Compatibility publisher for monitors created outside the composition root."""

    def publish(self, event_type: str, source: str, payload: Mapping[str, Any]) -> None:
        logger.debug("Ignoring uncomposed event %s from %s", event_type, source)


class EventPublisherRouter:
    """Route events to a late-bound publisher without process-global state."""

    def __init__(self, publisher: EventPublisherPort | None = None) -> None:
        self._lock = threading.RLock()
        self._publisher = publisher

    def bind(self, publisher: EventPublisherPort | None) -> None:
        with self._lock:
            self._publisher = publisher

    def publish(self, event_type: str, source: str, payload: Mapping[str, Any]) -> None:
        with self._lock:
            publisher = self._publisher
        if publisher is None:
            logger.debug("Ignoring uncomposed event %s from %s", event_type, source)
            return
        publisher.publish(event_type, source, payload)


def build_compatibility_runtime_services(
    config: Mapping[str, Any], websites: Iterable[object]
) -> RuntimeServices:
    """Build minimal infrastructure-only services for legacy direct construction."""
    from anteumbra.infrastructure.monitoring.metrics import get_metrics

    context = RuntimeContext.from_websites(config, list(websites))
    return RuntimeServices(
        context=context,
        registry=SuspiciousRegistryAdapter(NullEventPublisher()),
        metrics=MetricsAdapter(get_metrics()),
        events=NullEventPublisher(),
    )
