"""Runtime dependency contracts used by the monitoring execution pipeline."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Protocol

from anteumbra.domain.site import SiteIdentity, SiteResolver


class DetectionRegistryPort(Protocol):
    """Persist detected files with their explicit site ownership."""

    def add(
        self,
        file_path: Path,
        features: list[str],
        *,
        first_seen_ip: str | None,
        detection_source: str,
        site: SiteIdentity,
    ) -> None:
        """Store or update a suspicious-file record."""

    def remove(self, file_path: Path, *, site: SiteIdentity) -> bool:
        """Mark a suspicious-file record as removed within its site boundary."""


class MetricsPort(Protocol):
    """Record an aggregate metric and, when supplied, its site bucket."""

    def increment(
        self,
        metric: str,
        value: int = 1,
        *,
        site_id: str | None = None,
    ) -> None:
        """Increment one metric."""

    def increment_site(self, metric: str, site_id: str, value: int = 1) -> None:
        """Increment only the site bucket when a legacy caller owns the global total."""


class EventPublisherPort(Protocol):
    """Publish a domain event without exposing the plugin implementation."""

    def publish(self, event_type: str, source: str, payload: Mapping[str, Any]) -> None:
        """Publish an event on the configured event bus."""


@dataclass(frozen=True)
class RuntimeContext:
    """Immutable runtime configuration plus the configured site resolver."""

    config: Mapping[str, Any]
    site_resolver: SiteResolver

    @classmethod
    def from_websites(
        cls,
        config: Mapping[str, Any],
        websites: Iterable[object],
    ) -> "RuntimeContext":
        """Build context in the composition root from parsed website settings."""
        return cls(config=config, site_resolver=SiteResolver.from_websites(websites))

    def site_for_path(self, file_path: str | Path) -> SiteIdentity:
        """Resolve a path to a configured site or the explicit legacy bucket."""
        return self.site_resolver.resolve(str(file_path))

    def site_for_website(self, website: object) -> SiteIdentity:
        """Return the identity declared by a parsed website object."""
        name = str(getattr(website, "name", "")).strip()
        if not name:
            return SiteIdentity.legacy()
        return SiteIdentity.from_values(
            getattr(website, "site_id", None),
            name,
        )


@dataclass(frozen=True)
class RuntimeServices:
    """The explicit dependencies required by a running monitor instance."""

    context: RuntimeContext
    registry: DetectionRegistryPort
    metrics: MetricsPort
    events: EventPublisherPort
