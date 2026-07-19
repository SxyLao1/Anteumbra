"""Runtime dependency contracts used by the monitoring execution pipeline."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Protocol

from anteumbra.domain.quarantine import QuarantineGuardPort
from anteumbra.domain.site import SiteIdentity, SiteResolver


class ConfigProviderPort(Protocol):
    """Expose one runtime-owned, atomically reloadable configuration."""

    @property
    def path(self) -> Path:
        """Return the active configuration source path."""

    @property
    def generation(self) -> int:
        """Return the current successful reload generation."""

    def get(self) -> dict[str, Any]:
        """Return a defensive copy of the resolved configuration."""

    def get_websites(self) -> list[Any]:
        """Return every configured site, including disabled sites."""

    def get_enabled_websites(self) -> list[Any]:
        """Return enabled configured sites."""

    def get_website(self, site_id: str) -> Any | None:
        """Return one configured site by stable ID."""

    def resolve_site_identity(
        self,
        file_path: str | Path,
        site_id: str | None = None,
        site_name: str | None = None,
    ) -> SiteIdentity:
        """Resolve explicit or path-derived site ownership."""

    def reload(self, config_path: str | Path | None = None) -> dict[str, Any]:
        """Atomically publish a newly loaded valid configuration."""


class RuntimeLoggingPort(Protocol):
    """Create and release loggers owned by one application runtime."""

    def get_logger(self, component: str) -> logging.Logger:
        """Return a component logger."""

    def get_site_logger(self, site: SiteIdentity) -> logging.Logger:
        """Return the monitor logger owned by one stable site identity."""

    def get_site_log_path(self, site: SiteIdentity) -> Path:
        """Return the active monitor log path for one site."""

    def get_site_history_paths(self, site: SiteIdentity) -> tuple[Path, ...]:
        """Return existing active and archived monitor logs for one site."""

    def get_access_logger(self) -> logging.Logger:
        """Return the HTTP access logger."""

    def get_application_logger(self) -> logging.Logger:
        """Return the web application logger."""

    def close(self) -> None:
        """Flush and close all handlers owned by the runtime."""


class DetectionRegistryPort(Protocol):
    """Persist detected files with their explicit site ownership."""

    def add(
        self,
        file_path: str | Path,
        features: list[str],
        first_seen_ip: str | None = None,
        detection_source: str = "passive",
        site_id: str | None = None,
        site_name: str | None = None,
        *,
        site: SiteIdentity | None = None,
    ) -> None:
        """Store or update a suspicious-file record."""

    def get_all(
        self,
        include_deleted: bool = False,
        include_false_positive: bool = False,
        site_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """Return a filtered defensive record snapshot."""

    def remove(
        self,
        file_path: str | Path,
        site_id: str | None = None,
        *,
        site: SiteIdentity | None = None,
    ) -> bool:
        """Mark a suspicious-file record as removed within its site boundary."""

    def get(
        self,
        file_path: str | Path,
        site_id: str | None = None,
    ) -> dict[str, Any] | None:
        """Return one site-qualified record, including inactive states."""

    def mark_quarantined(
        self,
        file_path: str | Path,
        quarantine_id: str,
        site_id: str | None = None,
    ) -> bool:
        """Link a Registry record to a committed quarantine object."""

    def mark_restored(
        self,
        file_path: str | Path,
        site_id: str | None = None,
    ) -> bool:
        """Clear quarantine state after a committed restore."""

    def mark_alerted(
        self,
        file_path: str | Path,
        site_id: str | None = None,
    ) -> bool:
        """Mark a record after alert delivery."""

    def mark_false_positive(
        self,
        file_path: str | Path,
        reason: str = "",
        site_id: str | None = None,
    ) -> bool:
        """Record a reviewed false positive."""

    def soft_delete_record(
        self,
        file_path: str | Path,
        site_id: str | None = None,
    ) -> bool:
        """Soft-delete one record while preserving audit history."""

    def increment_access(
        self,
        file_path: str | Path,
        ip: str,
        site_id: str | None = None,
    ) -> None:
        """Record one access-log correlation."""

    def compact(self, compact_days: int | None = None) -> dict[str, int]:
        """Permanently remove expired inactive records."""

    def migrate_site_metadata(self) -> int:
        """Backfill explicit site identity for historical records."""

    def replay_wal(self) -> int:
        """Replay pending Registry transactions."""

    def close(self) -> None:
        """Release persistence resources."""


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

    def record_notification(
        self,
        status: str,
        error: str = "",
        *,
        site_id: str | None = None,
    ) -> None:
        """Record one notification outcome."""

    def record_wechat_failure(self, *, site_id: str | None = None) -> None:
        """Record one WeChat channel failure."""


class RuntimeMetricsPort(MetricsPort, Protocol):
    """Metrics operations consumed by lifecycle and web diagnostics."""

    def record_memory_usage(self) -> bool:
        """Refresh process memory and report whether the probe succeeded."""

    def get(self, site_id: str | None = None) -> dict[str, Any]:
        """Return aggregate or site-qualified metrics."""

    def start(self) -> None:
        """Start persistence work."""

    def stop(self, timeout: float = 2.0, persist: bool = True) -> bool:
        """Stop persistence work."""


class EventPublisherPort(Protocol):
    """Publish a domain event without exposing the plugin implementation."""

    def publish(self, event_type: str, source: str, payload: Mapping[str, Any]) -> None:
        """Publish an event on the configured event bus."""


class BindableEventPublisherPort(EventPublisherPort, Protocol):
    """Runtime-owned publisher that can bind the late-built plugin event bus."""

    def bind(self, publisher: EventPublisherPort | None) -> None:
        """Atomically replace the active event target."""


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
    quarantine: QuarantineGuardPort
