"""Focused contracts for replaceable runtime services."""

from __future__ import annotations

import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping, Protocol, Sequence

from anteumbra.domain.runtime import EventPublisherPort


class PluginManagerPort(EventPublisherPort, Protocol):
    """Plugin inventory, event publication, and lifecycle contract."""

    @property
    def is_enabled(self) -> bool:
        """Return whether plugin dispatch is enabled."""

    @property
    def detectors(self) -> Mapping[str, object]:
        """Return registered detector plugins."""

    @property
    def notifiers(self) -> Mapping[str, object]:
        """Return registered notifier plugins."""

    @property
    def event_sources(self) -> Mapping[str, object]:
        """Return registered event-source plugins."""

    def list_all(self) -> list[dict[str, Any]]:
        """Return plugin status records."""

    def shutdown(self) -> None:
        """Stop dispatch and deactivate plugins."""


class NotifierPort(Protocol):
    """Queue and deliver security notifications."""

    def enqueue_alert(
        self,
        message: str,
        level: str = "CRITICAL",
        *,
        site_id: str | None = None,
    ) -> bool:
        """Queue one alert for asynchronous delivery."""

    def send_alert(
        self,
        message: str,
        level: str = "CRITICAL",
        analysis: dict[str, Any] | None = None,
        *,
        site_id: str | None = None,
    ) -> bool:
        """Deliver one alert immediately."""

    def shutdown(self) -> None:
        """Flush and stop notification workers."""


class SIEMExporterPort(Protocol):
    """Export detections to the configured SIEM representation."""

    @property
    def enabled(self) -> bool:
        """Return whether automatic export is active."""

    @property
    def export_path(self) -> Path:
        """Return the active file export path."""

    @property
    def format(self) -> str:
        """Return the active output format."""

    def set_format(self, output_format: str) -> None:
        """Select an output format."""

    def export_existing(
        self,
        records: list[dict[str, Any]],
        category: str = "webshell.detected",
    ) -> int:
        """Export existing Registry records."""

    def emit_detection(
        self,
        detection: dict[str, Any],
        category: str = "webshell.detected",
    ) -> str | None:
        """Export one detection."""

    def get_stats(self) -> dict[str, Any]:
        """Return exporter diagnostics."""

    def close(self) -> None:
        """Release exporter resources."""


class YaraEnginePort(Protocol):
    """Compiled YARA engine consumed by scanners and rule management."""

    @property
    def rules_path(self) -> Path:
        """Return the active rule directory."""

    @property
    def load_errors(self) -> Mapping[str, str]:
        """Return rule-file compilation errors."""

    @property
    def compiled_rules(self) -> object | None:
        """Return the active compiled rule set."""

    def reload(self) -> bool:
        """Reload rules from disk."""

    def scan(self, file_path: Path) -> list[Any]:
        """Scan one file."""

    def scan_data(self, data: str | bytes, source_name: str = "memory") -> list[Any]:
        """Scan in-memory content."""

    def get_rule_stats(self) -> dict[str, Any]:
        """Return active rule statistics."""


class ScannerPort(Protocol):
    """Scan one file using a caller-supplied site policy."""

    def scan(
        self,
        file_path: Path,
        scan_options: Any,
        logger: logging.Logger,
    ) -> Any:
        """Return one scan result."""


class FileClusterViewPort(Protocol):
    """Read-only file-cluster projection."""

    @property
    def cluster_id(self) -> str:
        """Return the stable cluster ID."""

    @property
    def size(self) -> int:
        """Return the file count."""

    @property
    def sample_files(self) -> list[str]:
        """Return representative filenames."""

    @property
    def created_at(self) -> datetime:
        """Return cluster creation time."""

    @property
    def hash_track(self) -> str:
        """Return the selected hash implementation."""

    @property
    def threshold(self) -> float:
        """Return the similarity threshold."""


class FileClusterEnginePort(Protocol):
    """Cluster suspicious files and expose immutable projections."""

    def cluster_file(self, file_path: str) -> tuple[str | None, str]:
        """Cluster one file and return its cluster and hash."""

    def get_cluster(self, file_path: str) -> FileClusterViewPort | None:
        """Return a file's cluster projection."""

    def list_clusters(
        self,
        *,
        min_size: int = 1,
        limit: int | None = None,
    ) -> Sequence[FileClusterViewPort]:
        """Return largest-first cluster projections."""

    def get_stats(self) -> dict[str, Any]:
        """Return cluster statistics."""


class ThreatProfileRepositoryPort(Protocol):
    """Best-effort profile shadow repository used for recovery."""

    def save(self, record_id: str, data: Mapping[str, Any]) -> None:
        """Save one serialized profile."""

    def list_all(self, limit: int | None = None, **filters: Any) -> list[dict[str, Any]]:
        """Return serialized profiles available for recovery."""

    def close(self) -> None:
        """Release repository resources."""

class ThreatGraphPort(Protocol):
    """Site-qualified threat-intelligence graph contract."""

    def ingest_waf_event(self, event: dict[str, Any]) -> str | None:
        """Ingest one WAF event."""

    def ingest_registry_entry(self, entry: dict[str, Any]) -> str | None:
        """Ingest one Registry record."""

    def query_ip(self, ip: str, site_id: str | None = None) -> Any | None:
        """Return site-qualified IP reputation."""

    def query_file(self, path: str, site_id: str | None = None) -> Any | None:
        """Return site-qualified file reputation."""

    def query_profile(self, profile_id: str, site_id: str | None = None) -> Any | None:
        """Return one site-qualified profile."""

    def get_active_profiles(
        self,
        min_score: float = 0.0,
        site_id: str | None = None,
    ) -> list[Any]:
        """Return active profiles by descending risk."""

    def find_profiles_for_file(
        self,
        path: str,
        site_id: str | None = None,
    ) -> list[Any]:
        """Return profiles linked to one file."""

    def merge_overlapping_profiles(self, min_overlap: int = 3) -> int:
        """Merge compatible overlapping profiles."""

    def decay_profiles(self, now: datetime | None = None) -> int:
        """Apply risk decay."""

    def persist(self) -> None:
        """Persist the graph."""

    def close(self) -> None:
        """Release persistence resources."""


class WalPort(Protocol):
    """Registry write-ahead-log diagnostics consumed by the web interface."""

    def get_info(self) -> dict[str, Any]:
        """Return WAL diagnostics."""

    def get_status(self) -> tuple[str, str, float]:
        """Return status code, text, and size."""

    def list_archives(self) -> list[dict[str, Any]]:
        """Return WAL archive metadata."""


class SSEPort(Protocol):
    """Runtime-owned live log and Registry update stream."""

    def start(self) -> None:
        """Start dispatch work."""

    def stop(self, timeout: float = 2.0) -> bool:
        """Stop dispatch work."""

    def get_limits(self) -> dict[str, int]:
        """Return stream capacity limits."""

    def register_client(self, client_ip: str | None = None) -> Any:
        """Register one stream client."""

    def unregister_client(self, client: Any) -> bool:
        """Unregister one stream client."""

    def cleanup_connections(self, client_ip: str | None = None) -> int:
        """Close matching stream clients."""

    def trigger_registry_update(self) -> bool:
        """Publish a Registry refresh signal."""

    def connected_client_count(self) -> int:
        """Return active stream client count."""

    def ip_client_count(self, client_ip: str) -> int:
        """Return active clients for one IP."""

    def ip_clients(self, client_ip: str) -> list[Any]:
        """Return clients belonging to one IP."""

    def persist_log_line(self, log_line: str) -> bool:
        """Append one historical log line."""

    def get_log_buffer(self) -> list[str]:
        """Return persisted historical log lines."""


class WAFPollerPort(Protocol):
    """Interruptible WAF event polling lifecycle."""

    @property
    def source_name(self) -> str:
        """Return the configured source name."""

    def start(self) -> None:
        """Start polling."""

    def stop(self, timeout: float = 5.0) -> None:
        """Stop polling."""


class ScanHistoryStorePort(Protocol):
    """Durable storage for completed manual scan records."""

    def save(self, scan_id: str, record: Mapping[str, Any]) -> None:
        """Atomically persist one scan record under its validated identifier."""

    def list_records(self, limit: int | None = None) -> list[dict[str, Any]]:
        """Return recent complete records without exposing storage paths."""

    def get(self, scan_id: str) -> dict[str, Any] | None:
        """Return one complete record, or None when it has expired or is absent."""
