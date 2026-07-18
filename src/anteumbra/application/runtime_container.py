"""Explicit ownership of services belonging to one Anteumbra runtime."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from anteumbra.domain.runtime import ConfigProviderPort


@dataclass
class RuntimeContainer:
    """Typed service inventory assembled only by the composition root.

    Optional fields are populated as legacy global resources are migrated.
    Keeping them named makes dependencies visible and prevents an arbitrary
    string-keyed service locator from becoming the new architecture.
    """

    config: ConfigProviderPort
    plugin_manager: Any | None = None
    metrics: Any | None = None
    notifier: Any | None = None
    siem_exporter: Any | None = None
    yara_engine: Any | None = None
    scanner: Any | None = None
    threat_graph: Any | None = None
    ip_blocker: Any | None = None
    hash_engine: Any | None = None
    file_cluster_engine: Any | None = None
    log_heuristic_engine: Any | None = None
    registry: Any | None = None
    quarantine: Any | None = None
    block_ledger: Any | None = None
    wal: Any | None = None
    sse: Any | None = None
    waf_poller: Any | None = None
