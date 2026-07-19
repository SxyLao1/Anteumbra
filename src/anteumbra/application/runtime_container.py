"""Explicit ownership of services belonging to one Anteumbra runtime."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from anteumbra.domain.blocking import BlockLedgerPort, IPBlockerPort
from anteumbra.domain.runtime import (
    BindableEventPublisherPort,
    ConfigProviderPort,
    RuntimeLoggingPort,
)

if TYPE_CHECKING:
    from anteumbra.application.config_history_service import ConfigHistoryLogger
    from anteumbra.application.password_service import PasswordService
    from anteumbra.application.quarantine_service import QuarantineService
    from anteumbra.application.scan_state_service import ScanRuntimeState


@dataclass
class RuntimeContainer:
    """Typed service inventory assembled only by the composition root.

    Optional fields are populated as legacy global resources are migrated.
    Keeping them named makes dependencies visible and prevents an arbitrary
    string-keyed service locator from becoming the new architecture.
    """

    config: ConfigProviderPort
    events: BindableEventPublisherPort
    logging: RuntimeLoggingPort
    passwords: PasswordService
    config_history: ConfigHistoryLogger
    scan_state: ScanRuntimeState
    plugin_manager: Any | None = None
    metrics: Any | None = None
    notifier: Any | None = None
    siem_exporter: Any | None = None
    yara_engine: Any | None = None
    scanner: Any | None = None
    threat_graph: Any | None = None
    ip_blocker: IPBlockerPort | None = None
    hash_engine: Any | None = None
    file_cluster_engine: Any | None = None
    registry: Any | None = None
    quarantine: QuarantineService | None = None
    memory_shell_tracer: Any | None = None
    block_ledger: BlockLedgerPort | None = None
    wal: Any | None = None
    sse: Any | None = None
    waf_poller: Any | None = None
