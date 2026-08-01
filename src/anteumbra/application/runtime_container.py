"""Explicit ownership of services belonging to one Anteumbra runtime."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from anteumbra.domain.blocking import BlockLedgerPort, IPBlockerPort
from anteumbra.domain.runtime import (
    BindableEventPublisherPort,
    ConfigProviderPort,
    DetectionRegistryPort,
    RuntimeLoggingPort,
    RuntimeMetricsPort,
)
from anteumbra.domain.service_ports import (
    FileClusterEnginePort,
    NotifierPort,
    PluginManagerPort,
    ScannerPort,
    SIEMExporterPort,
    SSEPort,
    ThreatGraphPort,
    WAFPollerPort,
    WalPort,
    YaraEnginePort,
)

if TYPE_CHECKING:
    from anteumbra.application.config_history_service import ConfigHistoryLogger
    from anteumbra.application.log_analysis_service import AccessLogAnalysisService
    from anteumbra.application.login_rate_service import LoginRateLimiter
    from anteumbra.application.password_service import PasswordService
    from anteumbra.application.quarantine_service import QuarantineService
    from anteumbra.application.scan_history_service import ScanHistoryService
    from anteumbra.application.scan_state_service import ScanRuntimeState


@dataclass
class RuntimeContainer:
    """Typed service inventory assembled only by the composition root.

    Required fields form the supported runtime contract. Optional fields are
    capabilities that can genuinely be disabled, rather than placeholders for
    dependencies that happen to be initialized later.
    """

    config: ConfigProviderPort
    events: BindableEventPublisherPort
    logging: RuntimeLoggingPort
    passwords: PasswordService
    config_history: ConfigHistoryLogger
    scan_state: ScanRuntimeState
    scan_history: ScanHistoryService
    login_rate_limiter: LoginRateLimiter
    log_analysis: AccessLogAnalysisService
    metrics: RuntimeMetricsPort
    notifier: NotifierPort
    siem_exporter: SIEMExporterPort
    yara_engine: YaraEnginePort
    scanner: ScannerPort
    threat_graph: ThreatGraphPort
    file_cluster_engine: FileClusterEnginePort
    registry: DetectionRegistryPort
    quarantine: QuarantineService
    block_ledger: BlockLedgerPort
    wal: WalPort
    sse: SSEPort
    plugin_manager: PluginManagerPort | None = None
    ip_blocker: IPBlockerPort | None = None
    waf_poller: WAFPollerPort | None = None
