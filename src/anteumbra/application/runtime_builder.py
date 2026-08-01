"""Build the concrete services owned by one Anteumbra runtime."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from anteumbra.application.runtime_container import RuntimeContainer
from anteumbra.domain.runtime import ConfigProviderPort
from anteumbra.domain.service_ports import PluginManagerPort


def build_runtime_container(
    config_path: str | Path | None = None,
    *,
    plugin_manager: PluginManagerPort | None = None,
    config_provider: ConfigProviderPort | None = None,
) -> RuntimeContainer:
    """Build one runtime container at the process composition root."""
    from anteumbra.application.config_history_service import ConfigHistoryLogger
    from anteumbra.application.login_rate_service import LoginRateLimiter
    from anteumbra.application.password_service import PasswordService
    from anteumbra.application.quarantine_service import QuarantineService
    from anteumbra.application.scan_history_service import ScanHistoryService
    from anteumbra.application.scan_state_service import ScanRuntimeState
    from anteumbra.infrastructure.config.provider import TomlConfigProvider
    from anteumbra.infrastructure.block_ledger import BlockLedger
    from anteumbra.infrastructure.detection.file_cluster import FileClusterEngine
    from anteumbra.infrastructure.detection.hash_engine import HashEngine
    from anteumbra.infrastructure.detection.scanner import ScannerService
    from anteumbra.infrastructure.detection.yara_engine import build_yara_engine
    from anteumbra.infrastructure.monitoring.metrics import MetricsCollector
    from anteumbra.infrastructure.monitoring.notifier import Notifier
    from anteumbra.infrastructure.monitoring.siem_exporter import SIEMExporter
    from anteumbra.infrastructure.ip_blocker import IPBlocker
    from anteumbra.infrastructure.persistence.sqlite_repository import SqliteRepository
    from anteumbra.infrastructure.quarantine import QuarantineStore
    from anteumbra.infrastructure.runtime_adapters import EventPublisherRouter
    from anteumbra.infrastructure.scan_history import FileScanHistoryStore
    from anteumbra.infrastructure.suspicious_registry import SuspiciousRegistry
    from anteumbra.infrastructure.threat_graph import ThreatGraph
    from anteumbra.infrastructure.utils.logger_factory import RuntimeLoggerFactory
    from anteumbra.infrastructure.utils.path_utils import normalize_path
    from anteumbra.infrastructure.monitoring.log_analyzer import get_analyzer
    from anteumbra.infrastructure.monitoring.log_monitor import LogMonitor
    from anteumbra.infrastructure.monitoring.monitor import WebsiteMonitor
    from anteumbra.infrastructure.monitoring.notifier import format_alert_message
    from anteumbra.infrastructure.utils.sse_manager import SSEManager
    from anteumbra.infrastructure.waf_client import build_waf_poller
    from anteumbra.infrastructure.wal_manager import WalManager

    if config_path is not None and config_provider is not None:
        raise ValueError("config_path and config_provider are mutually exclusive")
    provider = config_provider or TomlConfigProvider(config_path)
    runtime_logging = RuntimeLoggerFactory(provider)
    passwords = PasswordService(provider)
    config = provider.get()
    data_dir = normalize_path(config.get("paths", {}).get("data_dir", "data"))
    config_history = ConfigHistoryLogger(
        data_dir / "config_history.json",
        rules_dir=normalize_path(
            config.get("paths", {}).get("yara_rules_path", "rules/webshell")
        ),
    )
    scan_state = ScanRuntimeState()
    scan_history = ScanHistoryService(
        FileScanHistoryStore(
            data_dir / "scans",
            logger=runtime_logging.get_logger("scan_history"),
        )
    )
    login_rate_limiter = LoginRateLimiter()
    events = EventPublisherRouter(plugin_manager)
    wal = WalManager(
        data_dir / "registry_wal.log",
        settings_loader=lambda: provider.get().get("filesizes", {}),
        event_publisher=events,
        logger=runtime_logging.get_logger("wal_manager"),
    )
    sse = SSEManager(
        provider,
        data_dir / "sse_log_buffer.json",
        logger=runtime_logging.get_logger("sse"),
    )
    shadow_ledger = None
    shadow_quarantine = None
    shadow_registry = None
    shadow_threat_profiles = None
    storage = config.get("storage", {})
    if str(storage.get("backend", "json")).strip().lower() in {"sqlite", "both"}:
        db_path = normalize_path(
            storage.get("db_path") or storage.get("sqlite_path", "data/anteumbra.db")
        )
        try:
            shadow_ledger = SqliteRepository(
                str(db_path),
                table_name="block_ledger_entries",
                key_column="record_id",
                sort_column="blocked_at",
            )
        except Exception:
            runtime_logging.get_logger("block_ledger").exception(
                "Block ledger SQLite shadow initialization failed; JSON remains authoritative"
            )
        try:
            shadow_quarantine = SqliteRepository(
                str(db_path),
                table_name="quarantine",
                key_column="quarantine_id",
                sort_column="created_at",
            )
        except Exception:
            runtime_logging.get_logger("quarantine").exception(
                "Quarantine SQLite shadow initialization failed; JSON remains authoritative"
            )
        try:
            shadow_registry = SqliteRepository(
                str(db_path),
                table_name="registry",
                key_column="record_id",
                sort_column="detected_at",
            )
        except Exception:
            runtime_logging.get_logger("suspicious_registry").exception(
                "Registry SQLite shadow initialization failed; JSON remains authoritative"
            )
        try:
            shadow_threat_profiles = SqliteRepository(
                str(db_path),
                table_name="threat_profiles",
                key_column="profile_id",
                sort_column="updated_at",
            )
        except Exception:
            runtime_logging.get_logger("threat_graph").exception(
                "Threat profile SQLite shadow initialization failed; JSON remains authoritative"
            )
    block_ledger = BlockLedger(
        data_dir / "block_ledger.json",
        shadow_repository=shadow_ledger,
        event_publisher=events,
    )
    quarantine_store = QuarantineStore(
        data_dir / "quarantine",
        site_resolver=provider.resolve_site_identity,
        shadow_repository=shadow_quarantine,
        logger=runtime_logging.get_logger("quarantine"),
    )
    registry = SuspiciousRegistry(
        data_dir / "suspicious_registry.json",
        config=provider,
        wal=wal,
        event_publisher=events,
        change_callback=sse.trigger_registry_update,
        shadow_repository=shadow_registry,
        logger=runtime_logging.get_logger("suspicious_registry"),
    )
    registry.replay_wal()
    quarantine = QuarantineService(
        quarantine_store,
        registry,
        site_resolver=provider.resolve_site_identity,
        logger=runtime_logging.get_logger("quarantine_service"),
    )
    waf_poller = build_waf_poller(
        provider,
        data_dir / "waf_events.jsonl",
        log=runtime_logging.get_logger("waf_client"),
    )
    ip_blocker = IPBlocker.from_config(
        config.get("ip_blocker", {}),
        retry_path=data_dir / "block_retry_queue.json",
        log=runtime_logging.get_logger("ip_blocker"),
    )
    metrics = MetricsCollector(
        data_dir / "metrics.json",
        registry_reader=registry.get_all,
    )
    notifier = Notifier(
        config.get("notifier", {}),
        runtime_logging.get_logger("monitor.notifier"),
        metrics,
    )
    siem_exporter = SIEMExporter(config.get("siem", {}))
    hash_engine = HashEngine()
    file_cluster_engine = FileClusterEngine(hash_engine)
    threat_graph = ThreatGraph(
        config,
        file_cluster_engine,
        shadow_repository=shadow_threat_profiles,
        log=runtime_logging.get_logger("threat_graph"),
    )
    threat_graph.set_persist_path(data_dir / "threat_intel" / "threat_graph.json")
    threat_graph.load()
    yara_engine = build_yara_engine(provider, runtime_logging.get_logger("yara"))
    scanner = ScannerService(provider, yara_engine, metrics)
    return RuntimeContainer(
        config=provider,
        events=events,
        logging=runtime_logging,
        passwords=passwords,
        config_history=config_history,
        scan_state=scan_state,
        scan_history=scan_history,
        login_rate_limiter=login_rate_limiter,
        plugin_manager=plugin_manager,
        metrics=metrics,
        notifier=notifier,
        siem_exporter=siem_exporter,
        file_cluster_engine=file_cluster_engine,
        threat_graph=threat_graph,
        yara_engine=yara_engine,
        scanner=scanner,
        ip_blocker=ip_blocker,
        block_ledger=block_ledger,
        wal=wal,
        sse=sse,
        registry=registry,
        quarantine=quarantine,
        waf_poller=waf_poller,
    )


@dataclass(frozen=True, slots=True)
class RuntimeLifecycleDependencies:
    """Concrete runtime capabilities assembled outside lifecycle orchestration."""

    config_provider_factory: Callable[[], ConfigProviderPort]
    path_normalizer: Callable[[str | Path], Path]
    version_getter: Callable[[], str]
    process_identity_writer: Callable[[Path, Path], object]
    process_identity_remover: Callable[[Path, object], None]
    container_builder: Callable[..., RuntimeContainer]
    runtime_services_builder: Callable[..., object]
    app_factory: Callable[..., object]
    server_factory: Callable[..., object]
    monitor_factory: Callable[..., object]
    analyzer_factory: Callable[..., object]
    log_monitor_factory: Callable[..., object]
    alert_formatter: Callable[[dict[str, object]], str]


def build_runtime_lifecycle_dependencies() -> RuntimeLifecycleDependencies:
    """Assemble concrete lifecycle capabilities at the composition root."""
    from anteumbra.application.runtime_adapters import build_runtime_services
    from anteumbra.infrastructure.config.provider import TomlConfigProvider
    from anteumbra.infrastructure.config.version import get_version
    from anteumbra.infrastructure.process_identity import (
        remove_process_identity,
        write_process_identity,
    )
    from anteumbra.infrastructure.utils.path_utils import normalize_path
    from anteumbra.infrastructure.monitoring.log_analyzer import get_analyzer
    from anteumbra.infrastructure.monitoring.log_monitor import LogMonitor
    from anteumbra.infrastructure.monitoring.monitor import WebsiteMonitor
    from anteumbra.infrastructure.monitoring.notifier import format_alert_message
    from anteumbra.interfaces.web.factory import create_app, create_runtime_server

    return RuntimeLifecycleDependencies(
        config_provider_factory=TomlConfigProvider,
        path_normalizer=normalize_path,
        version_getter=get_version,
        process_identity_writer=write_process_identity,
        process_identity_remover=remove_process_identity,
        container_builder=build_runtime_container,
        runtime_services_builder=build_runtime_services,
        app_factory=create_app,
        server_factory=create_runtime_server,
        monitor_factory=WebsiteMonitor,
        analyzer_factory=get_analyzer,
        log_monitor_factory=LogMonitor,
        alert_formatter=format_alert_message,
    )
