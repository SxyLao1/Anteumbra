"""Compose and run the complete Anteumbra process."""

from __future__ import annotations

import logging
import os
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Protocol

from anteumbra.application.jsonl_consumer import JsonlEventTailer
from anteumbra.application.runtime_container import RuntimeContainer
from anteumbra.application.runtime_health_service import assess_runtime_capabilities
from anteumbra.domain.runtime import (
    ConfigProviderPort,
    DetectionRegistryPort,
    EventPublisherPort,
    RuntimeMetricsPort,
)
from anteumbra.domain.service_ports import (
    NotifierPort,
    PluginManagerPort,
    SIEMExporterPort,
    SSEPort,
    ThreatGraphPort,
    WAFPollerPort,
)


logger = logging.getLogger(__name__)


class RuntimeStartupError(RuntimeError):
    """Raised when the complete runtime cannot be started safely."""


class MonitorResourcePort(Protocol):
    """Lifecycle surface shared by file and access-log monitors."""

    @property
    def is_running(self) -> bool:
        """Return whether the monitor worker is active."""

    def start(self) -> None:
        """Start monitoring."""

    def stop(self) -> None:
        """Stop monitoring."""


class RuntimeServerPort(Protocol):
    """Bound web-server lifecycle owned by RuntimeLifecycle."""

    def serve_forever(self) -> None:
        """Serve requests until shutdown."""

    def shutdown(self) -> None:
        """Stop accepting and serving requests."""

    def server_close(self) -> None:
        """Release the bound listener."""


@dataclass(slots=True)
class RuntimeState:
    """Resources and observable state owned by one runtime lifecycle."""

    running: bool = False
    stopping: bool = False
    stopped: bool = False
    warnings: list[str] = field(default_factory=list)
    websites: list[str] = field(default_factory=list)
    monitors: list[MonitorResourcePort] = field(default_factory=list)
    log_monitors: list[MonitorResourcePort] = field(default_factory=list)
    threads: list[threading.Thread] = field(default_factory=list)
    stop_event: threading.Event = field(default_factory=threading.Event)
    container: RuntimeContainer | None = None
    pid_file: Path | None = None
    web_server: RuntimeServerPort | None = None
    web_thread: threading.Thread | None = None
    profile_tailer: JsonlEventTailer | None = None
    sse_started: bool = False


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
    from anteumbra.infrastructure.suspicious_registry import SuspiciousRegistry
    from anteumbra.infrastructure.threat_graph import ThreatGraph
    from anteumbra.infrastructure.utils.logger_factory import RuntimeLoggerFactory
    from anteumbra.infrastructure.utils.path_utils import normalize_path
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


class RuntimeLifecycle:
    """Start and stop one complete Anteumbra runtime without global state."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 8080,
        *,
        config_provider: ConfigProviderPort | None = None,
    ) -> None:
        self.host = host
        self.port = port
        self._config_provider = config_provider
        self._lock = threading.RLock()
        self._state = RuntimeState()

    def run(self) -> None:
        """Start all runtime components and block until interrupted."""
        from anteumbra.infrastructure.config.provider import TomlConfigProvider
        from anteumbra.infrastructure.config.version import get_version
        from anteumbra.infrastructure.utils.path_utils import normalize_path

        with self._lock:
            if self._state.running or self._state.stopping:
                raise RuntimeError("Runtime lifecycle is already active")

        provider = self._config_provider or TomlConfigProvider()
        config = provider.get()
        data_dir = normalize_path(config.get("paths", {}).get("data_dir", "data"))
        websites = provider.get_enabled_websites()
        if not websites:
            raise RuntimeStartupError("No enabled websites in config.toml")

        missing_paths: list[Path] = []
        for website in websites:
            website.path = normalize_path(website.path)
            if not website.path.exists():
                missing_paths.append(website.path)
        if missing_paths:
            details = "\n".join(
                f"Website path does not exist: {missing_path}"
                for missing_path in missing_paths
            )
            raise RuntimeStartupError(
                f"{details}\nCreate the directories or update website.path in config.toml."
            )

        try:
            container = build_runtime_container(config_provider=provider)
        except Exception as exc:
            logger.exception("Anteumbra runtime initialization failed")
            raise RuntimeStartupError(
                "Runtime initialization failed. Check the runtime logs for details."
            ) from exc

        pid_file = data_dir / "anteumbra.pid"
        state = RuntimeState(
            warnings=[],
            websites=[website.name for website in websites],
            container=container,
            pid_file=pid_file,
        )
        with self._lock:
            self._state = state

        runtime_logger = container.logging.get_logger("Anteumbra")
        try:
            data_dir.mkdir(parents=True, exist_ok=True)
            pid_file.write_text(str(os.getpid()), encoding="utf-8")
            state.warnings.extend(
                item["message"]
                for item in assess_runtime_capabilities(config)["warnings"]
            )

            print(f"Anteumbra v{get_version()} - Web Perimeter Security")
            for website in websites:
                print(f"  Website: {website.name}")
                print(f"  Watch:   {website.path}")
            print(f"  Admin:   http://{self.host}:{self.port}/admin")
            print(f"  Health:  http://{self.host}:{self.port}/api/v1/health")
            print("-" * 50)

            plugin_manager = _start_plugins(
                config,
                state.warnings,
                container.metrics,
                container.notifier,
                container.siem_exporter,
                container.threat_graph,
                container.quarantine,
                container.logging.get_logger,
            )
            container.plugin_manager = plugin_manager
            container.events.bind(plugin_manager)
            if container.ip_blocker is not None:
                container.ip_blocker.start()

            from anteumbra.application.runtime_adapters import build_runtime_services

            runtime_services = build_runtime_services(
                config,
                websites,
                event_publisher=container.events,
                registry=container.registry,
                metrics=container.metrics,
                quarantine=container.quarantine,
            )

            from anteumbra.interfaces.web.factory import create_app, create_runtime_server

            app = create_app(runtime=container)
            state.web_server = create_runtime_server(app, self.host, self.port)

            _migrate_site_metadata(container, state.warnings)
            monitors, log_monitors, site_warnings = _start_site_monitors(
                websites,
                runtime_services=runtime_services,
                logger_factory=container.logging.get_logger,
                config_provider=container.config,
                notifier=container.notifier,
                registry=container.registry,
                scan_callback=container.scanner.scan,
            )
            state.monitors = monitors
            state.log_monitors = log_monitors
            state.warnings.extend(site_warnings)
            if not state.monitors:
                raise RuntimeError("No website monitor could be started")

            _start_waf_poller(container.waf_poller, state.warnings)

            print("[OK] ThreatGraph initialized")
            profile_threads, profile_tailer = _start_profile_workers(
                container.threat_graph,
                runtime_logger,
                state.stop_event,
                data_dir,
            )
            state.threads.extend(profile_threads)
            state.profile_tailer = profile_tailer

            state.sse_started = _start_sse(container.sse, state.warnings)
            _start_metrics(container.metrics, state.warnings)
            _start_siem(container.siem_exporter, state.warnings)

            state.web_thread = threading.Thread(
                target=state.web_server.serve_forever,
                daemon=True,
                name="AnteumbraWebServer",
            )
            state.web_thread.start()
            with self._lock:
                state.running = True
            print("[OK] Web server started")

            print("=" * 50)
            if state.warnings:
                print("  STARTED WITH WARNINGS")
                for warning in dict.fromkeys(state.warnings):
                    print(f"  [WARN] {warning}")
            else:
                print("  ALL SYSTEMS OPERATIONAL")
            print(f"  Dashboard: http://{self.host}:{self.port}/admin")
            print(f"  Health:    http://{self.host}:{self.port}/api/v1/health")
            print("=" * 50)

            try:
                while not state.stop_event.wait(1.0):
                    pass
            except KeyboardInterrupt:
                print("\nShutting down...")
        except Exception as exc:
            runtime_logger.exception("Anteumbra startup failed")
            raise RuntimeStartupError(
                "Runtime startup failed. Check the runtime logs for details."
            ) from exc
        finally:
            self.stop()

    def status(self) -> dict[str, Any]:
        """Return a stable snapshot suitable for status APIs and diagnostics."""
        with self._lock:
            state = self._state
            return {
                "running": state.running,
                "websites": list(state.websites),
                "warnings": list(dict.fromkeys(state.warnings)),
                "monitor_count": len(state.monitors),
                "log_monitor_count": len(state.log_monitors),
            }

    def stop(self) -> None:
        """Stop every runtime resource that was successfully started."""
        with self._lock:
            state = self._state
            if state.stopping or state.stopped:
                return
            if state.container is None:
                state.stopped = True
                return
            state.running = False
            state.stopping = True
            state.stop_event.set()

        container = state.container
        web_server = state.web_server
        web_thread = state.web_thread
        if web_server is not None:
            if web_thread is not None and web_thread.is_alive():
                _stop_resource("web server", web_server.shutdown)
                web_thread.join(timeout=5.0)
            close_server = getattr(web_server, "server_close", None)
            if callable(close_server):
                _stop_resource("web server socket", close_server)

        for log_monitor in reversed(state.log_monitors):
            _stop_resource("log monitor", log_monitor.stop)
        for monitor in reversed(state.monitors):
            _stop_resource("file monitor", monitor.stop)

        scan_state = getattr(container, "scan_state", None)
        if scan_state:
            _stop_resource("manual scan state", scan_state.shutdown)

        poller = getattr(container, "waf_poller", None)
        if poller:
            _stop_resource("WAF poller", poller.stop)

        ip_blocker = getattr(container, "ip_blocker", None)
        if ip_blocker:
            _stop_resource("IP blocker", ip_blocker.stop)

        manager = getattr(container, "plugin_manager", None)
        shutdown_manager = getattr(manager, "shutdown", None)
        if callable(shutdown_manager):
            _stop_resource("plugin manager", shutdown_manager)

        events = getattr(container, "events", None)
        if events:
            events.bind(None)

        block_ledger = getattr(container, "block_ledger", None)
        if block_ledger:
            _stop_resource("block ledger", block_ledger.close)

        quarantine = getattr(container, "quarantine", None)
        if quarantine:
            _stop_resource("quarantine", quarantine.close)

        registry = getattr(container, "registry", None)
        if registry:
            _stop_resource("Registry", registry.close)

        notifier = getattr(container, "notifier", None)
        if notifier:
            _stop_resource("notifier", notifier.shutdown)

        siem_exporter = getattr(container, "siem_exporter", None)
        if siem_exporter:
            _stop_resource("SIEM exporter", siem_exporter.close)

        if state.sse_started:
            sse = getattr(container, "sse", None)
            if sse:
                _stop_resource("SSE worker", sse.stop)

        metrics = getattr(container, "metrics", None)
        if metrics:
            _stop_resource("metrics", metrics.stop)

        for thread in state.threads:
            if thread.is_alive():
                thread.join(timeout=2.0)

        threat_graph = getattr(container, "threat_graph", None)
        if threat_graph:
            _stop_resource("threat graph persistence", threat_graph.persist)
            _stop_resource("threat graph", threat_graph.close)

        try:
            if (
                state.pid_file
                and state.pid_file.exists()
                and state.pid_file.read_text(encoding="utf-8").strip()
                == str(os.getpid())
            ):
                state.pid_file.unlink()
        except OSError:
            logger.exception("Failed to remove PID file")

        runtime_logging = getattr(container, "logging", None)
        if runtime_logging:
            _stop_resource("runtime logging", runtime_logging.close)

        with self._lock:
            state.monitors.clear()
            state.log_monitors.clear()
            state.threads.clear()
            state.web_server = None
            state.web_thread = None
            state.profile_tailer = None
            state.stopping = False
            state.stopped = True

        print("Anteumbra stopped.")


def _migrate_site_metadata(container: RuntimeContainer, warnings: list[str]) -> None:
    """Backfill historical records once the configured site roots are available."""
    try:
        registry_changed = container.registry.migrate_site_metadata()
        quarantine_changed = container.quarantine.migrate_site_metadata()
        if registry_changed or quarantine_changed:
            print(
                "[OK] Site metadata migrated: "
                f"registry={registry_changed}, quarantine={quarantine_changed}"
            )
    except Exception as exc:
        logger.exception("Site metadata migration failed")
        warnings.append(f"Site metadata migration failed: {exc}")


def _start_site_monitors(
    websites,
    *,
    runtime_services: Any | None = None,
    monitor_factory: Callable[..., MonitorResourcePort] | None = None,
    logger_factory: Callable[[str], logging.Logger] | None = None,
    scan_callback: Callable[..., Any] | None = None,
    analyzer_factory: Callable[..., Any] | None = None,
    log_monitor_factory: Callable[..., MonitorResourcePort] | None = None,
    config_provider: ConfigProviderPort | None = None,
    notifier: NotifierPort | None = None,
    registry: DetectionRegistryPort | None = None,
) -> tuple[list[MonitorResourcePort], list[MonitorResourcePort], list[str]]:
    if monitor_factory is None:
        from anteumbra.infrastructure.monitoring.monitor import WebsiteMonitor

        monitor_factory = WebsiteMonitor
    if logger_factory is None:
        raise ValueError("logger_factory must be supplied by the composition root")
    if scan_callback is None:
        raise ValueError("scan_callback must be supplied by the composition root")
    if analyzer_factory is None:
        from anteumbra.infrastructure.monitoring.log_analyzer import get_analyzer

        analyzer_factory = get_analyzer
    if log_monitor_factory is None:
        from anteumbra.infrastructure.monitoring.log_monitor import LogMonitor

        log_monitor_factory = LogMonitor

    monitors: list[MonitorResourcePort] = []
    log_monitors: list[MonitorResourcePort] = []
    warnings: list[str] = []
    for website in websites:
        site_logger = logger_factory(website.name)
        try:
            if runtime_services is None:
                monitor = monitor_factory(website, scan_callback, site_logger)
            else:
                monitor = monitor_factory(
                    website,
                    scan_callback,
                    site_logger,
                    services=runtime_services,
                )
            monitor.start()
            if getattr(monitor, "is_running", True):
                monitors.append(monitor)
                print(f"[OK] File monitor watching: {website.path}")
            else:
                warnings.append(f"File monitor failed to start for {website.name}")
        except Exception as exc:
            site_logger.exception("File monitor startup failed")
            warnings.append(f"File monitor failed for {website.name}: {exc}")
            continue

        log_config = getattr(website, "log_config", {}) or {}
        if not log_config.get("log_monitor_enabled", False):
            print(f"[OK] Log monitor disabled: {website.name}")
            continue
        try:
            analyzer = analyzer_factory(website, site_logger)
            if config_provider is None or notifier is None or registry is None:
                log_monitor = log_monitor_factory(site_logger, analyzer)
            else:
                log_monitor = log_monitor_factory(
                    site_logger,
                    analyzer,
                    config_provider=config_provider,
                    notifier=notifier,
                    registry=registry,
                )
            log_monitor.start()
            if getattr(log_monitor, "is_running", True):
                log_monitors.append(log_monitor)
                print(f"[OK] Log monitor started: {website.name}")
            else:
                warnings.append(f"Log monitor did not start for {website.name}")
        except Exception as exc:
            site_logger.exception("Log monitor startup failed")
            warnings.append(f"Log monitor failed for {website.name}: {exc}")

    return monitors, log_monitors, warnings


def _start_profile_workers(
    threat_graph: ThreatGraphPort,
    runtime_logger: logging.Logger,
    stop_event: threading.Event,
    data_dir: Path,
) -> tuple[list[threading.Thread], JsonlEventTailer]:
    cache_path = data_dir / "waf_events.jsonl"
    tailer = JsonlEventTailer(
        cache_path,
        threat_graph.ingest_waf_event,
        logger=runtime_logger,
        dead_letter_path=data_dir / "waf_events.deadletter.jsonl",
    )
    def consume() -> None:
        while not stop_event.is_set():
            try:
                tailer.poll()
            except Exception:
                runtime_logger.exception("Profile event consumer poll failed")
            stop_event.wait(5.0)

    def persist() -> None:
        while not stop_event.wait(300.0):
            try:
                threat_graph.merge_overlapping_profiles(min_overlap=3)
                threat_graph.decay_profiles()
                threat_graph.persist()
            except Exception:
                runtime_logger.exception("Threat profile persistence failed")

    threads = [
        threading.Thread(target=consume, daemon=True, name="ProfileConsumer"),
        threading.Thread(target=persist, daemon=True, name="ProfilePersist"),
    ]
    for thread in threads:
        thread.start()
    print("[OK] Profile workers started")
    return threads, tailer


def _start_plugins(
    config: dict[str, Any],
    warnings: list[str],
    metrics: RuntimeMetricsPort,
    notifier: NotifierPort,
    siem_exporter: SIEMExporterPort,
    threat_graph: ThreatGraphPort,
    quarantine,
    logger_factory: Callable[[str], logging.Logger],
) -> PluginManagerPort | None:
    manager = None
    try:
        from anteumbra.application.plugin_manager import PluginManager
        manager = PluginManager(
            metric_recorder=lambda name: metrics.increment(name),
            log=logger_factory("plugin_manager"),
        )
        manager.set_plugin_factories(
            _build_builtin_plugin_factories(
                config,
                manager,
                notifier,
                siem_exporter,
                threat_graph,
                quarantine,
                logger_factory,
            )
        )
        manager.init_from_config(config)
        if manager.is_enabled:
            plugins = manager.list_all()
            names = ", ".join(plugin["name"] for plugin in plugins)
            print(f"[OK] Plugins: {len(plugins)} loaded ({names})")
        return manager
    except Exception as exc:
        logger.exception("Plugin startup failed")
        warnings.append(f"Plugin system failed: {exc}")
        if manager is not None:
            try:
                manager.shutdown()
            except Exception:
                logger.exception("Partially initialized plugin manager shutdown failed")
        return None


def _build_builtin_plugin_factories(
    config: dict[str, Any],
    event_publisher: EventPublisherPort,
    notifier: NotifierPort,
    siem_exporter: SIEMExporterPort,
    threat_graph: ThreatGraphPort,
    quarantine,
    logger_factory: Callable[[str], logging.Logger],
) -> dict[str, Callable[[], Any]]:
    """Wire official plugins without allowing them to locate runtime services."""
    from anteumbra.infrastructure.monitoring.notifier import format_alert_message
    from anteumbra.plugins.notifier_handler import NotifierHandlerPlugin
    from anteumbra.plugins.quarantine_handler import QuarantineHandlerPlugin
    from anteumbra.plugins.siem_handler import SIEMHandlerPlugin
    from anteumbra.plugins.stdout_logger import StdoutLoggerPlugin
    from anteumbra.plugins.threat_graph_handler import ThreatGraphHandlerPlugin

    return {
        "stdout_logger": lambda: StdoutLoggerPlugin(
            log=logger_factory("plugin.stdout_logger"),
        ),
        "notifier_handler": lambda: NotifierHandlerPlugin(
            notifier,
            format_alert_message,
            config,
            log=logger_factory("plugin.notifier_handler"),
        ),
        "quarantine_handler": lambda: QuarantineHandlerPlugin(
            quarantine_file=quarantine.quarantine_file,
            recently_restored=quarantine.is_recently_restored,
            events=event_publisher,
            runtime_config=config,
            log=logger_factory("plugin.quarantine_handler"),
        ),
        "siem_handler": lambda: SIEMHandlerPlugin(
            siem_exporter,
            log=logger_factory("plugin.siem_handler"),
        ),
        "threat_graph_handler": lambda: ThreatGraphHandlerPlugin(
            threat_graph,
            event_publisher,
            log=logger_factory("plugin.threat_graph_handler"),
        ),
    }


def _start_waf_poller(
    poller: WAFPollerPort | None,
    warnings: list[str],
) -> None:
    try:
        if poller:
            poller.start()
            print(f"[OK] WAF poller: {poller.source_name}")
    except Exception as exc:
        logger.exception("WAF poller startup failed")
        warnings.append(f"WAF poller failed: {exc}")


def _start_sse(sse: SSEPort, warnings: list[str]) -> bool:
    try:
        sse.start()
        return True
    except Exception as exc:
        logger.exception("SSE worker startup failed")
        warnings.append(f"SSE worker failed: {exc}")
        return False


def _start_metrics(metrics: RuntimeMetricsPort, warnings: list[str]) -> None:
    try:
        metrics.start()
    except Exception as exc:
        logger.exception("Metrics startup failed")
        warnings.append(f"Metrics failed: {exc}")


def _start_siem(exporter: SIEMExporterPort, warnings: list[str]) -> None:
    try:
        if exporter.enabled:
            print(f"[OK] SIEM export: {exporter.format} -> {exporter.export_path}")
    except Exception as exc:
        logger.exception("SIEM startup failed")
        warnings.append(f"SIEM exporter failed: {exc}")


def _stop_resource(name: str, callback: Callable[[], Any]) -> None:
    try:
        callback()
    except Exception:
        logger.exception("Failed to stop %s", name)
