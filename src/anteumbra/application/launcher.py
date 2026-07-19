"""Compose and run the complete Anteumbra process."""

from __future__ import annotations

import logging
import os
import threading
from pathlib import Path
from typing import Any, Callable

from anteumbra.application.jsonl_consumer import JsonlEventTailer
from anteumbra.application.runtime_container import RuntimeContainer
from anteumbra.application.runtime_health_service import assess_runtime_capabilities


logger = logging.getLogger(__name__)
_launcher_state: dict[str, Any] = {}
_state_lock = threading.RLock()


def build_runtime_container(
    config_path: str | Path | None = None,
    *,
    plugin_manager: Any | None = None,
) -> RuntimeContainer:
    """Build one runtime container at the process composition root."""
    from anteumbra.application.quarantine_service import QuarantineService
    from anteumbra.infrastructure.config.provider import TomlConfigProvider
    from anteumbra.infrastructure.config.registry import ConfigRegistry
    from anteumbra.infrastructure.block_ledger import BlockLedger
    from anteumbra.infrastructure.detection.file_cluster import FileClusterEngine
    from anteumbra.infrastructure.detection.hash_engine import HashEngine
    from anteumbra.infrastructure.detection.memory_shell_tracer import MemoryShellTracer
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
    from anteumbra.infrastructure.utils.logger_factory import get_logger
    from anteumbra.infrastructure.utils.path_utils import normalize_path
    from anteumbra.infrastructure.utils.sse_manager import SSEManager
    from anteumbra.infrastructure.waf_client import build_waf_poller
    from anteumbra.infrastructure.wal_manager import WalManager

    provider = TomlConfigProvider(config_path)
    ConfigRegistry.bind(provider)
    config = provider.get()
    data_dir = normalize_path(config.get("paths", {}).get("data_dir", "data"))
    events = EventPublisherRouter(plugin_manager)
    wal = WalManager(
        data_dir / "registry_wal.log",
        settings_loader=lambda: provider.get().get("filesizes", {}),
        event_publisher=events,
        logger=get_logger("wal_manager"),
    )
    sse = SSEManager(
        provider,
        data_dir / "sse_log_buffer.json",
        logger=get_logger("sse"),
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
            get_logger("block_ledger").exception(
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
            get_logger("quarantine").exception(
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
            get_logger("suspicious_registry").exception(
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
            get_logger("threat_graph").exception(
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
        logger=get_logger("quarantine"),
    )
    registry = SuspiciousRegistry(
        data_dir / "suspicious_registry.json",
        config=provider,
        wal=wal,
        event_publisher=events,
        change_callback=sse.trigger_registry_update,
        shadow_repository=shadow_registry,
        logger=get_logger("suspicious_registry"),
    )
    registry.replay_wal()
    quarantine = QuarantineService(
        quarantine_store,
        registry,
        site_resolver=provider.resolve_site_identity,
        logger=get_logger("quarantine_service"),
    )
    memory_shell_tracer = MemoryShellTracer(
        registry_reader=registry.get_all,
        config_provider=provider,
    )
    waf_poller = build_waf_poller(
        provider,
        data_dir / "waf_events.jsonl",
        log=get_logger("waf_client"),
    )
    ip_blocker = IPBlocker.from_config(
        config.get("ip_blocker", {}),
        retry_path=data_dir / "block_retry_queue.json",
        log=get_logger("ip_blocker"),
    )
    metrics = MetricsCollector(
        data_dir / "metrics.json",
        registry_reader=registry.get_all,
    )
    notifier = Notifier(config.get("notifier", {}), get_logger("monitor.notifier"), metrics)
    siem_exporter = SIEMExporter(config.get("siem", {}))
    hash_engine = HashEngine()
    file_cluster_engine = FileClusterEngine(hash_engine)
    threat_graph = ThreatGraph(
        config,
        file_cluster_engine,
        shadow_repository=shadow_threat_profiles,
    )
    threat_graph.set_persist_path(data_dir / "threat_intel" / "threat_graph.json")
    threat_graph.load()
    yara_engine = build_yara_engine(provider, get_logger("yara"))
    scanner = ScannerService(provider, yara_engine, metrics)
    return RuntimeContainer(
        config=provider,
        events=events,
        plugin_manager=plugin_manager,
        metrics=metrics,
        notifier=notifier,
        siem_exporter=siem_exporter,
        hash_engine=hash_engine,
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
        memory_shell_tracer=memory_shell_tracer,
        waf_poller=waf_poller,
    )


def start_all(host: str = "127.0.0.1", port: int = 8080) -> None:
    """Start all runtime components and block until interrupted."""
    from anteumbra.infrastructure.config.version import get_version
    from anteumbra.infrastructure.utils.logger_factory import get_logger
    from anteumbra.infrastructure.utils.path_utils import normalize_path

    container = build_runtime_container()
    config = container.config.get()
    data_dir = normalize_path(config.get("paths", {}).get("data_dir", "data"))
    websites = container.config.get_enabled_websites()
    if not websites:
        print("[FATAL] No enabled websites in config.toml")
        return

    missing_paths: list[Path] = []
    for website in websites:
        website.path = normalize_path(website.path)
        if not website.path.exists():
            missing_paths.append(website.path)
    if missing_paths:
        for missing_path in missing_paths:
            print(f"[FATAL] Website path does not exist: {missing_path}")
        print("        Create the directories or update website.path in config.toml.")
        return

    data_dir.mkdir(parents=True, exist_ok=True)
    pid_file = data_dir / "anteumbra.pid"
    pid_file.write_text(str(os.getpid()), encoding="utf-8")

    runtime_logger = get_logger("Anteumbra")
    stop_event = threading.Event()
    warnings = [item["message"] for item in assess_runtime_capabilities(config)["warnings"]]

    with _state_lock:
        _launcher_state.clear()
        _launcher_state.update({
            "running": False,
            "stop_event": stop_event,
            "warnings": warnings,
            "websites": [website.name for website in websites],
            "monitors": [],
            "log_monitors": [],
            "threads": [],
            "container": container,
            "pid_file": pid_file,
        })

    print(f"Anteumbra v{get_version()} - Web Perimeter Security")
    for website in websites:
        print(f"  Website: {website.name}")
        print(f"  Watch:   {website.path}")
    print(f"  Admin:   http://{host}:{port}/admin")
    print(f"  Health:  http://{host}:{port}/api/v1/health")
    print("-" * 50)

    try:
        plugin_manager = _start_plugins(
            config,
            warnings,
            container.metrics,
            container.notifier,
            container.siem_exporter,
            container.threat_graph,
            container.quarantine,
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
        web_server = create_runtime_server(app, host, port)
        _launcher_state["web_server"] = web_server

        _migrate_site_metadata(container, warnings)
        monitors, log_monitors, site_warnings = _start_site_monitors(
            websites,
            runtime_services=runtime_services,
            config_provider=container.config,
            notifier=container.notifier,
            registry=container.registry,
            scan_callback=container.scanner.scan,
        )
        warnings.extend(site_warnings)
        _launcher_state["monitors"] = monitors
        _launcher_state["log_monitors"] = log_monitors
        if not monitors:
            raise RuntimeError("No website monitor could be started")

        _start_waf_poller(container.waf_poller, warnings)

        threat_graph = container.threat_graph
        _launcher_state["threat_graph"] = threat_graph
        print("[OK] ThreatGraph initialized")
        profile_threads = _start_profile_workers(
            threat_graph,
            runtime_logger,
            stop_event,
            data_dir,
        )
        _launcher_state["threads"].extend(profile_threads)

        _start_sse(container.sse, warnings)
        _start_metrics(container.metrics, warnings)
        _start_siem(container.siem_exporter, warnings)

        web_thread = threading.Thread(
            target=web_server.serve_forever,
            daemon=True,
            name="AnteumbraWebServer",
        )
        web_thread.start()
        _launcher_state["web_thread"] = web_thread
        _launcher_state["running"] = True
        print("[OK] Web server started")

        print("=" * 50)
        if warnings:
            print("  STARTED WITH WARNINGS")
            for warning in dict.fromkeys(warnings):
                print(f"  [WARN] {warning}")
        else:
            print("  ALL SYSTEMS OPERATIONAL")
        print(f"  Dashboard: http://{host}:{port}/admin")
        print(f"  Health:    http://{host}:{port}/api/v1/health")
        print("=" * 50)

        try:
            while not stop_event.wait(1.0):
                pass
        except KeyboardInterrupt:
            print("\nShutting down...")
    except Exception:
        runtime_logger.exception("Anteumbra startup failed")
        print("[FATAL] Runtime startup failed. Check the runtime logs for details.")
    finally:
        stop_all()


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
    monitor_factory: Callable[..., Any] | None = None,
    logger_factory: Callable[[str], logging.Logger] | None = None,
    scan_callback: Callable[..., Any] | None = None,
    analyzer_factory: Callable[..., Any] | None = None,
    log_monitor_factory: Callable[..., Any] | None = None,
    config_provider: Any | None = None,
    notifier: Any | None = None,
    registry: Any | None = None,
) -> tuple[list[Any], list[Any], list[str]]:
    if monitor_factory is None:
        from anteumbra.infrastructure.monitoring.monitor import WebsiteMonitor

        monitor_factory = WebsiteMonitor
    if logger_factory is None:
        from anteumbra.infrastructure.utils.logger_factory import get_logger

        logger_factory = get_logger
    if scan_callback is None:
        raise ValueError("scan_callback must be supplied by the composition root")
    if analyzer_factory is None:
        from anteumbra.infrastructure.monitoring.log_analyzer import get_analyzer

        analyzer_factory = get_analyzer
    if log_monitor_factory is None:
        from anteumbra.infrastructure.monitoring.log_monitor import LogMonitor

        log_monitor_factory = LogMonitor

    monitors: list[Any] = []
    log_monitors: list[Any] = []
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
    threat_graph,
    runtime_logger,
    stop_event,
    data_dir: Path,
) -> list[threading.Thread]:
    cache_path = data_dir / "waf_events.jsonl"
    tailer = JsonlEventTailer(
        cache_path,
        threat_graph.ingest_waf_event,
        logger=runtime_logger,
        dead_letter_path=data_dir / "waf_events.deadletter.jsonl",
    )
    _launcher_state["profile_tailer"] = tailer

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
    return threads


def _start_plugins(
    config: dict[str, Any],
    warnings: list[str],
    metrics,
    notifier,
    siem_exporter,
    threat_graph,
    quarantine,
):
    try:
        from anteumbra.application.plugin_manager import PluginManager
        manager = PluginManager(
            metric_recorder=lambda name: metrics.increment(name),
        )
        manager.set_plugin_factories(
            _build_builtin_plugin_factories(
                config,
                manager,
                notifier,
                siem_exporter,
                threat_graph,
                quarantine,
            )
        )
        manager.init_from_config(config)
        _launcher_state["plugin_manager"] = manager
        if manager.is_enabled:
            plugins = manager.list_all()
            names = ", ".join(plugin["name"] for plugin in plugins)
            print(f"[OK] Plugins: {len(plugins)} loaded ({names})")
        return manager
    except Exception as exc:
        logger.exception("Plugin startup failed")
        warnings.append(f"Plugin system failed: {exc}")
        from anteumbra.infrastructure.runtime_adapters import NullEventPublisher

        return NullEventPublisher()


def _build_builtin_plugin_factories(
    config: dict[str, Any],
    event_publisher,
    notifier,
    siem_exporter,
    threat_graph,
    quarantine,
) -> dict[str, Callable[[], Any]]:
    """Wire official plugins without allowing them to locate runtime services."""
    from anteumbra.infrastructure.monitoring.notifier import format_alert_message
    from anteumbra.plugins.notifier_handler import NotifierHandlerPlugin
    from anteumbra.plugins.quarantine_handler import QuarantineHandlerPlugin
    from anteumbra.plugins.siem_handler import SIEMHandlerPlugin
    from anteumbra.plugins.threat_graph_handler import ThreatGraphHandlerPlugin

    return {
        "notifier_handler": lambda: NotifierHandlerPlugin(
            notifier,
            format_alert_message,
            config,
        ),
        "quarantine_handler": lambda: QuarantineHandlerPlugin(
            quarantine_file=quarantine.quarantine_file,
            recently_restored=quarantine.is_recently_restored,
            events=event_publisher,
            runtime_config=config,
        ),
        "siem_handler": lambda: SIEMHandlerPlugin(siem_exporter),
        "threat_graph_handler": lambda: ThreatGraphHandlerPlugin(
            threat_graph,
            event_publisher,
        ),
    }


def _start_waf_poller(poller, warnings: list[str]) -> None:
    try:
        if poller:
            poller.start()
            print(f"[OK] WAF poller: {poller.source.get_name()}")
    except Exception as exc:
        logger.exception("WAF poller startup failed")
        warnings.append(f"WAF poller failed: {exc}")


def _start_sse(sse, warnings: list[str]) -> None:
    try:
        if sse is None:
            raise RuntimeError("SSEManager is not configured")
        sse.start()
        _launcher_state["sse_started"] = True
    except Exception as exc:
        logger.exception("SSE worker startup failed")
        warnings.append(f"SSE worker failed: {exc}")


def _start_metrics(metrics, warnings: list[str]) -> None:
    try:
        metrics.start()
    except Exception as exc:
        logger.exception("Metrics startup failed")
        warnings.append(f"Metrics failed: {exc}")


def _start_siem(exporter, warnings: list[str]) -> None:
    try:
        if exporter is not None and exporter.enabled:
            print(f"[OK] SIEM export: {exporter.format} -> {exporter.export_path}")
    except Exception as exc:
        logger.exception("SIEM startup failed")
        warnings.append(f"SIEM exporter failed: {exc}")


def get_runtime_status() -> dict[str, Any]:
    with _state_lock:
        return {
            "running": bool(_launcher_state.get("running", False)),
            "websites": list(_launcher_state.get("websites", [])),
            "warnings": list(dict.fromkeys(_launcher_state.get("warnings", []))),
            "monitor_count": len(_launcher_state.get("monitors", [])),
            "log_monitor_count": len(_launcher_state.get("log_monitors", [])),
        }


def stop_all() -> None:
    """Stop every runtime resource that was successfully started."""
    with _state_lock:
        if (
            not _launcher_state
            or _launcher_state.get("stopping")
            or _launcher_state.get("stopped")
        ):
            return
        _launcher_state["running"] = False
        _launcher_state["stopping"] = True
        state = dict(_launcher_state)

    stop_event = state.get("stop_event")
    if stop_event:
        stop_event.set()

    web_server = state.get("web_server")
    web_thread = state.get("web_thread")
    if web_server and web_thread and web_thread.is_alive():
        _stop_resource("web server", web_server.shutdown)
        web_thread.join(timeout=5.0)

    for log_monitor in reversed(state.get("log_monitors", [])):
        _stop_resource("log monitor", log_monitor.stop)
    for monitor in reversed(state.get("monitors", [])):
        _stop_resource("file monitor", monitor.stop)

    container = state.get("container")
    poller = getattr(container, "waf_poller", None)
    if poller:
        _stop_resource("WAF poller", poller.stop)

    ip_blocker = getattr(container, "ip_blocker", None)
    if ip_blocker:
        _stop_resource("IP blocker", ip_blocker.stop)

    manager = state.get("plugin_manager")
    if manager:
        _stop_resource("plugin manager", manager.shutdown)

    events = getattr(container, "events", None)
    if events:
        events.bind(None)

    block_ledger = getattr(container, "block_ledger", None)
    if block_ledger:
        _stop_resource("block ledger", block_ledger.close)

    registry = getattr(container, "registry", None)
    quarantine = getattr(container, "quarantine", None)
    if quarantine:
        _stop_resource("quarantine", quarantine.close)

    if registry:
        _stop_resource("Registry", registry.close)

    notifier = getattr(container, "notifier", None)
    if notifier:
        _stop_resource("notifier", notifier.shutdown)

    siem_exporter = getattr(container, "siem_exporter", None)
    if siem_exporter:
        _stop_resource("SIEM exporter", siem_exporter.close)

    if state.get("sse_started"):
        sse = getattr(container, "sse", None)
        if sse:
            _stop_resource("SSE worker", sse.stop)

    metrics = getattr(container, "metrics", None)
    if metrics:
        _stop_resource("metrics", metrics.stop)

    threat_graph = state.get("threat_graph")
    if threat_graph:
        _stop_resource("threat graph persistence", threat_graph.persist)
        _stop_resource("threat graph", threat_graph.close)

    for thread in state.get("threads", []):
        if thread.is_alive():
            thread.join(timeout=2.0)

    pid_file = state.get("pid_file")
    try:
        if (
            pid_file
            and pid_file.exists()
            and pid_file.read_text(encoding="utf-8").strip() == str(os.getpid())
        ):
            pid_file.unlink()
    except OSError:
        logger.exception("Failed to remove PID file")

    with _state_lock:
        _launcher_state.clear()
        _launcher_state.update({
            "running": False,
            "stopped": True,
            "warnings": list(state.get("warnings", [])),
            "websites": list(state.get("websites", [])),
            "monitors": [],
            "log_monitors": [],
        })

    print("Anteumbra stopped.")


def _stop_resource(name: str, callback: Callable[[], Any]) -> None:
    try:
        callback()
    except Exception:
        logger.exception("Failed to stop %s", name)
