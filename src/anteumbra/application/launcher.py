"""Compose and run the complete Anteumbra process."""

from __future__ import annotations

import logging
import os
import threading
from pathlib import Path
from typing import Any, Callable

from anteumbra.application.jsonl_consumer import JsonlEventTailer
from anteumbra.application.runtime_health_service import assess_runtime_capabilities


logger = logging.getLogger(__name__)
_launcher_state: dict[str, Any] = {}
_state_lock = threading.RLock()


def start_all(host: str = "127.0.0.1", port: int = 8080) -> None:
    """Start all runtime components and block until interrupted."""
    from anteumbra.infrastructure.config.registry import ConfigRegistry
    from anteumbra.infrastructure.config.version import get_version
    from anteumbra.infrastructure.utils.logger_factory import get_logger
    from anteumbra.infrastructure.utils.path_utils import normalize_path

    ConfigRegistry.initialize()
    config = ConfigRegistry.get_raw_config()
    websites = ConfigRegistry.get_enabled_websites()
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

    pid_dir = Path("data")
    pid_dir.mkdir(parents=True, exist_ok=True)
    (pid_dir / "anteumbra.pid").write_text(str(os.getpid()), encoding="utf-8")

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
        })

    print(f"Anteumbra v{get_version()} - Web Perimeter Security")
    for website in websites:
        print(f"  Website: {website.name}")
        print(f"  Watch:   {website.path}")
    print(f"  Admin:   http://{host}:{port}/admin")
    print(f"  Health:  http://{host}:{port}/api/v1/health")
    print("-" * 50)

    try:
        plugin_manager = _start_plugins(config, warnings)

        from anteumbra.application.runtime_adapters import build_runtime_services

        runtime_services = build_runtime_services(
            config,
            websites,
            event_publisher=plugin_manager,
        )

        from anteumbra.interfaces.web.factory import create_app, create_runtime_server

        app = create_app(plugin_manager=plugin_manager)
        web_server = create_runtime_server(app, host, port)
        _launcher_state["web_server"] = web_server

        _migrate_site_metadata(warnings)
        monitors, log_monitors, site_warnings = _start_site_monitors(
            websites, runtime_services=runtime_services
        )
        warnings.extend(site_warnings)
        _launcher_state["monitors"] = monitors
        _launcher_state["log_monitors"] = log_monitors
        if not monitors:
            raise RuntimeError("No website monitor could be started")

        _start_waf_poller(warnings)

        from anteumbra.infrastructure.threat_graph import get_threat_graph

        threat_graph = get_threat_graph()
        _launcher_state["threat_graph"] = threat_graph
        print("[OK] ThreatGraph initialized")
        profile_threads = _start_profile_workers(
            threat_graph,
            runtime_logger,
            stop_event,
        )
        _launcher_state["threads"].extend(profile_threads)

        _start_sse(warnings)
        _start_metrics(warnings)
        _start_siem(warnings)

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


def _migrate_site_metadata(warnings: list[str]) -> None:
    """Backfill historical records once the configured site roots are available."""
    try:
        from anteumbra.application.quarantine_service import (
            migrate_site_metadata as migrate_quarantine_sites,
        )
        from anteumbra.application.registry_service import (
            migrate_site_metadata as migrate_registry_sites,
        )

        registry_changed = migrate_registry_sites()
        quarantine_changed = migrate_quarantine_sites()
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
) -> tuple[list[Any], list[Any], list[str]]:
    if monitor_factory is None:
        from anteumbra.infrastructure.monitoring.monitor import WebsiteMonitor

        monitor_factory = WebsiteMonitor
    if logger_factory is None:
        from anteumbra.infrastructure.utils.logger_factory import get_logger

        logger_factory = get_logger
    if scan_callback is None:
        from anteumbra.infrastructure.detection.scanner import quick_scan_yara

        scan_callback = quick_scan_yara
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
            log_monitor = log_monitor_factory(site_logger, analyzer)
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


def _start_profile_workers(threat_graph, runtime_logger, stop_event) -> list[threading.Thread]:
    from anteumbra.infrastructure.utils.path_utils import normalize_path

    cache_path = normalize_path("data/waf_events.jsonl")
    tailer = JsonlEventTailer(
        cache_path,
        threat_graph.ingest_waf_event,
        logger=runtime_logger,
        dead_letter_path=normalize_path("data/waf_events.deadletter.jsonl"),
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


def _start_plugins(config: dict[str, Any], warnings: list[str]):
    try:
        from anteumbra.application.plugin_manager import PluginManager
        from anteumbra.infrastructure.monitoring.metrics import get_metrics

        metrics = get_metrics()
        manager = PluginManager(
            metric_recorder=lambda name: metrics.increment(name),
        )
        manager.set_plugin_factories(
            _build_builtin_plugin_factories(config, manager)
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
) -> dict[str, Callable[[], Any]]:
    """Wire official plugins without allowing them to locate runtime services."""
    from anteumbra.application.quarantine_service import quarantine_registered_file
    from anteumbra.infrastructure.monitoring.notifier import (
        format_alert_message,
        get_notifier,
    )
    from anteumbra.infrastructure.monitoring.siem_exporter import get_siem_exporter
    from anteumbra.infrastructure.quarantine import is_recently_restored
    from anteumbra.infrastructure.threat_graph import get_threat_graph
    from anteumbra.infrastructure.utils.logger_factory import get_logger
    from anteumbra.plugins.notifier_handler import NotifierHandlerPlugin
    from anteumbra.plugins.quarantine_handler import QuarantineHandlerPlugin
    from anteumbra.plugins.siem_handler import SIEMHandlerPlugin
    from anteumbra.plugins.threat_graph_handler import ThreatGraphHandlerPlugin

    return {
        "notifier_handler": lambda: NotifierHandlerPlugin(
            get_notifier(get_logger("monitor.notifier")),
            format_alert_message,
            config,
        ),
        "quarantine_handler": lambda: QuarantineHandlerPlugin(
            quarantine_file=quarantine_registered_file,
            recently_restored=is_recently_restored,
            events=event_publisher,
            runtime_config=config,
        ),
        "siem_handler": lambda: SIEMHandlerPlugin(get_siem_exporter()),
        "threat_graph_handler": lambda: ThreatGraphHandlerPlugin(
            get_threat_graph(),
            event_publisher,
        ),
    }


def _start_waf_poller(warnings: list[str]) -> None:
    try:
        from anteumbra.infrastructure.waf_client import get_waf_poller

        poller = get_waf_poller()
        if poller:
            poller.start()
            _launcher_state["waf_poller"] = poller
            print(f"[OK] WAF poller: {poller.source.get_name()}")
    except Exception as exc:
        logger.exception("WAF poller startup failed")
        warnings.append(f"WAF poller failed: {exc}")


def _start_sse(warnings: list[str]) -> None:
    try:
        from anteumbra.infrastructure.utils.sse_manager import start_sse_worker

        start_sse_worker()
        _launcher_state["sse_started"] = True
    except Exception as exc:
        logger.exception("SSE worker startup failed")
        warnings.append(f"SSE worker failed: {exc}")


def _start_metrics(warnings: list[str]) -> None:
    try:
        from anteumbra.infrastructure.monitoring.metrics import preload_metrics

        preload_metrics()
    except Exception as exc:
        logger.exception("Metrics startup failed")
        warnings.append(f"Metrics failed: {exc}")


def _start_siem(warnings: list[str]) -> None:
    try:
        from anteumbra.infrastructure.monitoring.siem_exporter import get_siem_exporter

        exporter = get_siem_exporter()
        if exporter.enabled:
            print(f"[OK] SIEM export: {exporter._format} -> {exporter._export_path}")
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

    poller = state.get("waf_poller")
    if poller:
        _stop_resource("WAF poller", poller.stop)

    manager = state.get("plugin_manager")
    if manager:
        _stop_resource("plugin manager", manager.shutdown)

    if state.get("sse_started"):
        try:
            from anteumbra.infrastructure.utils.sse_manager import stop_sse_worker

            _stop_resource("SSE worker", stop_sse_worker)
        except ImportError:
            logger.exception("SSE shutdown import failed")

    try:
        from anteumbra.infrastructure.monitoring.metrics import stop_metrics

        _stop_resource("metrics", stop_metrics)
    except ImportError:
        logger.exception("Metrics shutdown import failed")

    threat_graph = state.get("threat_graph")
    if threat_graph:
        _stop_resource("threat graph persistence", threat_graph.persist)

    for thread in state.get("threads", []):
        if thread.is_alive():
            thread.join(timeout=2.0)

    pid_file = Path("data/anteumbra.pid")
    try:
        if pid_file.exists() and pid_file.read_text(encoding="utf-8").strip() == str(os.getpid()):
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
