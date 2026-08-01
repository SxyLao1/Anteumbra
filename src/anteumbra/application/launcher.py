"""Compose and run the complete Anteumbra process."""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Protocol

from anteumbra.application.jsonl_consumer import JsonlEventTailer
from anteumbra.application.runtime_container import RuntimeContainer
from anteumbra.application.runtime_builder import (
    RuntimeLifecycleDependencies,
    build_runtime_lifecycle_dependencies,
)
from anteumbra.application.runtime_plugins import (
    _start_plugins,
)
from anteumbra.application.runtime_workers import (
    MonitorResourcePort,
    _migrate_site_metadata,
    _start_metrics,
    _start_profile_workers,
    _start_siem,
    _start_site_monitors,
    _start_sse,
    _start_waf_poller,
)
from anteumbra.application.runtime_health_service import assess_runtime_capabilities
from anteumbra.domain.runtime import (
    ConfigProviderPort,
)



logger = logging.getLogger(__name__)


class RuntimeStartupError(RuntimeError):
    """Raised when the complete runtime cannot be started safely."""


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
    process_identity: object | None = None
    web_server: RuntimeServerPort | None = None
    web_thread: threading.Thread | None = None
    profile_tailer: JsonlEventTailer | None = None
    sse_started: bool = False





class RuntimeLifecycle:
    """Start and stop one complete Anteumbra runtime without global state."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 8080,
        *,
        config_provider: ConfigProviderPort | None = None,
        dependencies: RuntimeLifecycleDependencies | None = None,
    ) -> None:
        self.host = host
        self.port = port
        self._config_provider = config_provider
        self._dependencies = dependencies or build_runtime_lifecycle_dependencies()
        self._lock = threading.RLock()
        self._state = RuntimeState()

    def run(self) -> None:
        """Start all runtime components and block until interrupted."""
        with self._lock:
            if self._state.running or self._state.stopping:
                raise RuntimeError("Runtime lifecycle is already active")

        dependencies = self._dependencies
        provider = self._config_provider or dependencies.config_provider_factory()
        config = provider.get()
        data_dir = dependencies.path_normalizer(config.get("paths", {}).get("data_dir", "data"))
        websites = provider.get_enabled_websites()
        if not websites:
            raise RuntimeStartupError("No enabled websites in config.toml")

        missing_paths: list[Path] = []
        for website in websites:
            website.path = dependencies.path_normalizer(website.path)
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
            container = dependencies.container_builder(config_provider=provider)
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
            state.process_identity = dependencies.process_identity_writer(pid_file, Path.cwd())
            state.warnings.extend(
                item["message"]
                for item in assess_runtime_capabilities(config)["warnings"]
            )

            print(f"Anteumbra v{dependencies.version_getter()} - Web Perimeter Security")
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
                alert_formatter=dependencies.alert_formatter,
            )
            container.plugin_manager = plugin_manager
            container.events.bind(plugin_manager)
            if container.ip_blocker is not None:
                container.ip_blocker.start()

            runtime_services = dependencies.runtime_services_builder(
                config,
                websites,
                event_publisher=container.events,
                registry=container.registry,
                metrics=container.metrics,
                quarantine=container.quarantine,
            )

            app = dependencies.app_factory(runtime=container)
            state.web_server = dependencies.server_factory(app, self.host, self.port)

            _migrate_site_metadata(container, state.warnings)
            monitors, log_monitors, site_warnings = _start_site_monitors(
                websites,
                runtime_services=runtime_services,
                logger_factory=container.logging.get_site_logger,
                config_provider=container.config,
                notifier=container.notifier,
                registry=container.registry,
                scan_callback=container.scanner.scan,
                monitor_factory=dependencies.monitor_factory,
                analyzer_factory=dependencies.analyzer_factory,
                log_monitor_factory=dependencies.log_monitor_factory,
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
            if state.pid_file and state.process_identity:
                self._dependencies.process_identity_remover(state.pid_file, state.process_identity)
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











def _stop_resource(name: str, callback: Callable[[], Any]) -> None:
    try:
        callback()
    except Exception:
        logger.exception("Failed to stop %s", name)
