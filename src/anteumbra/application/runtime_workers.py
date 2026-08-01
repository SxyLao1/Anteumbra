"""Start runtime monitors and background workers without lifecycle ownership."""

from __future__ import annotations

import logging
import threading
from pathlib import Path
from typing import Any, Callable, Protocol

from anteumbra.application.jsonl_consumer import JsonlEventTailer
from anteumbra.application.runtime_container import RuntimeContainer
from anteumbra.domain.runtime import (
    ConfigProviderPort,
    DetectionRegistryPort,
    RuntimeMetricsPort,
)
from anteumbra.domain.site import SiteIdentity
from anteumbra.domain.service_ports import (
    NotifierPort,
    SIEMExporterPort,
    SSEPort,
    ThreatGraphPort,
    WAFPollerPort,
)


logger = logging.getLogger(__name__)


class MonitorResourcePort(Protocol):
    """Lifecycle surface shared by file and access-log monitors."""

    @property
    def is_running(self) -> bool:
        """Return whether the monitor worker is active."""

    def start(self) -> None:
        """Start monitoring."""

    def stop(self) -> None:
        """Stop monitoring."""


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
    logger_factory: Callable[[SiteIdentity], logging.Logger] | None = None,
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
        site = SiteIdentity.from_values(website.site_id, website.name)
        site_logger = logger_factory(site)
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
