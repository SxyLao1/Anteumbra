"""Focused regression tests for the site-isolation architecture boundary."""

import logging
from pathlib import Path
from types import SimpleNamespace

import pytest


def test_site_identity_resolves_the_most_specific_root():
    from anteumbra.domain.site import SiteIdentity, SiteResolver, SiteRoot

    resolver = SiteResolver(
        [
            SiteRoot(SiteIdentity("alpha", "Alpha"), "C:/sites/alpha"),
            SiteRoot(SiteIdentity("alpha-admin", "Alpha Admin"), "C:/sites/alpha/admin"),
        ]
    )

    assert resolver.resolve("C:/sites/alpha/index.php").site_id == "alpha"
    assert resolver.resolve("C:/sites/alpha/admin/shell.php").site_id == "alpha-admin"
    assert resolver.resolve("C:/outside/shell.php").site_id == "legacy"


def test_config_provider_rejects_duplicate_site_ids(tmp_path):
    from anteumbra.infrastructure.config.provider import parse_websites

    with pytest.raises(ValueError, match="Duplicate website.id"):
        parse_websites(
            {
                "website": [
                    {"id": "same", "name": "Alpha", "path": str(tmp_path / "a"), "port": 80},
                    {"id": "same", "name": "Beta", "path": str(tmp_path / "b"), "port": 8080},
                ]
            }
        )


def _registry(tmp_path, shadow=None):
    from anteumbra.domain.site import SiteIdentity
    from anteumbra.infrastructure.suspicious_registry import SuspiciousRegistry
    from anteumbra.infrastructure.wal_manager import WalManager

    config = SimpleNamespace(
        get=lambda: {"filesizes": {}},
        resolve_site_identity=lambda _path, site_id=None, site_name=None: (
            SiteIdentity.from_values(
                site_id or "legacy", site_name or "Legacy / unassigned"
            )
        ),
    )
    return SuspiciousRegistry(
        tmp_path / "registry.json",
        config=config,
        wal=WalManager(tmp_path / "wal.log"),
        event_publisher=SimpleNamespace(publish=lambda *_args, **_kwargs: None),
        shadow_repository=shadow,
    )


def test_registry_filters_records_by_explicit_site(tmp_path):
    registry = _registry(tmp_path)

    alpha_path = tmp_path / "alpha" / "shell.php"
    beta_path = tmp_path / "beta" / "shell.php"
    registry.add(alpha_path, ["alpha-rule"], site_id="alpha", site_name="Alpha")
    registry.add(beta_path, ["beta-rule"], site_id="beta", site_name="Beta")

    alpha = registry.get_all(site_id="alpha")
    beta = registry.get_all(site_id="beta")

    assert [record["site_id"] for record in alpha] == ["alpha"]
    assert [record["site_id"] for record in beta] == ["beta"]
    assert alpha[0]["features"] == ["alpha-rule"]
    assert beta[0]["features"] == ["beta-rule"]


def test_registry_record_identity_includes_site_id(tmp_path):
    registry = _registry(tmp_path)

    shared_path = tmp_path / "shared.php"
    registry.add(shared_path, ["alpha-rule"], site_id="alpha", site_name="Alpha")
    registry.add(shared_path, ["beta-rule"], site_id="beta", site_name="Beta")

    records = registry.get_all(
        include_deleted=True, include_false_positive=True
    )
    assert {record["site_id"] for record in records} == {"alpha", "beta"}
    assert registry.remove(shared_path, site_id="alpha") is True
    assert registry.get(shared_path, site_id="alpha")["file_exists"] is False
    assert registry.get(shared_path, site_id="beta")["file_exists"] is True


def test_registry_shadow_store_keys_include_the_site(tmp_path):
    saved = []
    shadow = SimpleNamespace(
        save=lambda record_id, data: saved.append((record_id, data)),
        delete=lambda _record_id: False,
        list_all=lambda **_kwargs: [],
    )
    registry = _registry(tmp_path, shadow=shadow)
    shared_path = Path("C:/sites/shared.php")

    registry.add(shared_path, ["alpha"], site_id="alpha", site_name="Alpha")
    registry.add(shared_path, ["beta"], site_id="beta", site_name="Beta")

    assert {record_id for record_id, _ in saved} == {
        f"alpha:{registry.get(shared_path, 'alpha')['file_path']}",
        f"beta:{registry.get(shared_path, 'beta')['file_path']}",
    }


def test_quarantine_filters_records_by_site(tmp_path):
    from anteumbra.domain.site import SiteIdentity
    from anteumbra.infrastructure.quarantine import QuarantineStore

    quarantine_dir = tmp_path / "quarantine"
    store = QuarantineStore(
        quarantine_dir,
        site_resolver=lambda _path, site_id=None, site_name=None: (
            SiteIdentity.from_values(site_id or "legacy", site_name or "Legacy")
        ),
    )

    alpha_file = tmp_path / "alpha.php"
    beta_file = tmp_path / "beta.php"
    alpha_file.write_text("<?php", encoding="utf-8")
    beta_file.write_text("<?php", encoding="utf-8")

    store.quarantine_file(
        alpha_file,
        "alpha-rule",
        ["alpha"],
        site=SiteIdentity("alpha", "Alpha"),
    )
    store.quarantine_file(
        beta_file,
        "beta-rule",
        ["beta"],
        site=SiteIdentity("beta", "Beta"),
    )

    assert len(store.list_records(site_id="alpha")) == 1
    assert len(store.list_records(site_id="beta")) == 1
    assert store.get_stats(site_id="alpha")["quarantined"] == 1


def test_quarantine_batch_alert_carries_one_site_identity(monkeypatch):
    from anteumbra.plugins.quarantine_handler import QuarantineHandlerPlugin

    emitted = []

    class Events:
        def publish(self, event_type, source, payload):
            emitted.append((event_type, source, payload))

    plugin = QuarantineHandlerPlugin(
        quarantine_file=lambda **_kwargs: None,
        recently_restored=lambda _path: False,
        events=Events(),
        runtime_config={},
        log=logging.getLogger("test.quarantine_handler"),
    )
    plugin.activate({"batch_threshold": 2})
    plugin._batch_state["alpha"] = {
        "count": 2,
        "last_flush": 0.0,
        "site_name": "Alpha",
    }

    plugin._flush_batch("alpha")

    assert len(emitted) == 1
    event_type, source, payload = emitted[0]
    assert (event_type, source) == ("alert_requested", "quarantine_handler")
    assert payload["batch_count"] == 2
    assert payload["site_id"] == "alpha"
    assert payload["site_name"] == "Alpha"


def test_threat_graph_handler_preserves_site_identity():
    from anteumbra.domain import DomainEvent
    from anteumbra.plugins.threat_graph_handler import ThreatGraphHandlerPlugin

    ingested = []
    filters = []
    emitted = []

    class Graph:
        def get_active_profiles(self, *, site_id=None):
            filters.append(site_id)
            return []

        def ingest_registry_entry(self, entry):
            ingested.append(entry)

    class Events:
        def publish(self, event_type, source, payload):
            emitted.append((event_type, source, payload))

    plugin = ThreatGraphHandlerPlugin(
        Graph(),
        Events(),
        log=logging.getLogger("test.threat_graph_handler"),
    )
    plugin.on_event(DomainEvent(
        "record_added",
        0,
        "registry",
        {
            "file_path": "/srv/alpha/shell.php",
            "site_id": "alpha",
            "site_name": "Alpha",
        },
    ))

    assert ingested[0]["site_id"] == "alpha"
    assert ingested[0]["site_name"] == "Alpha"
    assert filters == ["alpha", "alpha"]
    assert emitted == []


def test_metrics_keep_global_compatibility_and_add_site_buckets(tmp_path):
    from anteumbra.infrastructure.monitoring.metrics import MetricsCollector

    def records(*, include_deleted=False, include_false_positive=False, site_id=None):
        all_records = [
            {"file_path": "a", "site_id": "alpha"},
            {"file_path": "b", "site_id": "beta"},
        ]
        if not include_deleted and not include_false_positive:
            return all_records
        return all_records

    collector = MetricsCollector(
        tmp_path / "metrics.json", registry_reader=records
    )
    collector.increment_site("scan_total", "alpha", 3)
    collector.increment_site("scan_total", "beta", 2)

    snapshot = collector.get()

    assert snapshot["scan_suspicious"] == 2
    assert snapshot["sites"]["alpha"]["scan_total"] == 3
    assert snapshot["sites"]["beta"]["scan_total"] == 2
    assert snapshot["sites"]["alpha"]["registry_size"] == 1


def test_monitor_events_include_site_identity(tmp_path):
    from anteumbra.domain.runtime import RuntimeContext, RuntimeServices
    from anteumbra.infrastructure.models import ScanOptions, Website
    from anteumbra.infrastructure.monitoring.monitor import FileMonitorHandler

    class Registry:
        def add(self, *_args, **_kwargs):
            return None

        def remove(self, *_args, **_kwargs):
            return True

    class Metrics:
        def increment(self, *_args, **_kwargs):
            return None

        def increment_site(self, *_args, **_kwargs):
            return None

    class Events:
        def __init__(self):
            self.events = []

        def publish(self, event_type, source, payload):
            self.events.append((event_type, source, dict(payload)))

    website = Website("Alpha", tmp_path, 8080, site_id="alpha")
    context = RuntimeContext.from_websites({"quarantine": {}}, [website])
    events = Events()
    services = RuntimeServices(
        context,
        Registry(),
        Metrics(),
        events,
        SimpleNamespace(is_recently_restored=lambda _path: False),
    )
    handler = FileMonitorHandler(
        scan_callback=lambda *_args: None,
        scan_options=ScanOptions(monitor_extensions=[".php"]),
        base_path=tmp_path,
        logger=__import__("logging").getLogger("test.site.events"),
        website=website,
        services=services,
    )
    try:
        handler._emit_file_quarantined(
            str(tmp_path / "shell.php"), "rule", ["rule"], str(tmp_path / "shell.php")
        )
    finally:
        handler.shutdown()

    assert events.events[0][0] == "file_quarantined"
    assert events.events[0][2]["site_id"] == "alpha"
    assert events.events[0][2]["site_name"] == "Alpha"


def test_quick_scan_respects_the_selected_site_extensions(tmp_path):
    from types import SimpleNamespace

    from anteumbra.domain.entities import ScanResult
    from anteumbra.infrastructure.detection import scanner
    from anteumbra.infrastructure.models import ScanOptions

    sample = tmp_path / "shell.custom"
    sample.write_text("payload", encoding="utf-8")
    expected = ScanResult(sample, True, ["test-rule"], engine="test")
    scanner_service = SimpleNamespace(
        scan=lambda _path, _options, _logger: expected,
    )

    result = scanner.quick_scan_yara(
        sample,
        ScanOptions(monitor_extensions=[".custom"]),
        __import__("logging").getLogger("test.site.extensions"),
        scanner_service=scanner_service,
    )

    assert result is expected


def test_manual_scan_preserves_an_explicit_site_identity(tmp_path):
    from anteumbra.domain.entities import ScanResult
    from anteumbra.domain.site import SiteIdentity
    from anteumbra.infrastructure.detection import manual_scanner

    target = tmp_path / "manual"
    target.mkdir()
    sample = target / "shell.custom"
    sample.write_text("payload", encoding="utf-8")
    added = []
    scan_options = []

    registry = SimpleNamespace(
        get_all=lambda **_kwargs: [],
        add=lambda path, features, **kwargs: added.append(
            (path, features, kwargs)
        ),
    )
    scanner_service = SimpleNamespace(
        scan=lambda path, options, _logger: (
            scan_options.append(options)
            or ScanResult(path, True, ["test-rule"], engine="test")
        )
    )
    provider = SimpleNamespace(
        resolve_site_identity=lambda _path, site_id=None, site_name=None: (
            SiteIdentity.from_values(site_id, site_name or str(site_id))
        ),
        get_website=lambda _site_id: None,
        get=lambda: {},
    )
    metric_recorder = SimpleNamespace(increment_site=lambda *_args, **_kwargs: None)

    result = manual_scanner.ManualScanner(
        config_provider=provider,
        scanner_service=scanner_service,
        metrics=metric_recorder,
        registry=registry,
    ).scan_directory(
        target,
        extensions=[".custom"],
        site_id="alpha",
        site_name="Alpha",
    )

    assert result.status == "completed"
    assert result.site_id == "alpha"
    assert added[0][2]["site"].site_id == "alpha"
    assert scan_options[0].monitor_extensions == [".custom"]


def test_dashboard_summary_keeps_aggregate_and_site_boundaries():
    from anteumbra.application import dashboard_service

    records = [
        {
            "file_path": "C:/alpha/shell.php",
            "site_id": "alpha",
            "site_name": "Alpha",
            "features": ["alpha-rule"],
            "detected_at": "2026-01-01T01:00:00",
        },
        {
            "file_path": "C:/beta/shell.php",
            "site_id": "beta",
            "site_name": "Beta",
            "features": ["beta-rule"],
            "detected_at": "2026-01-01T02:00:00",
            "marked_false_positive": True,
        },
    ]

    def get_all(**kwargs):
        site_id = kwargs.get("site_id")
        return [record for record in records if not site_id or record["site_id"] == site_id]

    def quarantine_stats(site_id=None):
        counts = {
            None: {"total": 1, "quarantined": 1, "restored": 0, "deleted": 0},
            "alpha": {"total": 1, "quarantined": 1, "restored": 0, "deleted": 0},
            "beta": {"total": 0, "quarantined": 0, "restored": 0, "deleted": 0},
        }
        return counts[site_id]

    metrics = SimpleNamespace(get=lambda: {"sites": {"alpha": {"scan_total": 4}}})
    websites = [
        SimpleNamespace(site_id="alpha", name="Alpha"),
        SimpleNamespace(site_id="beta", name="Beta"),
    ]

    summary = dashboard_service.build_dashboard_summary(
        metrics=metrics,
        websites=websites,
        registry=SimpleNamespace(get_all=get_all),
        quarantine_stats_reader=quarantine_stats,
    )

    assert summary["aggregate"]["total_detections"] == 2
    assert summary["aggregate"]["false_positives"] == 1
    assert {site["site_id"] for site in summary["sites"]} == {"alpha", "beta"}
    assert summary["sites"][0]["metrics"] == {"scan_total": 4}
