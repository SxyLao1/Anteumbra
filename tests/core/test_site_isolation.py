"""Focused regression tests for the site-isolation architecture boundary."""

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


def test_config_registry_rejects_duplicate_site_ids(tmp_path):
    from anteumbra.infrastructure.config.registry import ConfigRegistry

    with pytest.raises(ValueError, match="Duplicate website.id"):
        ConfigRegistry._parse_websites(
            {
                "website": [
                    {"id": "same", "name": "Alpha", "path": str(tmp_path / "a"), "port": 80},
                    {"id": "same", "name": "Beta", "path": str(tmp_path / "b"), "port": 8080},
                ]
            }
        )


def test_registry_filters_records_by_explicit_site(tmp_path, monkeypatch):
    from anteumbra.infrastructure import suspicious_registry as registry

    registry_path = tmp_path / "registry.json"
    monkeypatch.setattr(registry, "_REGISTRY_PATH", registry_path)
    monkeypatch.setattr(registry, "_REGISTRY_BACKUP_PATH", registry_path.with_suffix(".bak"))
    monkeypatch.setattr(registry, "_last_registry_snapshot", None)
    monkeypatch.setattr(registry, "_async_save_enabled", False)
    monkeypatch.setattr(registry, "_ensure_initialized", lambda: None)
    monkeypatch.setattr(registry, "_save_registry", lambda _records: None)
    monkeypatch.setattr(registry, "_repo_shadow_save", lambda _records: None)
    monkeypatch.setattr(registry, "_repo_load_registry", lambda: None)

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


def test_registry_record_identity_includes_site_id(tmp_path, monkeypatch):
    from anteumbra.infrastructure import suspicious_registry as registry

    registry_path = tmp_path / "registry.json"
    monkeypatch.setattr(registry, "_REGISTRY_PATH", registry_path)
    monkeypatch.setattr(registry, "_REGISTRY_BACKUP_PATH", registry_path.with_suffix(".bak"))
    monkeypatch.setattr(registry, "_last_registry_snapshot", None)
    monkeypatch.setattr(registry, "_async_save_enabled", False)
    monkeypatch.setattr(registry, "_ensure_initialized", lambda: None)
    monkeypatch.setattr(registry, "_save_registry", lambda _records: None)
    monkeypatch.setattr(registry, "_save_registry_sync", lambda _records: True)
    monkeypatch.setattr(registry, "_repo_shadow_save", lambda _records: None)
    monkeypatch.setattr(registry, "_repo_load_registry", lambda: None)

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


def test_registry_shadow_store_keys_include_the_site(monkeypatch):
    from anteumbra.infrastructure import persistence, suspicious_registry as registry

    saved = []
    monkeypatch.setattr(
        persistence,
        "get_shadow_repository",
        lambda _namespace: SimpleNamespace(
            save=lambda record_id, data: saved.append((record_id, data))
        ),
    )

    registry._repo_shadow_save(
        [
            {
                "file_path": "C:/sites/shared.php",
                "site_id": "alpha",
                "site_name": "Alpha",
            },
            {
                "file_path": "C:/sites/shared.php",
                "site_id": "beta",
                "site_name": "Beta",
            },
        ]
    )

    assert [record_id for record_id, _ in saved] == [
        "alpha:C:/sites/shared.php",
        "beta:C:/sites/shared.php",
    ]


def test_quarantine_filters_records_by_site(tmp_path, monkeypatch):
    from anteumbra.infrastructure import quarantine

    quarantine_dir = tmp_path / "quarantine"
    db_path = quarantine_dir / "quarantine.json"
    quarantine_dir.mkdir(parents=True)
    db_path.write_text("[]", encoding="utf-8")
    monkeypatch.setattr(quarantine, "_quarantine_dir", quarantine_dir)
    monkeypatch.setattr(quarantine, "_quarantine_db", db_path)
    monkeypatch.setattr(quarantine, "_repo_shadow_save_quarantine", lambda _records: None)

    alpha_file = tmp_path / "alpha.php"
    beta_file = tmp_path / "beta.php"
    alpha_file.write_text("<?php", encoding="utf-8")
    beta_file.write_text("<?php", encoding="utf-8")

    quarantine.quarantine_file(
        str(alpha_file), "alpha-rule", ["alpha"], site_id="alpha", site_name="Alpha"
    )
    quarantine.quarantine_file(
        str(beta_file), "beta-rule", ["beta"], site_id="beta", site_name="Beta"
    )

    assert len(quarantine.get_quarantine_list(site_id="alpha")) == 1
    assert len(quarantine.get_quarantine_list(site_id="beta")) == 1
    assert quarantine.get_quarantine_stats(site_id="alpha")["quarantined"] == 1


def test_quarantine_batch_alert_carries_one_site_identity(monkeypatch):
    from types import SimpleNamespace

    from anteumbra.application import plugin_manager
    from anteumbra.plugins.quarantine_handler import QuarantineHandlerPlugin

    emitted = []
    monkeypatch.setattr(
        plugin_manager,
        "get_plugin_manager",
        lambda: SimpleNamespace(
            is_enabled=True,
            emit=lambda event_type, source, payload: emitted.append(
                (event_type, source, payload)
            ),
        ),
    )
    plugin = QuarantineHandlerPlugin()
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


def test_metrics_keep_global_compatibility_and_add_site_buckets(monkeypatch, tmp_path):
    from anteumbra.infrastructure import suspicious_registry
    from anteumbra.infrastructure.monitoring.metrics import MetricsCollector

    def records(*, include_deleted=False, include_false_positive=False, site_id=None):
        all_records = [
            {"file_path": "a", "site_id": "alpha"},
            {"file_path": "b", "site_id": "beta"},
        ]
        if not include_deleted and not include_false_positive:
            return all_records
        return all_records

    monkeypatch.setattr(suspicious_registry, "get_all", records)
    collector = MetricsCollector(tmp_path / "metrics.json")
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
    services = RuntimeServices(context, Registry(), Metrics(), events)
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


def test_quick_scan_respects_the_selected_site_extensions(monkeypatch, tmp_path):
    from types import SimpleNamespace

    from anteumbra.domain.entities import ScanResult
    from anteumbra.infrastructure.detection import scanner
    from anteumbra.infrastructure.models import ScanOptions

    sample = tmp_path / "shell.custom"
    sample.write_text("payload", encoding="utf-8")
    expected = ScanResult(sample, True, ["test-rule"], engine="test")
    monkeypatch.setattr(
        scanner,
        "get_scanner_chain",
        lambda _logger: SimpleNamespace(scan=lambda _path: expected),
    )

    result = scanner.quick_scan_yara(
        sample,
        ScanOptions(monitor_extensions=[".custom"]),
        __import__("logging").getLogger("test.site.extensions"),
    )

    assert result is expected


def test_manual_scan_preserves_an_explicit_site_identity(monkeypatch, tmp_path):
    from anteumbra.domain.entities import ScanResult
    from anteumbra.infrastructure import suspicious_registry
    from anteumbra.infrastructure.detection import manual_scanner
    from anteumbra.infrastructure.monitoring import metrics

    target = tmp_path / "manual"
    target.mkdir()
    sample = target / "shell.custom"
    sample.write_text("payload", encoding="utf-8")
    added = []
    scan_options = []

    monkeypatch.setattr(
        suspicious_registry,
        "get_all",
        lambda **_kwargs: [],
    )
    monkeypatch.setattr(
        suspicious_registry,
        "add",
        lambda path, features, **kwargs: added.append((path, features, kwargs)),
    )
    monkeypatch.setattr(
        manual_scanner,
        "quick_scan_yara",
        lambda path, options, _logger: (
            scan_options.append(options)
            or ScanResult(path, True, ["test-rule"], engine="test")
        ),
    )
    monkeypatch.setattr(
        metrics,
        "get_metrics",
        lambda: SimpleNamespace(increment_site=lambda *_args, **_kwargs: None),
    )

    result = manual_scanner.ManualScanner().scan_directory(
        target,
        extensions=[".custom"],
        site_id="alpha",
        site_name="Alpha",
    )

    assert result.status == "completed"
    assert result.site_id == "alpha"
    assert added[0][2]["site_id"] == "alpha"
    assert scan_options[0].monitor_extensions == [".custom"]


def test_dashboard_summary_keeps_aggregate_and_site_boundaries(monkeypatch):
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

    class Config:
        @staticmethod
        def get_enabled_websites():
            return [
                SimpleNamespace(site_id="alpha", name="Alpha"),
                SimpleNamespace(site_id="beta", name="Beta"),
            ]

    monkeypatch.setattr(dashboard_service, "get_all", get_all)
    monkeypatch.setattr(dashboard_service, "get_quarantine_stats", quarantine_stats)
    monkeypatch.setattr(dashboard_service, "ConfigRegistry", Config)
    monkeypatch.setattr(
        dashboard_service,
        "get_metrics",
        lambda: SimpleNamespace(get=lambda: {"sites": {"alpha": {"scan_total": 4}}}),
    )

    summary = dashboard_service.build_dashboard_summary()

    assert summary["aggregate"]["total_detections"] == 2
    assert summary["aggregate"]["false_positives"] == 1
    assert {site["site_id"] for site in summary["sites"]} == {"alpha", "beta"}
    assert summary["sites"][0]["metrics"] == {"scan_total": 4}
