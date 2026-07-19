"""Tests for the runtime-owned suspicious-file Registry."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from anteumbra.domain.site import SiteIdentity
from anteumbra.infrastructure.suspicious_registry import (
    RegistryDataError,
    RegistryPersistenceError,
    SuspiciousRegistry,
)
from anteumbra.infrastructure.wal_manager import WalManager


class ConfigStub:
    def __init__(self):
        self.compact_days = 30
        self.site_names = {"alpha": "Alpha", "beta": "Beta"}

    def get(self):
        return {"filesizes": {"registry_compact_days": self.compact_days}}

    def resolve_site_identity(
        self,
        file_path,
        site_id=None,
        site_name=None,
    ):
        if site_id:
            return SiteIdentity.from_values(
                site_id,
                self.site_names.get(site_id, site_name or site_id),
            )
        normalized = str(file_path).replace("\\", "/").lower()
        if "/alpha/" in normalized:
            return SiteIdentity("alpha", "Alpha")
        if "/beta/" in normalized:
            return SiteIdentity("beta", "Beta")
        return SiteIdentity.legacy()


class EventStub:
    def __init__(self):
        self.events = []

    def publish(self, event_type, source, payload):
        self.events.append((event_type, source, dict(payload)))


class ShadowStub:
    def __init__(self, records=None, fail=False):
        self.records = dict(records or {})
        self.fail = fail
        self.closed = False

    def save(self, record_id, data):
        if self.fail:
            raise RuntimeError("shadow unavailable")
        self.records[record_id] = dict(data)

    def delete(self, record_id):
        return self.records.pop(record_id, None) is not None

    def list_all(self, limit=100, offset=0):
        return list(self.records.values())[offset : offset + limit]

    def close(self):
        self.closed = True


@pytest.fixture
def registry_bundle(tmp_path):
    config = ConfigStub()
    events = EventStub()
    changes = []
    wal = WalManager(tmp_path / "registry_wal.log")
    registry = SuspiciousRegistry(
        tmp_path / "suspicious_registry.json",
        config=config,
        wal=wal,
        event_publisher=events,
        change_callback=lambda: changes.append("changed"),
    )
    return registry, wal, config, events, changes


def test_full_record_lifecycle_is_synchronous_and_durable(registry_bundle):
    registry, wal, config, events, changes = registry_bundle
    path = Path("/srv/alpha/shell.php")

    registry.add(path, ["eval"], "10.0.0.1", "active")
    registry.increment_access(path, "10.0.0.2")
    assert registry.mark_alerted(path) is True
    assert registry.mark_quarantined(path, "q-1") is True
    assert registry.mark_restored(path) is True
    assert registry.mark_false_positive(path, "reviewed") is True

    record = registry.get(path)
    assert record["site_id"] == "alpha"
    assert record["features"] == ["eval"]
    assert record["communication_count"] == 1
    assert record["alerted"] is True
    assert record["quarantine_id"] is None
    assert record["file_exists"] is True
    assert record["marked_false_positive"] is True
    assert registry.get_all() == []
    assert len(registry.get_all(include_false_positive=True)) == 1
    assert wal.read_entries(pending_only=True) == []
    assert len(events.events) == 6
    assert len(changes) == 6

    reloaded = SuspiciousRegistry(
        registry.path,
        config=config,
        wal=wal,
        event_publisher=events,
    )
    assert reloaded.get(path)["communication_count"] == 1


def test_duplicate_add_refreshes_one_record_without_crossing_sites(registry_bundle):
    registry, _, _, _, _ = registry_bundle
    path = Path("/shared/shell.php")
    alpha = SiteIdentity("alpha", "Alpha")
    beta = SiteIdentity("beta", "Beta")

    registry.add(path, ["first"], "1.1.1.1", site=alpha)
    registry.add(path, ["second"], "2.2.2.2", site=alpha)
    registry.add(path, ["beta"], "3.3.3.3", site=beta)

    assert len(registry.get_all(site_id="alpha")) == 1
    assert len(registry.get_all(site_id="beta")) == 1
    assert registry.get(path, "alpha")["features"] == ["second"]
    assert registry.get(path, "beta")["features"] == ["beta"]


def test_returned_records_are_defensive_copies(registry_bundle):
    registry, _, _, _, _ = registry_bundle
    path = Path("/srv/alpha/shell.php")
    registry.add(path, ["eval"])

    record = registry.get(path)
    record["features"].append("mutated")
    all_records = registry.get_all()
    all_records[0]["site_name"] = "Changed"

    persisted = registry.get(path)
    assert persisted["features"] == ["eval"]
    assert persisted["site_name"] == "Alpha"


def test_site_metadata_migration_refreshes_name_without_changing_id(registry_bundle):
    registry, _, config, _, _ = registry_bundle
    path = Path("/srv/alpha/shell.php")
    registry.add(path, ["eval"])
    config.site_names["alpha"] = "Renamed Alpha"

    assert registry.migrate_site_metadata() == 1
    record = registry.get(path, "alpha")
    assert record["site_id"] == "alpha"
    assert record["site_name"] == "Renamed Alpha"


def test_reload_persists_canonical_configured_site_name(registry_bundle):
    registry, _, config, events, _ = registry_bundle
    path = Path("/srv/alpha/shell.php")
    registry.add(path, ["eval"])
    config.site_names["alpha"] = "Renamed Alpha"

    reloaded = SuspiciousRegistry(
        registry.path,
        config=config,
        wal=WalManager(registry.path.with_name("reload_wal.log")),
        event_publisher=events,
    )

    assert reloaded.get(path, "alpha")["site_name"] == "Renamed Alpha"
    persisted = json.loads(registry.path.read_text(encoding="utf-8"))
    assert persisted[0]["site_id"] == "alpha"
    assert persisted[0]["site_name"] == "Renamed Alpha"


def test_remove_and_soft_delete_preserve_audit_records(registry_bundle):
    registry, _, _, _, _ = registry_bundle
    first = Path("/srv/alpha/first.php")
    second = Path("/srv/alpha/second.php")
    registry.add(first, ["eval"])
    registry.add(second, ["assert"])

    assert registry.remove(first) is True
    assert registry.soft_delete_record(second) is True
    assert registry.remove(Path("/srv/alpha/missing.php")) is False

    records = registry.get_all(include_deleted=True)
    assert len(records) == 2
    assert all(record["file_exists"] is False for record in records)
    assert all(record["deleted_at"] for record in records)


def test_failed_json_commit_stays_pending_and_replays_idempotently(
    registry_bundle, monkeypatch
):
    registry, wal, _, _, _ = registry_bundle
    path = Path("/srv/alpha/shell.php")
    registry.add(path, ["eval"])
    original_write = registry._atomic_write

    def fail_primary(target, content):
        if target == registry.path:
            raise OSError("disk full")
        original_write(target, content)

    monkeypatch.setattr(registry, "_atomic_write", fail_primary)
    with pytest.raises(RegistryPersistenceError, match="WAL transaction"):
        registry.increment_access(path, "10.0.0.1")

    assert registry.get(path)["communication_count"] == 0
    assert len(wal.read_entries(pending_only=True)) == 1

    monkeypatch.setattr(registry, "_atomic_write", original_write)
    assert registry.replay_wal() == 1
    assert registry.get(path)["communication_count"] == 1
    assert registry.replay_wal() == 0
    assert registry.get(path)["communication_count"] == 1


def test_backup_recovers_corrupt_primary(registry_bundle):
    registry, wal, config, events, _ = registry_bundle
    path = Path("/srv/alpha/shell.php")
    registry.add(path, ["eval"])
    registry.path.write_text("not-json", encoding="utf-8")

    recovered = SuspiciousRegistry(
        registry.path,
        config=config,
        wal=wal,
        event_publisher=events,
    )

    assert recovered.get(path)["features"] == ["eval"]
    assert isinstance(json.loads(registry.path.read_text(encoding="utf-8")), list)


def test_invalid_primary_and_backup_fail_explicitly(tmp_path):
    path = tmp_path / "registry.json"
    path.write_text("bad", encoding="utf-8")
    path.with_name("registry.json.bak").write_text("also-bad", encoding="utf-8")

    with pytest.raises(RegistryDataError, match="no valid recovery source"):
        SuspiciousRegistry(
            path,
            config=ConfigStub(),
            wal=WalManager(tmp_path / "wal.log"),
            event_publisher=EventStub(),
        )


def test_dict_format_is_migrated_to_canonical_list(tmp_path):
    path = tmp_path / "registry.json"
    path.write_text(
        json.dumps(
            {
                "/srv/alpha/shell.php": {
                    "detected_at": "2026-01-01T00:00:00",
                    "features": ["eval"],
                }
            }
        ),
        encoding="utf-8",
    )
    registry = SuspiciousRegistry(
        path,
        config=ConfigStub(),
        wal=WalManager(tmp_path / "wal.log"),
        event_publisher=EventStub(),
    )

    assert registry.get(Path("/srv/alpha/shell.php"))["site_id"] == "alpha"
    assert isinstance(json.loads(path.read_text(encoding="utf-8")), list)


def test_shadow_is_diagnostic_and_never_overrides_valid_json(tmp_path):
    shadow = ShadowStub(
        {
            "shadow:only": {
                "file_path": "/srv/beta/shadow.php",
                "detected_at": "2020-01-01T00:00:00",
                "features": ["shadow"],
            }
        }
    )
    path = tmp_path / "registry.json"
    path.write_text(
        json.dumps(
            [
                {
                    "file_path": "/srv/alpha/json.php",
                    "detected_at": "2026-01-01T00:00:00",
                    "features": ["json"],
                }
            ]
        ),
        encoding="utf-8",
    )

    registry = SuspiciousRegistry(
        path,
        config=ConfigStub(),
        wal=WalManager(tmp_path / "wal.log"),
        event_publisher=EventStub(),
        shadow_repository=shadow,
    )

    assert registry.get(Path("/srv/alpha/json.php")) is not None
    assert registry.get(Path("/srv/beta/shadow.php")) is None


def test_shadow_failure_does_not_undo_authoritative_json(tmp_path):
    registry = SuspiciousRegistry(
        tmp_path / "registry.json",
        config=ConfigStub(),
        wal=WalManager(tmp_path / "wal.log"),
        event_publisher=EventStub(),
        shadow_repository=ShadowStub(fail=True),
    )

    registry.add(Path("/srv/alpha/shell.php"), ["eval"])

    assert registry.get(Path("/srv/alpha/shell.php")) is not None
    assert registry.path.exists()


def test_compaction_removes_only_old_inactive_records(registry_bundle):
    registry, _, _, _, _ = registry_bundle
    old = Path("/srv/alpha/old.php")
    recent = Path("/srv/alpha/recent.php")
    active = Path("/srv/alpha/active.php")
    for path in (old, recent, active):
        registry.add(path, ["eval"])
    registry.soft_delete_record(old)
    registry.soft_delete_record(recent)

    records = json.loads(registry.path.read_text(encoding="utf-8"))
    next(record for record in records if record["file_path"].endswith("old.php"))[
        "detected_at"
    ] = (datetime.now(timezone.utc) - timedelta(days=60)).isoformat()
    serialized = json.dumps(records)
    registry.path.write_text(serialized, encoding="utf-8")
    registry.backup_path.write_text(serialized, encoding="utf-8")
    registry.reload()

    result = registry.compact(30)

    assert result == {"total": 3, "cleaned": 1, "remaining": 2}
    assert registry.get(old) is None
    assert registry.get(recent) is not None
    assert registry.get(active) is not None


def test_close_releases_injected_shadow(tmp_path):
    shadow = ShadowStub()
    registry = SuspiciousRegistry(
        tmp_path / "registry.json",
        config=ConfigStub(),
        wal=WalManager(tmp_path / "wal.log"),
        event_publisher=EventStub(),
        shadow_repository=shadow,
    )

    registry.close()

    assert shadow.closed is True
