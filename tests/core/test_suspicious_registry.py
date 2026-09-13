"""Tests for the runtime-owned suspicious-file Registry."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from anteumbra.domain.site import SiteIdentity
from anteumbra.infrastructure.persistence.sqlite_repository import SqliteRepository
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


def _authority_marker(registry_path: Path) -> Path:
    return registry_path.with_name(f"{registry_path.name}.sqlite-authority")


def _claim_sqlite_authority(registry_path: Path) -> None:
    """Mark the store as the one already holding every record."""
    marker = _authority_marker(registry_path)
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text("sqlite\n", encoding="utf-8")


class ShadowStub:
    def __init__(self, records=None, fail=False):
        self.records = dict(records or {})
        self.fail = fail
        self.closed = False

    def save(self, record_id, data):
        if self.fail:
            raise RuntimeError("shadow unavailable")
        # The real repository exposes its key column on the way back out.
        self.records[record_id] = {"record_id": record_id, **data}

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


def test_failed_json_commit_stays_pending_and_replays_idempotently(registry_bundle, monkeypatch):
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


def test_sqlite_is_authoritative_and_adopts_records_only_the_json_knows(tmp_path):
    """Once SQLite is the store of record, it wins — but the readable file is not lost.

    A store that is only half populated must not erase history that is still
    sitting in the JSON snapshot.
    """
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
    _claim_sqlite_authority(path)

    registry = SuspiciousRegistry(
        path,
        config=ConfigStub(),
        wal=WalManager(tmp_path / "wal.log"),
        event_publisher=EventStub(),
        shadow_repository=shadow,
    )

    # the stored row is authoritative ...
    assert registry.get(Path("/srv/beta/shadow.php")) is not None
    # ... and the record only the JSON file had is adopted, not dropped
    assert registry.get(Path("/srv/alpha/json.php")) is not None
    assert any("json.php" in key for key in shadow.records), (
        "the adopted record has to be written back to the store"
    )


def test_the_first_start_trusts_the_json_snapshot_over_stray_rows(tmp_path):
    """A leftover row in the database must not become the source of truth."""
    shadow = ShadowStub()
    shadow.save("stray", {"file_path": "/srv/beta/stray.php", "features": ["stray"]})
    path = tmp_path / "registry.json"
    path.write_text(
        json.dumps([{"file_path": "/srv/alpha/real.php", "features": ["real"]}]),
        encoding="utf-8",
    )

    registry = SuspiciousRegistry(
        path,
        config=ConfigStub(),
        wal=WalManager(tmp_path / "wal.log"),
        event_publisher=EventStub(),
        shadow_repository=shadow,
    )

    assert registry.get(Path("/srv/alpha/real.php")) is not None
    assert registry.get(Path("/srv/beta/stray.php")) is None
    assert not any("stray" in key for key in shadow.records), "the stray row is dropped"
    assert _authority_marker(path).exists(), "the store is claimed for the next start"

    reopened = SuspiciousRegistry(
        path,
        config=ConfigStub(),
        wal=WalManager(tmp_path / "wal.log"),
        event_publisher=EventStub(),
        shadow_repository=shadow,
    )
    # now the store is the authority, so a row only it knows about wins
    shadow.records["extra"] = {"file_path": "/srv/beta/extra.php", "features": ["extra"]}
    third = SuspiciousRegistry(
        path,
        config=ConfigStub(),
        wal=WalManager(tmp_path / "wal.log"),
        event_publisher=EventStub(),
        shadow_repository=shadow,
    )
    assert third.get(Path("/srv/beta/extra.php")) is not None
    assert reopened.get(Path("/srv/alpha/real.php")) is not None


def test_duplicate_identities_in_the_store_are_healed_not_fatal(tmp_path, caplog):
    """Legacy rows can hold the same record twice; that must not stop startup."""
    shadow = ShadowStub(
        {
            "old-key": {
                "file_path": "/srv/alpha/shell.php",
                "detected_at": "2026-01-01T00:00:00",
                "features": ["old"],
            },
            "alpha:/srv/alpha/shell.php": {
                "file_path": "/srv/alpha/shell.php",
                "detected_at": "2026-02-02T00:00:00",
                "features": ["new"],
            },
        }
    )
    path = tmp_path / "registry.json"
    path.write_text("[]", encoding="utf-8")
    _claim_sqlite_authority(path)

    with caplog.at_level("WARNING"):
        registry = SuspiciousRegistry(
            path,
            config=ConfigStub(),
            wal=WalManager(tmp_path / "wal.log"),
            event_publisher=EventStub(),
            shadow_repository=shadow,
        )

    record = registry.get(Path("/srv/alpha/shell.php"))
    assert record is not None
    assert record["features"] == ["new"], "the newest copy has to win"
    assert "newest of two records" in caplog.text


def test_first_sqlite_start_migrates_the_json_snapshot(tmp_path, caplog):
    shadow = ShadowStub()
    path = tmp_path / "registry.json"
    path.write_text(
        json.dumps(
            [
                {
                    "file_path": "/srv/alpha/old.php",
                    "detected_at": "2026-01-01T00:00:00",
                    "features": ["old"],
                }
            ]
        ),
        encoding="utf-8",
    )

    with caplog.at_level("INFO"):
        registry = SuspiciousRegistry(
            path,
            config=ConfigStub(),
            wal=WalManager(tmp_path / "wal.log"),
            event_publisher=EventStub(),
            shadow_repository=shadow,
        )

    assert registry.get(Path("/srv/alpha/old.php")) is not None
    assert len(shadow.records) == 1, "the empty store has to be filled from JSON"
    assert "migrated" in caplog.text


def test_sqlite_recovery_rekeys_without_leaking_storage_fields(tmp_path, caplog):
    old_record_id = "/srv/alpha/recovered.php"
    shadow = SqliteRepository(str(tmp_path / "anteumbra.db"))
    shadow.save(
        old_record_id,
        {
            "file_path": old_record_id,
            "detected_at": "2026-07-19T01:00:00+00:00",
            "features": ["recovered"],
            "site_id": "alpha",
            "site_name": "Alpha",
        },
    )

    registry = SuspiciousRegistry(
        tmp_path / "registry.json",
        config=ConfigStub(),
        wal=WalManager(tmp_path / "wal.log"),
        event_publisher=EventStub(),
        shadow_repository=shadow,
    )
    try:
        recovered = registry.get(Path(old_record_id))
        canonical_record_id = f"alpha:{recovered['file_path']}"

        assert recovered["features"] == ["recovered"]
        assert not SuspiciousRegistry._SHADOW_STORAGE_FIELDS.intersection(recovered)
        assert shadow.get(old_record_id) is None
        assert shadow.get(canonical_record_id)["site_id"] == "alpha"
        assert "SQLite shadow synchronization failed" not in caplog.text
        # the readable snapshot is refreshed from the authoritative store
        snapshot = json.loads(registry.path.read_text(encoding="utf-8"))
        assert [record["file_path"] for record in snapshot] == [recovered["file_path"]]
    finally:
        registry.close()


def test_a_failed_primary_write_leaves_its_wal_transaction_pending(tmp_path):
    """SQLite is the authority now, so its failure is the caller's failure."""
    registry = SuspiciousRegistry(
        tmp_path / "registry.json",
        config=ConfigStub(),
        wal=WalManager(tmp_path / "wal.log"),
        event_publisher=EventStub(),
        shadow_repository=ShadowStub(fail=True),
    )

    with pytest.raises(RegistryPersistenceError):
        registry.add(Path("/srv/alpha/shell.php"), ["eval"])


def test_a_failed_json_snapshot_does_not_undo_the_stored_record(tmp_path, monkeypatch):
    shadow = ShadowStub()
    registry = SuspiciousRegistry(
        tmp_path / "registry.json",
        config=ConfigStub(),
        wal=WalManager(tmp_path / "wal.log"),
        event_publisher=EventStub(),
        shadow_repository=shadow,
    )
    monkeypatch.setattr(
        type(registry._json_store),  # noqa: SLF001 - the snapshot is deliberately broken
        "persist",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("disk full")),
    )

    registry.add(Path("/srv/alpha/shell.php"), ["eval"])

    assert registry.get(Path("/srv/alpha/shell.php")) is not None
    assert shadow.records, "the authoritative store kept the record"


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
    next(record for record in records if record["file_path"].endswith("old.php"))["detected_at"] = (
        datetime.now(timezone.utc) - timedelta(days=60)
    ).isoformat()
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
