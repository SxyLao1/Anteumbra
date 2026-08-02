"""Behavioral tests for the runtime-owned block audit ledger."""

import json

import pytest

from anteumbra.domain.site import SiteIdentity
from anteumbra.infrastructure.block_ledger import (
    BlockLedger,
    BlockLedgerPersistenceError,
)


class MemoryShadow:
    def __init__(self, records=(), *, fail_save=False, fail_load=False):
        self.records = {
            str(item.get("record_id", index)): dict(item) for index, item in enumerate(records)
        }
        self.fail_save = fail_save
        self.fail_load = fail_load
        self.closed = False
        self.load_calls = 0

    def save(self, record_id, data):
        if self.fail_save:
            raise OSError("shadow unavailable")
        self.records[record_id] = dict(data)

    def get(self, record_id):
        return self.records.get(record_id)

    def list_all(self, limit=100, offset=0):
        self.load_calls += 1
        if self.fail_load:
            raise OSError("shadow unavailable")
        return list(self.records.values())[offset : offset + limit]

    def query(self, filters, limit=100, offset=0):
        records = [
            item
            for item in self.records.values()
            if all(item.get(key) == value for key, value in filters.items())
        ]
        return records[offset : offset + limit]

    def delete(self, record_id):
        return self.records.pop(record_id, None) is not None

    def count(self, filters=None):
        return len(self.query(filters or {}, limit=1_000_000))

    def close(self):
        self.closed = True


class EventRecorder:
    def __init__(self):
        self.events = []

    def publish(self, event_type, source, payload):
        self.events.append((event_type, source, dict(payload)))


@pytest.fixture
def alpha():
    return SiteIdentity("alpha", "Alpha")


@pytest.fixture
def beta():
    return SiteIdentity("beta", "Beta")


@pytest.fixture
def ledger(tmp_path):
    return BlockLedger(tmp_path / "block_ledger.json")


def test_add_persists_site_owned_record(ledger, alpha):
    entry = ledger.add_entry(
        "10.0.0.1",
        site=alpha,
        source="scanner",
        reason="SQLMap detected",
        broadcast_results=[{"device": "waf", "success": True}],
    )

    assert entry["record_id"] == "alpha|10.0.0.1"
    assert entry["site_id"] == "alpha"
    assert entry["broadcast_status"] == "success"
    assert json.loads(ledger.path.read_text(encoding="utf-8"))[0]["site_name"] == "Alpha"


def test_same_ip_is_independent_across_sites(ledger, alpha, beta):
    ledger.add_entry("10.0.0.2", site=alpha, reason="alpha reason")
    ledger.add_entry("10.0.0.2", site=beta, reason="beta reason")

    assert ledger.get_by_ip("10.0.0.2", site_id="alpha")["reason"] == "alpha reason"
    assert ledger.get_by_ip("10.0.0.2", site_id="beta")["reason"] == "beta reason"
    assert ledger.get_entries(site_id="alpha")[1] == 1
    assert ledger.get_entries()[1] == 2


def test_duplicate_updates_only_its_site_and_preserves_notes(ledger, alpha, beta):
    ledger.add_entry("10.0.0.3", site=alpha, reason="first")
    ledger.update_notes("10.0.0.3", "reviewed", site_id="alpha")
    ledger.add_entry("10.0.0.3", site=beta, reason="beta")
    updated = ledger.add_entry("10.0.0.3", site=alpha, reason="second", source="auto")

    assert updated["reason"] == "second"
    assert updated["notes"] == "reviewed"
    assert ledger.get_by_ip("10.0.0.3", site_id="beta")["reason"] == "beta"


def test_filters_and_stats_respect_site_boundary(ledger, alpha, beta):
    ledger.add_entry("10.0.0.4", site=alpha, source="auto", reason="SQL injection")
    ledger.add_entry("10.0.0.5", site=alpha, source="manual", reason="XSS")
    ledger.add_entry("10.0.0.6", site=beta, source="auto", reason="SQL injection")

    entries, total = ledger.get_entries(site_id="alpha", source_filter="auto", search="SQL")
    stats = ledger.get_stats(site_id="alpha")

    assert total == 1
    assert entries[0]["ip"] == "10.0.0.4"
    assert stats == {"total": 2, "auto": 1, "manual": 1, "today": 2, "blocked": 2, "unblocked": 0}


def test_mark_unblocked_retains_audit_history(ledger, alpha):
    ledger.add_entry("10.0.0.7", site=alpha)

    assert ledger.mark_unblocked("10.0.0.7", site_id="alpha", unblocked_by="operator")
    record = ledger.get_by_ip("10.0.0.7", site_id="alpha")

    assert record["status"] == "unblocked"
    assert record["unblocked_by"] == "operator"
    assert record["unblocked_at"]
    assert ledger.get_stats(site_id="alpha")["unblocked"] == 1


def test_update_and_delete_cannot_cross_site(ledger, alpha, beta):
    ledger.add_entry("10.0.0.8", site=alpha)

    assert not ledger.update_notes("10.0.0.8", "wrong", site_id=beta.site_id)
    assert not ledger.remove_entry("10.0.0.8", site_id=beta.site_id)
    assert ledger.get_by_ip("10.0.0.8", site_id=alpha.site_id) is not None
    assert ledger.remove_entry("10.0.0.8", site_id=alpha.site_id)


def test_valid_json_is_authoritative_and_reconciles_shadow(tmp_path, alpha):
    path = tmp_path / "block_ledger.json"
    path.write_text(
        json.dumps([{"ip": "10.0.0.9", **alpha.as_dict(), "blocked_at": "2026-01-01"}]),
        encoding="utf-8",
    )
    shadow = MemoryShadow(
        [
            {
                "record_id": "alpha|10.0.0.9",
                "ip": "10.0.0.9",
                **alpha.as_dict(),
                "blocked_at": "2025-01-01",
                "reason": "stale",
            }
        ]
    )
    ledger = BlockLedger(path, shadow_repository=shadow)

    assert ledger.get_by_ip("10.0.0.9", site_id="alpha")["reason"] == ""
    assert shadow.records["alpha|10.0.0.9"]["reason"] == ""


def test_missing_json_recovers_shadow_and_rebuilds_primary(tmp_path, alpha):
    record = {
        "record_id": "alpha|10.0.0.10",
        "ip": "10.0.0.10",
        **alpha.as_dict(),
        "blocked_at": "2026-01-01T00:00:00+00:00",
    }
    shadow = MemoryShadow([record])
    ledger = BlockLedger(tmp_path / "block_ledger.json", shadow_repository=shadow)

    assert ledger.get_by_ip("10.0.0.10", site_id="alpha")["site_name"] == "Alpha"
    assert ledger.path.exists()


def test_corrupt_primary_without_recovery_raises(tmp_path):
    path = tmp_path / "block_ledger.json"
    path.write_text("{not json", encoding="utf-8")
    ledger = BlockLedger(path)

    with pytest.raises(BlockLedgerPersistenceError, match="cannot load authoritative"):
        ledger.get_entries()


def test_primary_write_failure_is_not_reported_as_success(tmp_path, alpha):
    parent_file = tmp_path / "not-a-directory"
    parent_file.write_text("occupied", encoding="utf-8")
    ledger = BlockLedger(parent_file / "block_ledger.json")

    with pytest.raises(BlockLedgerPersistenceError, match="cannot persist authoritative"):
        ledger.add_entry("10.0.0.11", site=alpha)


def test_shadow_failure_is_diagnostic_but_primary_succeeds(tmp_path, alpha):
    shadow = MemoryShadow(fail_save=True)
    ledger = BlockLedger(tmp_path / "block_ledger.json", shadow_repository=shadow)

    entry = ledger.add_entry("10.0.0.12", site=alpha)

    assert entry["ip"] == "10.0.0.12"
    assert ledger.path.exists()
    assert "save: OSError: shadow unavailable" in ledger.shadow_errors


def test_events_include_site_identity(tmp_path, alpha):
    events = EventRecorder()
    ledger = BlockLedger(tmp_path / "block_ledger.json", event_publisher=events)

    ledger.add_entry("10.0.0.13", site=alpha)
    ledger.mark_unblocked("10.0.0.13", site_id="alpha")

    assert [item[0] for item in events.events] == ["block_executed", "block_removed"]
    assert all(item[2]["site_id"] == "alpha" for item in events.events)


def test_legacy_record_is_migrated_to_explicit_bucket(tmp_path):
    path = tmp_path / "block_ledger.json"
    path.write_text(
        json.dumps([{"ip": "10.0.0.14", "blocked_at": "2026-01-01"}]),
        encoding="utf-8",
    )
    ledger = BlockLedger(path)

    assert ledger.get_by_ip("10.0.0.14", site_id="legacy")["site_name"] == "Legacy / unassigned"


def test_csv_export_neutralizes_formula_values(ledger, alpha):
    ledger.add_entry("10.0.0.15", site=alpha, reason='=HYPERLINK("bad")')

    exported = ledger.export_ledger("csv", site_id="alpha")

    assert "'=HYPERLINK" in exported


def test_invalid_ip_and_format_are_rejected(ledger, alpha):
    with pytest.raises(ValueError, match="invalid IP"):
        ledger.add_entry("not-an-ip", site=alpha)
    with pytest.raises(ValueError, match="format"):
        ledger.export_ledger("xml")


def test_close_releases_shadow(tmp_path):
    shadow = MemoryShadow()
    ledger = BlockLedger(tmp_path / "block_ledger.json", shadow_repository=shadow)

    ledger.close()

    assert shadow.closed
