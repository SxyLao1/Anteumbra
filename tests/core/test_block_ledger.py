# -*- coding: utf-8 -*-
"""v1.0.9: Unit tests for block_ledger.py — IP block audit ledger.

Tests cover: add_entry, get_by_ip, get_entries, get_stats, update_notes,
export_ledger (json + csv), remove_entry, and dedup behavior.
"""
import json
import os
import tempfile
from pathlib import Path

import pytest

# ── Fixtures ──────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def isolate_block_ledger(monkeypatch, tmp_path):
    """Force block_ledger to use a temp JSON file, bypass SQLite shadow."""
    from anteumbra.infrastructure import block_ledger as bl

    ledger_path = tmp_path / "block_ledger.json"
    monkeypatch.setattr(bl, "_LEDGER_PATH", ledger_path)
    monkeypatch.setattr(bl, "_LEDGER_CACHE", [])
    monkeypatch.setattr(bl, "_repo_shadow_save", lambda data: None)

    # Ensure save writes to temp path
    bl._LEDGER_PATH = ledger_path
    bl._LEDGER_CACHE = []
    yield bl


def test_json_ledger_is_authoritative_over_sqlite_shadow(
    isolate_block_ledger, monkeypatch
):
    from anteumbra.infrastructure import persistence

    ledger = isolate_block_ledger
    expected = [{"ip": "10.0.0.250", "source": "manual"}]
    ledger._LEDGER_PATH.write_text(json.dumps(expected), encoding="utf-8")

    def unexpected_shadow_read(_namespace):
        pytest.fail("a valid JSON ledger must not read the SQLite shadow")

    monkeypatch.setattr(persistence, "get_shadow_repository", unexpected_shadow_read)

    assert ledger._load() == expected


# ── Core CRUD Tests ───────────────────────────────────────────


class TestAddEntry:
    """Test add_entry() — create and dedup."""

    def test_add_single_entry(self, isolate_block_ledger):
        bl = isolate_block_ledger
        entry = bl.add_entry("10.0.0.1", source="scanner", reason="SQLMap detected")
        assert entry["ip"] == "10.0.0.1"
        assert entry["source"] == "scanner"
        assert entry["reason"] == "SQLMap detected"
        assert "blocked_at" in entry

    def test_add_entry_defaults(self, isolate_block_ledger):
        bl = isolate_block_ledger
        entry = bl.add_entry("10.0.0.2")
        assert entry["source"] == "manual"
        assert entry["blocked_by"] == "admin"
        assert entry["notes"] == ""

    def test_add_duplicate_updates_entry(self, isolate_block_ledger):
        bl = isolate_block_ledger
        bl.add_entry("10.0.0.3", reason="First block")
        entry = bl.add_entry("10.0.0.3", reason="Updated reason", source="waf")
        assert entry["reason"] == "Updated reason"
        assert entry["source"] == "waf"

    def test_add_entry_with_broadcast_results(self, isolate_block_ledger):
        bl = isolate_block_ledger
        broadcast = [{"device": "router1", "status": "ok"}]
        entry = bl.add_entry("10.0.0.4", broadcast_results=broadcast)
        # broadcast_results is destructured into broadcast_devices + broadcast_status
        assert "broadcast_devices" in entry
        assert "broadcast_status" in entry


class TestGetByIp:
    """Test get_by_ip() single-entry lookup."""

    def test_get_existing_ip(self, isolate_block_ledger):
        bl = isolate_block_ledger
        bl.add_entry("10.0.0.5", reason="Brute force")
        record = bl.get_by_ip("10.0.0.5")
        assert record is not None
        assert record["reason"] == "Brute force"

    def test_get_nonexistent_ip(self, isolate_block_ledger):
        bl = isolate_block_ledger
        record = bl.get_by_ip("192.168.99.99")
        assert record is None


class TestGetEntries:
    """Test get_entries() with pagination and filters."""

    def test_get_entries_returns_list(self, isolate_block_ledger):
        bl = isolate_block_ledger
        bl.add_entry("10.0.0.6")
        bl.add_entry("10.0.0.7")
        entries, total = bl.get_entries()
        assert total == 2
        assert len(entries) == 2

    def test_get_entries_pagination(self, isolate_block_ledger):
        bl = isolate_block_ledger
        for i in range(5):
            bl.add_entry(f"10.0.0.{10 + i}")
        entries, total = bl.get_entries(limit=3, offset=0)
        assert len(entries) == 3
        assert total == 5

    def test_get_entries_source_filter(self, isolate_block_ledger):
        bl = isolate_block_ledger
        bl.add_entry("10.0.0.20", source="scanner")
        bl.add_entry("10.0.0.21", source="waf")
        entries, total = bl.get_entries(source_filter="scanner")
        assert total == 1
        assert entries[0]["source"] == "scanner"

    def test_get_entries_search(self, isolate_block_ledger):
        bl = isolate_block_ledger
        bl.add_entry("10.0.0.30", reason="SQL injection")
        bl.add_entry("10.0.0.31", reason="XSS attack")
        entries, total = bl.get_entries(search="SQL")
        assert total == 1


class TestGetStats:
    """Test get_stats() aggregation."""

    def test_get_stats_empty(self, isolate_block_ledger):
        bl = isolate_block_ledger
        stats = bl.get_stats()
        assert stats["total"] == 0

    def test_get_stats_with_entries(self, isolate_block_ledger):
        bl = isolate_block_ledger
        bl.add_entry("10.0.0.40", source="auto")
        bl.add_entry("10.0.0.41", source="manual")
        bl.add_entry("10.0.0.42", source="auto")
        stats = bl.get_stats()
        assert stats["total"] == 3
        assert stats["auto"] == 2
        assert stats["manual"] == 1

    def test_get_stats_recent_count(self, isolate_block_ledger):
        bl = isolate_block_ledger
        bl.add_entry("10.0.0.50")
        stats = bl.get_stats()
        assert "today" in stats


class TestUpdateNotes:
    """Test update_notes() inline editing."""

    def test_update_notes_existing(self, isolate_block_ledger):
        bl = isolate_block_ledger
        bl.add_entry("10.0.0.60")
        result = bl.update_notes("10.0.0.60", "False positive — internal scanner")
        assert result is True
        record = bl.get_by_ip("10.0.0.60")
        assert record["notes"] == "False positive — internal scanner"

    def test_update_notes_nonexistent(self, isolate_block_ledger):
        bl = isolate_block_ledger
        result = bl.update_notes("10.99.99.99", "N/A")
        assert result is False


class TestExportLedger:
    """Test export_ledger() JSON and CSV formats."""

    def test_export_json(self, isolate_block_ledger):
        bl = isolate_block_ledger
        bl.add_entry("10.0.0.70", reason="Test export")
        exported = bl.export_ledger("json")
        data = json.loads(exported)
        assert isinstance(data, list)
        assert data[0]["ip"] == "10.0.0.70"

    def test_export_csv(self, isolate_block_ledger):
        bl = isolate_block_ledger
        bl.add_entry("10.0.0.80", reason="CSV test")
        exported = bl.export_ledger("csv")
        assert "10.0.0.80" in exported
        assert "CSV test" in exported

    def test_export_empty_ledger(self, isolate_block_ledger):
        bl = isolate_block_ledger
        exported = bl.export_ledger("json")
        assert exported == "[]"


class TestRemoveEntry:
    """Test remove_entry() — mark as removed."""

    def test_remove_existing(self, isolate_block_ledger):
        bl = isolate_block_ledger
        bl.add_entry("10.0.0.90")
        result = bl.remove_entry("10.0.0.90")
        assert result is True

    def test_remove_nonexistent(self, isolate_block_ledger):
        bl = isolate_block_ledger
        result = bl.remove_entry("10.99.99.99")
        assert result is False

    def test_remove_then_get_returns_none(self, isolate_block_ledger):
        bl = isolate_block_ledger
        bl.add_entry("10.0.0.91")
        bl.remove_entry("10.0.0.91")
        record = bl.get_by_ip("10.0.0.91")
        assert record is None


# ── Persistence Round-Trip ────────────────────────────────────


class TestPersistenceRoundTrip:
    """Test that entries survive save + reload."""

    def test_entries_persist_to_disk(self, isolate_block_ledger, tmp_path):
        bl = isolate_block_ledger
        bl.add_entry("10.0.0.100", reason="Persistence test")
        # Force save to disk
        bl._save(bl._LEDGER_CACHE)
        assert bl._LEDGER_PATH.exists()
        raw = bl._LEDGER_PATH.read_text(encoding="utf-8")
        assert "10.0.0.100" in raw

    def test_load_from_existing_file(self, isolate_block_ledger, tmp_path):
        bl = isolate_block_ledger
        # Write a pre-existing ledger file
        test_data = [
            {
                "ip": "10.0.0.101",
                "source": "waf",
                "reason": "Pre-existing",
                "blocked_at": "2026-07-04 12:00:00",
                "blocked_by": "auto",
                "notes": "",
                "broadcast_results": [],
            }
        ]
        bl._LEDGER_PATH.write_text(json.dumps(test_data), encoding="utf-8")
        bl._LEDGER_CACHE = bl._load()
        assert len(bl._LEDGER_CACHE) == 1
        assert bl._LEDGER_CACHE[0]["ip"] == "10.0.0.101"

    def test_load_corrupt_json_returns_empty(self, isolate_block_ledger, tmp_path):
        bl = isolate_block_ledger
        bl._LEDGER_PATH.write_text("{corrupt json!!!", encoding="utf-8")
        result = bl._load()
        assert result == []


# ── Edge Cases ────────────────────────────────────────────────


class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_add_entry_empty_reason(self, isolate_block_ledger):
        bl = isolate_block_ledger
        entry = bl.add_entry("10.0.0.200", reason="")
        assert entry["reason"] == ""

    def test_multiple_entries_same_source(self, isolate_block_ledger):
        bl = isolate_block_ledger
        bl.add_entry("10.0.0.210", source="auto")
        bl.add_entry("10.0.0.211", source="auto")
        bl.add_entry("10.0.0.212", source="auto")
        stats = bl.get_stats()
        assert stats["auto"] == 3
