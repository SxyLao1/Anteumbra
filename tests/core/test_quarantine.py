# -*- coding: utf-8 -*-
"""v1.0.9: Unit tests for quarantine.py — file quarantine management.

Tests cover: quarantine_file, restore_file, delete_quarantine,
get_quarantine_list, get_quarantine_detail, get_quarantine_stats,
is_recently_restored, and DB resilience.
"""
import json
import os
import time
from pathlib import Path

import pytest

# ── Fixtures ──────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def isolate_quarantine(monkeypatch, tmp_path):
    """Force quarantine to use temp paths, bypass SQLite shadow + ConfigRegistry."""
    from anteumbra.infrastructure import quarantine as q
    from anteumbra.infrastructure.config import registry as cfg_reg

    q_dir = tmp_path / "quarantine"
    q_dir.mkdir(parents=True, exist_ok=True)
    db_path = q_dir / "quarantine.json"

    # Stub ConfigRegistry — _load_db checks backend config
    monkeypatch.setattr(
        cfg_reg.ConfigRegistry, "get_raw_config",
        lambda: {"storage": {"backend": "json"}},
    )

    monkeypatch.setattr(q, "_quarantine_dir", q_dir)
    monkeypatch.setattr(q, "_quarantine_db", db_path)
    monkeypatch.setattr(q, "_recently_restored", {})
    monkeypatch.setattr(q, "_repo_shadow_save_quarantine", lambda data: None)

    # Ensure clean state
    q._quarantine_dir = q_dir
    q._quarantine_db = db_path
    q._recently_restored = {}
    # Pre-create empty DB to prevent recovery-scan creating duplicates
    db_path.write_text("[]", encoding="utf-8")

    yield q, q_dir, db_path

    # Teardown
    if db_path.exists():
        db_path.unlink()


@pytest.fixture
def sample_file(tmp_path):
    """Create a real file for quarantine testing."""
    f = tmp_path / "evil.php"
    f.write_text("<?php eval($_GET['cmd']); ?>")
    return f


# ── Quarantine File Tests ─────────────────────────────────────


class TestQuarantineFile:
    """Test quarantine_file() — move + record."""

    def test_quarantine_moves_file(self, isolate_quarantine, sample_file):
        q, q_dir, _ = isolate_quarantine
        result = q.quarantine_file(
            str(sample_file), rule_name="php_eval",
            features=["eval", "php"], original_path=str(sample_file),
        )
        assert result is not None
        assert "quarantine_id" in result
        assert not sample_file.exists()  # Moved out

    def test_quarantine_creates_record(self, isolate_quarantine, sample_file):
        q, q_dir, _ = isolate_quarantine
        result = q.quarantine_file(str(sample_file), "test_rule", ["f1"])
        assert result["rule_name"] == "test_rule"
        assert result["features"] == ["f1"]
        assert result["status"] == "quarantined"

    def test_quarantine_nonexistent_file(self, isolate_quarantine):
        q, q_dir, _ = isolate_quarantine
        result = q.quarantine_file("/nonexistent/path/shell.php", "test", [])
        assert result is None

    def test_quarantine_file_assigns_unique_ids(self, isolate_quarantine, tmp_path):
        q, q_dir, _ = isolate_quarantine
        f1 = tmp_path / "a.php"; f1.write_text("<?php ?>")
        f2 = tmp_path / "b.php"; f2.write_text("<?php ?>")
        r1 = q.quarantine_file(str(f1), "r1", ["a"])
        r2 = q.quarantine_file(str(f2), "r2", ["b"])
        assert r1["quarantine_id"] != r2["quarantine_id"]


# ── Quarantine List / Detail / Stats ──────────────────────────


class TestGetQuarantineList:
    """Test get_quarantine_list() with filters and pagination."""

    def test_get_list_empty(self, isolate_quarantine):
        q, _, _ = isolate_quarantine
        records = q.get_quarantine_list()
        assert records == []

    def test_get_list_with_entries(self, isolate_quarantine, sample_file):
        q, _, _ = isolate_quarantine
        q.quarantine_file(str(sample_file), "rule_a", ["f1"])
        records = q.get_quarantine_list()
        assert len(records) == 1

    def test_get_list_status_filter(self, isolate_quarantine, tmp_path):
        q, _, _ = isolate_quarantine
        f = tmp_path / "test.php"; f.write_text("data")
        q.quarantine_file(str(f), "rule", ["f1"])
        records = q.get_quarantine_list(status="quarantined")
        assert len(records) == 1
        records = q.get_quarantine_list(status="restored")
        assert len(records) == 0

    def test_get_list_pagination(self, isolate_quarantine, tmp_path):
        q, _, _ = isolate_quarantine
        for i in range(5):
            f = tmp_path / f"file_{i}.php"; f.write_text("test")
            q.quarantine_file(str(f), f"rule_{i}", [f"f_{i}"])
        records = q.get_quarantine_list(limit=3, offset=0)
        assert len(records) == 3

    def test_duplicate_qid_prefers_complete_record(self, isolate_quarantine, tmp_path):
        q, q_dir, db_path = isolate_quarantine
        quarantined = q_dir / "Q-20260101010101-ABCDEF12_shell.php"
        quarantined.write_text("payload", encoding="utf-8")
        original = tmp_path / "shell.php"
        complete = {
            "quarantine_id": "Q-20260101010101-ABCDEF12",
            "original_path": str(original),
            "quarantine_path": str(quarantined),
            "quarantine_time": "2026-01-01T01:01:01",
            "rule_name": "php_eval",
            "features": ["eval"],
            "file_size": 7,
            "status": "quarantined",
        }
        recovered = {
            **complete,
            "original_path": "(recovered)/shell.php",
            "rule_name": "(auto-recovered from disk)",
            "features": ["(recovered)"],
        }
        db_path.write_text(json.dumps([recovered, complete]), encoding="utf-8")

        records = q.get_quarantine_list()

        assert len(records) == 1
        assert records[0]["original_path"] == str(original)
        assert records[0]["rule_name"] == "php_eval"


class TestGetQuarantineDetail:
    """Test get_quarantine_detail() single record lookup."""

    def test_get_detail_existing(self, isolate_quarantine, sample_file):
        q, _, _ = isolate_quarantine
        result = q.quarantine_file(str(sample_file), "detail_rule", ["f1"])
        detail = q.get_quarantine_detail(result["quarantine_id"])
        assert detail is not None
        assert detail["rule_name"] == "detail_rule"

    def test_get_detail_nonexistent(self, isolate_quarantine):
        q, _, _ = isolate_quarantine
        detail = q.get_quarantine_detail("nonexistent-id")
        assert detail is None


class TestGetQuarantineStats:
    """Test get_quarantine_stats() aggregation."""

    def test_get_stats_empty(self, isolate_quarantine):
        q, _, _ = isolate_quarantine
        stats = q.get_quarantine_stats()
        assert stats["total"] == 0

    def test_get_stats_with_entries(self, isolate_quarantine, sample_file):
        q, _, _ = isolate_quarantine
        q.quarantine_file(str(sample_file), "r1", ["f1"])
        stats = q.get_quarantine_stats()
        assert stats["total"] == 1
        assert stats["quarantined"] == 1


# ── Restore Tests ─────────────────────────────────────────────


class TestRestoreFile:
    """Test restore_file() — undo quarantine."""

    def test_restore_restores_file(self, isolate_quarantine, sample_file):
        q, _, _ = isolate_quarantine
        original_content = sample_file.read_text()
        result = q.quarantine_file(str(sample_file), "test", ["f1"])
        restored = q.restore_file(result["quarantine_id"])
        assert restored is not None
        assert restored["status"] == "restored"
        assert sample_file.exists()
        assert sample_file.read_text() == original_content

    def test_restore_nonexistent_id(self, isolate_quarantine):
        q, _, _ = isolate_quarantine
        with pytest.raises(ValueError):
            q.restore_file("nonexistent-qid")

    def test_restore_sets_recently_restored(self, isolate_quarantine, sample_file):
        q, _, _ = isolate_quarantine
        result = q.quarantine_file(str(sample_file), "test", ["f1"])
        q.restore_file(result["quarantine_id"])
        assert q.is_recently_restored(str(sample_file)) is True


# ── Delete Quarantine Tests ───────────────────────────────────


class TestDeleteQuarantine:
    """Test delete_quarantine() — permanent deletion."""

    def test_delete_removes_record(self, isolate_quarantine, sample_file):
        q, _, _ = isolate_quarantine
        result = q.quarantine_file(str(sample_file), "test", ["f1"])
        q.delete_quarantine(result["quarantine_id"])
        detail = q.get_quarantine_detail(result["quarantine_id"])
        # delete_quarantine sets status to "deleted" — record still exists
        assert detail is not None
        assert detail["status"] == "deleted"

    def test_delete_nonexistent(self, isolate_quarantine):
        q, _, _ = isolate_quarantine
        with pytest.raises(ValueError, match="不存在"):
            q.delete_quarantine("nonexistent-qid")


# ── Is Recently Restored Tests ────────────────────────────────


class TestIsRecentlyRestored:
    """Test is_recently_restored() 30s whitelist."""

    def test_not_restored_by_default(self, isolate_quarantine):
        q, _, _ = isolate_quarantine
        assert q.is_recently_restored("/some/file.php") is False

    def test_is_restored_after_restore(self, isolate_quarantine, sample_file):
        q, _, _ = isolate_quarantine
        result = q.quarantine_file(str(sample_file), "test", ["f1"])
        q.restore_file(result["quarantine_id"])
        assert q.is_recently_restored(str(sample_file)) is True


# ── DB Resilience Tests ───────────────────────────────────────


class TestDbResilience:
    """Test quarantine DB corruption recovery."""

    def test_load_db_corrupt_json(self, isolate_quarantine):
        q, _, db_path = isolate_quarantine
        db_path.write_text("{corrupt json!!!", encoding="utf-8")
        # _load_db should return empty on corruption (use private function for test)
        result = q._load_db()
        assert result == []

    def test_load_db_empty_file(self, isolate_quarantine):
        q, _, db_path = isolate_quarantine
        result = q._load_db()
        assert result == []

    def test_save_db_creates_file(self, isolate_quarantine):
        q, _, db_path = isolate_quarantine
        q._save_db([{"test": "data"}])
        assert db_path.exists()
        loaded = json.loads(db_path.read_text(encoding="utf-8"))
        assert loaded[0]["test"] == "data"
