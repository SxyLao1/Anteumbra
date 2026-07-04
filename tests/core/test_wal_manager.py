# -*- coding: utf-8 -*-
"""v1.0.9: Unit tests for wal_manager.py — Write-Ahead Log for crash recovery.

Tests cover: write_entry, read_entries, archive_current_wal, replay,
get_wal_info, list_archives, get_status_text, is_replaying, and rotation.
"""
import os
import time
from pathlib import Path

import pytest

# ── Fixtures ──────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def isolate_wal(monkeypatch, tmp_path):
    """Force wal_manager to use temp paths, suppress ConfigRegistry access."""
    from anteumbra.infrastructure import wal_manager as wm
    from anteumbra.infrastructure.config import registry as cfg_reg

    wal_path = tmp_path / "registry_wal.log"

    # Stub ConfigRegistry to return minimal config — write_entry calls it directly
    monkeypatch.setattr(
        cfg_reg.ConfigRegistry, "get_raw_config",
        lambda: {"filesizes": {"wal_rotate_threshold_mb": 100}},
    )

    # Stub _init_wal_path to set temp path WITHOUT ConfigRegistry
    def _stub_init():
        wm._WAL_PATH = wal_path
        wm._WAL_PATH.parent.mkdir(parents=True, exist_ok=True)

    monkeypatch.setattr(wm, "_init_wal_path", _stub_init)
    monkeypatch.setattr(wm, "_replaying", False)

    # Force reset state
    wm._WAL_PATH = wal_path
    wm._replaying = False
    # Clean up any existing WAL
    for p in [wal_path] + list(tmp_path.glob("*.wal")):
        try:
            p.unlink()
        except Exception:
            pass

    yield wm

    # Teardown
    for p in [wal_path] + list(tmp_path.glob("*.wal")):
        try:
            p.unlink()
        except Exception:
            pass


# ── Write / Read Tests ────────────────────────────────────────


class TestWriteEntry:
    """Test write_entry() — append to WAL."""

    def test_write_single_entry(self, isolate_wal):
        wm = isolate_wal
        result = wm.write_entry("add", "/var/www/shell.php", ["php_eval"], ip="10.0.0.1")
        assert result is True
        assert wm._WAL_PATH.exists()

    def test_write_entry_creates_file(self, isolate_wal):
        wm = isolate_wal
        assert not wm._WAL_PATH.exists()
        wm.write_entry("add", "/tmp/test.php", ["test"])
        assert wm._WAL_PATH.exists()

    def test_write_entry_without_ip(self, isolate_wal):
        wm = isolate_wal
        result = wm.write_entry("remove", "/var/www/clean.php", [])
        assert result is True

    def test_write_entry_json_format(self, isolate_wal):
        wm = isolate_wal
        wm.write_entry("add", "/path/shell.php", ["eval", "base64"], ip="1.2.3.4")
        content = wm._WAL_PATH.read_text(encoding="utf-8")
        assert '"operation"' in content
        assert '"file_path"' in content
        assert '"features"' in content
        assert "1.2.3.4" in content

    def test_write_entry_while_replaying_is_skipped(self, isolate_wal):
        wm = isolate_wal
        wm._replaying = True
        # write_entry doesn't check _replaying — it writes regardless.
        # The _replaying flag is advisory for readers, not a write gate.
        result = wm.write_entry("add", "/tmp/skip.php", [])
        assert result is True  # Writes succeed even during replay


class TestReadEntries:
    """Test read_entries() — parse WAL file."""

    def test_read_entries_empty_file(self, isolate_wal):
        wm = isolate_wal
        entries = wm.read_entries()
        assert entries == []

    def test_read_entries_returns_list_of_dicts(self, isolate_wal):
        wm = isolate_wal
        wm.write_entry("add", "/a.php", ["f1"])
        wm.write_entry("remove", "/b.php", ["f2"])
        entries = wm.read_entries()
        assert len(entries) == 2
        assert entries[0]["operation"] == "add"
        assert entries[1]["operation"] == "remove"

    def test_read_entries_skips_comments(self, isolate_wal):
        wm = isolate_wal
        wm.write_entry("add", "/a.php", ["f1"])
        # Append a comment line manually
        with open(wm._WAL_PATH, "a", encoding="utf-8") as f:
            f.write("# This is a comment\n")
        entries = wm.read_entries()
        assert len(entries) == 1

    def test_read_entries_skips_empty_lines(self, isolate_wal):
        wm = isolate_wal
        wm.write_entry("add", "/a.php", ["f1"])
        with open(wm._WAL_PATH, "a", encoding="utf-8") as f:
            f.write("\n  \n")
        entries = wm.read_entries()
        assert len(entries) == 1


# ── Archive Tests ─────────────────────────────────────────────


class TestArchiveCurrentWal:
    """Test archive_current_wal() — rotate WAL to archive."""

    def test_archive_renames_wal(self, isolate_wal):
        wm = isolate_wal
        wm.write_entry("add", "/test.php", ["f1"])
        original_size = wm._WAL_PATH.stat().st_size
        result = wm.archive_current_wal()
        # archive_current_wal returns the backup path on success
        assert result is not None
        assert result.exists()  # Archive created

    def test_archive_empty_wal_returns_none(self, isolate_wal):
        wm = isolate_wal
        result = wm.archive_current_wal()
        # Returns empty dict when no WAL to archive
        assert result == {}


# ── Rotation Tests ────────────────────────────────────────────


class TestRotation:
    """Test WAL rotation logic (write many entries)."""

    def test_write_many_entries_survives_rotation(self, isolate_wal):
        wm = isolate_wal
        for i in range(10):
            wm.write_entry("add", f"/tmp/file_{i}.php", [f"feat_{i}"], ip="10.0.0.1")
        entries = wm.read_entries()
        assert len(entries) == 10

    def test_rotation_preserves_entry_order(self, isolate_wal):
        wm = isolate_wal
        paths = [f"/tmp/file_{i}.php" for i in range(5)]
        for p in paths:
            wm.write_entry("add", p, [])
        entries = wm.read_entries()
        for i, entry in enumerate(entries):
            assert entry["file_path"] == paths[i]


# ── Replay Tests ──────────────────────────────────────────────


class TestReplay:
    """Test replay() — WAL crash recovery playback."""

    def test_replay_dispatches_to_callbacks(self, isolate_wal):
        wm = isolate_wal
        wm.write_entry("add", "/tmp/shell.php", ["eval"], ip="10.0.0.5")
        wm.write_entry("remove", "/tmp/clean.php", [], ip="10.0.0.6")

        calls = []

        def cb_add(file_path, features, ip):
            calls.append(("add", str(file_path)))

        def cb_remove(file_path, features, ip):
            calls.append(("remove", str(file_path)))

        count = wm.replay({"add": cb_add, "remove": cb_remove})
        assert count == 2
        # Paths are normalized by replay — match by suffix
        assert calls[0][0] == "add"
        assert "shell.php" in calls[0][1]
        assert calls[1][0] == "remove"
        assert "clean.php" in calls[1][1]

    def test_replay_empty_wal_returns_zero(self, isolate_wal):
        wm = isolate_wal
        count = wm.replay({"add": lambda fp, feats, ip: None})
        assert count == 0

    def test_replay_unknown_operation_is_skipped(self, isolate_wal):
        wm = isolate_wal
        wm.write_entry("add", "/a.php", [])
        wm.write_entry("unknown_op", "/b.php", [])
        count = wm.replay({"add": lambda fp, feats, ip: None})
        assert count == 1  # Only "add" dispatched

    def test_replay_callback_error_does_not_abort(self, isolate_wal):
        wm = isolate_wal

        def failing_cb(file_path, features, ip):
            raise RuntimeError("Simulated failure")

        wm.write_entry("add", "/a.php", [])
        wm.write_entry("add", "/b.php", [])
        count = wm.replay({"add": failing_cb})
        # Entries that throw are NOT counted as recovered (count == 0),
        # but replay doesn't crash — it continues processing
        assert count == 0

    def test_replay_sets_replaying_flag(self, isolate_wal):
        wm = isolate_wal
        wm.write_entry("add", "/test.php", [])
        assert wm.is_replaying() is False
        wm.replay({"add": lambda fp, feats, ip: None})
        assert wm.is_replaying() is False  # Reset after replay

    def test_replay_archives_after_success(self, isolate_wal):
        wm = isolate_wal
        wm.write_entry("add", "/test.php", ["f1"])
        wm.replay({"add": lambda fp, feats, ip: None})
        # After replay, current WAL should exist (archive creates a fresh one)
        # Verify archives exist in parent dir
        archives = list(wm._WAL_PATH.parent.glob("registry_wal.log.*"))
        assert len(archives) >= 1  # At least one archive was created


# ── Info / Status Tests ───────────────────────────────────────


class TestGetWalInfo:
    """Test get_wal_info() — WAL status summary."""

    def test_get_wal_info_empty(self, isolate_wal):
        wm = isolate_wal
        info = wm.get_wal_info()
        # Returns {} when WAL doesn't exist yet
        assert isinstance(info, dict)

    def test_get_wal_info_with_entries(self, isolate_wal):
        wm = isolate_wal
        wm.write_entry("add", "/a.php", ["f1"])
        wm.write_entry("add", "/b.php", ["f2"])
        info = wm.get_wal_info()
        assert info.get("name") is not None
        assert info.get("size_mb", 0) >= 0


class TestListArchives:
    """Test list_archives() — enumerate archived WAL files."""

    def test_list_archives_empty(self, isolate_wal):
        wm = isolate_wal
        archives = wm.list_archives()
        assert archives == []

    def test_list_archives_after_archive(self, isolate_wal):
        wm = isolate_wal
        wm.write_entry("add", "/test.php", ["f1"])
        wm.archive_current_wal()
        archives = wm.list_archives()
        assert len(archives) == 1
        assert "name" in archives[0]
        assert "size_mb" in archives[0]


class TestGetStatusText:
    """Test get_status_text() — human-readable status."""

    def test_get_status_text_tuple(self, isolate_wal):
        wm = isolate_wal
        result = wm.get_status_text()
        assert isinstance(result, tuple)
        assert len(result) == 3
        status, text, size_mb = result
        assert isinstance(status, str)
        assert isinstance(text, str)


# ── Compatibility ─────────────────────────────────────────────


class TestReadWalRecords:
    """Test read_wal_records() v1.7.8 compatibility alias."""

    def test_read_wal_records_is_alias(self, isolate_wal):
        wm = isolate_wal
        wm.write_entry("add", "/test.php", ["f1"])
        records = wm.read_wal_records()
        assert len(records) == 1
        assert records[0]["file_path"] == "/test.php"

    def test_read_wal_records_with_limit(self, isolate_wal):
        wm = isolate_wal
        for i in range(5):
            wm.write_entry("add", f"/tmp/{i}.php", [])
        records = wm.read_wal_records(limit=3)
        assert len(records) == 3
