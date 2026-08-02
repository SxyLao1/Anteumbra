"""Unit tests for the runtime-owned Registry write-ahead log."""

from __future__ import annotations

import json

import pytest

from anteumbra.infrastructure.wal_manager import WalManager, WalWriteError


@pytest.fixture
def wal(tmp_path):
    return WalManager(
        tmp_path / "registry_wal.log",
        settings_loader=lambda: {"wal_rotate_threshold_mb": 10},
    )


def test_write_and_complete_tracks_only_pending_transactions(wal):
    transaction_id = wal.write_entry(
        "upsert",
        "/var/www/shell.php",
        ["php_eval"],
        "10.0.0.1",
        payload={"record": {"site_id": "alpha"}},
    )

    entries = wal.read_entries()
    assert len(entries) == 1
    assert entries[0]["transaction_id"] == transaction_id
    assert entries[0]["payload"]["record"]["site_id"] == "alpha"
    assert wal.read_entries(pending_only=True) == entries

    wal.mark_completed(transaction_id)
    assert wal.read_entries(pending_only=True) == []


def test_two_managers_do_not_share_paths_or_replay_state(tmp_path):
    first = WalManager(tmp_path / "first" / "wal.log")
    second = WalManager(tmp_path / "second" / "wal.log")

    first.write_entry("upsert", payload={"record": {"id": 1}})

    assert len(first.read_entries()) == 1
    assert second.read_entries() == []
    assert first.is_replaying is False
    assert second.is_replaying is False


def test_cleanup_uses_the_documented_filesize_setting_names(tmp_path):
    manager = WalManager(
        tmp_path / "wal.log",
        settings_loader=lambda: {
            "wal_cleanup_days": 3,
            "wal_cleanup_count": 4,
        },
    )

    settings = manager._settings()

    assert settings["retention_days"] == 3
    assert settings["max_archives"] == 4


def test_replay_acknowledges_success_and_archives_current_wal(wal):
    wal.write_entry("upsert", payload={"record": {"file_path": "/a.php"}})
    received = []

    recovered = wal.replay({"upsert": received.append})

    assert recovered == 1
    assert received[0]["payload"]["record"]["file_path"] == "/a.php"
    assert wal.read_entries() == []
    assert len(wal.list_archives()) == 1


def test_poison_entry_moves_to_dead_letter_and_never_replays_again(wal):
    wal.write_entry("upsert", payload={"record": {"file_path": "/bad.php"}})
    calls = []

    def fail(entry):
        calls.append(entry["transaction_id"])
        raise RuntimeError("invalid record")

    assert wal.replay({"upsert": fail}) == 0
    assert len(calls) == 1
    dead_letters = [
        json.loads(line) for line in wal.dead_letter_path.read_text(encoding="utf-8").splitlines()
    ]
    assert dead_letters[0]["reason"] == "replay_failed"
    assert "invalid record" in dead_letters[0]["error"]

    assert wal.replay({"upsert": fail}) == 0
    assert len(calls) == 1


def test_malformed_line_is_dead_lettered_and_removed_from_active_wal(wal):
    wal.path.write_text("not-json\n", encoding="utf-8")

    assert wal.replay({}) == 0

    envelope = json.loads(wal.dead_letter_path.read_text(encoding="utf-8"))
    assert envelope["reason"] == "malformed_record"
    assert wal.read_entries() == []
    assert len(wal.list_archives()) == 1


def test_legacy_entry_replays_once(wal):
    wal.path.write_text(
        json.dumps(
            {
                "operation": "add",
                "file_path": "/legacy.php",
                "features": ["eval"],
                "ip": "127.0.0.1",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    received = []

    assert wal.replay({"add": received.append}) == 1
    assert received[0]["version"] == 1
    assert received[0]["file_path"] == "/legacy.php"
    assert wal.replay({"add": received.append}) == 0
    assert len(received) == 1


def test_archive_refuses_to_discard_pending_transaction(wal):
    wal.write_entry("upsert", payload={"record": {"id": 1}})

    with pytest.raises(WalWriteError, match="pending transactions"):
        wal.archive_current_wal()


def test_completed_large_wal_rotates_without_losing_pending_data(tmp_path):
    wal = WalManager(
        tmp_path / "registry_wal.log",
        settings_loader=lambda: {"wal_rotate_threshold_mb": 0.01},
    )
    transaction_id = wal.write_entry("upsert", payload={"record": {"blob": "x" * 20_000}})

    wal.mark_completed(transaction_id)

    assert wal.read_entries() == []
    assert len(wal.list_archives()) == 1


def test_status_and_info_are_safe_before_and_after_first_write(wal):
    assert wal.get_info() == {}
    assert wal.get_status() == ("normal", "WAL ready (0.0MB)", 0.0)

    wal.write_entry("upsert", payload={"record": {"id": 1}})
    info = wal.get_info()
    assert info["name"] == "registry_wal.log"
    assert info["pending"] == 1
    assert wal.get_status()[0] == "normal"
