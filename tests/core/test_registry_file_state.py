"""Threat records must outlive the files they describe.

An operator in Explorer, a shell command, or an attacker cleaning up can delete
a flagged webshell without the product knowing.  These tests pin the contract:
the record survives, its file state is corrected, and the same content coming
back is not mistaken for a file we have already handled.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from anteumbra.application.content_fingerprint import file_content_hash
from anteumbra.domain import registry_records
from anteumbra.domain.site import SiteIdentity
from anteumbra.infrastructure.suspicious_registry import SuspiciousRegistry
from anteumbra.infrastructure.wal_manager import WalManager

IDENTITY = SiteIdentity("alpha", "Alpha")


class ConfigStub:
    def __init__(self):
        self.compact_days = 30

    def get(self):
        return {"filesizes": {"registry_compact_days": self.compact_days}}

    def resolve_site_identity(self, file_path, site_id=None, site_name=None):
        if site_id:
            return SiteIdentity.from_values(site_id, site_name or site_id)
        if "/alpha/" in str(file_path).replace("\\", "/").lower():
            return IDENTITY
        return SiteIdentity.legacy()


class EventStub:
    def __init__(self):
        self.events = []

    def publish(self, event_type, source, payload):
        self.events.append((event_type, source, dict(payload)))


@pytest.fixture
def bundle(tmp_path):
    events = EventStub()
    changes = []
    registry = SuspiciousRegistry(
        tmp_path / "suspicious_registry.json",
        config=ConfigStub(),
        wal=WalManager(tmp_path / "registry_wal.log"),
        event_publisher=events,
        change_callback=lambda: changes.append("changed"),
    )
    return registry, changes, events, tmp_path


def _record(**overrides):
    record = registry_records.create_detection_record(
        "/srv/alpha/shell.php",
        ["webshell-rule"],
        "203.0.113.8",
        "passive",
        IDENTITY,
        "2026-01-01T00:00:00+00:00",
        "hash-one",
    )
    record.update(overrides)
    return record


# ── domain state machine ──────────────────────────────────────────────


def test_removal_keeps_the_record_and_marks_it_missing():
    record = _record(alerted=True)

    registry_records.mark_removed(record, "2026-02-02T00:00:00+00:00", "deleted-on-disk")

    assert record["file_exists"] is False
    assert record["deleted_at"] == "2026-02-02T00:00:00+00:00"
    assert record["missing_at"] == "2026-02-02T00:00:00+00:00"
    assert record["missing_reason"] == "deleted-on-disk"
    assert record["alerted"] is False
    # The digest still describes what was caught here, which is the whole point
    # of keeping the record after the file is gone.
    assert record["content_hash"] == "hash-one"


def test_removal_of_a_quarantined_file_does_not_claim_the_operator_deleted_it():
    record = _record(quarantine_id="q-1")

    registry_records.mark_removed(record, "2026-02-02T00:00:00+00:00", "quarantined")

    assert record["file_exists"] is False
    assert record["deleted_at"] is None
    assert record["missing_reason"] == "quarantined"


def test_redetection_clears_missing_state_and_rearms_the_alert():
    record = _record(alerted=True)
    registry_records.mark_removed(record, "2026-02-02T00:00:00+00:00", "deleted-on-disk")

    registry_records.refresh_detection_record(
        record,
        ["webshell-rule"],
        "203.0.113.9",
        "passive",
        IDENTITY,
        "2026-03-03T00:00:00+00:00",
        "hash-two",
    )

    assert record["file_exists"] is True
    assert record["missing_at"] is None
    assert record["missing_reason"] == ""
    assert record["deleted_at"] is None
    assert record["alerted"] is False
    assert record["content_hash"] == "hash-two"


def test_presence_rearms_the_alert_only_when_the_record_was_missing():
    untouched = _record(alerted=True)
    registry_records.mark_present(untouched, "2026-04-04T00:00:00+00:00")
    assert untouched["alerted"] is True
    assert "reappeared_at" not in untouched

    recovered = _record(alerted=True)
    registry_records.mark_removed(recovered, "2026-02-02T00:00:00+00:00", "deleted-on-disk")
    registry_records.mark_present(recovered, "2026-04-04T00:00:00+00:00")
    assert recovered["alerted"] is False
    assert recovered["file_exists"] is True
    assert recovered["missing_at"] is None
    assert recovered["reappeared_at"] == "2026-04-04T00:00:00+00:00"


# ── registry persistence ──────────────────────────────────────────────


def test_remove_records_the_reason_and_keeps_the_record_queryable(bundle):
    registry, _changes, _events, _tmp = bundle
    path = Path("/srv/alpha/shell.php")
    registry.add(path, ["webshell-rule"], "203.0.113.8", "passive", content_hash="abc123")

    assert registry.remove(path, site_id="alpha", reason="deleted-on-disk") is True

    record = registry.get(path, site_id="alpha")
    assert record is not None
    assert record["file_exists"] is False
    assert record["missing_reason"] == "deleted-on-disk"
    assert record["content_hash"] == "abc123"
    assert [item["file_path"] for item in registry.get_all(include_deleted=True)] == [
        record["file_path"]
    ]
    assert registry.get_all() == []


def test_content_hash_survives_a_reload(bundle):
    registry, _changes, _events, tmp_path = bundle
    path = Path("/srv/alpha/shell.php")
    registry.add(path, ["webshell-rule"], None, "passive", content_hash="deadbeef")

    reopened = SuspiciousRegistry(
        tmp_path / "suspicious_registry.json",
        config=ConfigStub(),
        wal=WalManager(tmp_path / "registry_wal.log"),
        event_publisher=EventStub(),
    )

    record = reopened.get(path, site_id="alpha")
    assert record["content_hash"] == "deadbeef"
    assert record["missing_at"] is None
    assert record["missing_reason"] == ""


def test_mark_present_ignores_paths_the_registry_never_lost(bundle):
    registry, changes, _events, _tmp = bundle
    path = Path("/srv/alpha/shell.php")
    registry.add(path, ["webshell-rule"], None, "passive")
    before = len(changes)

    assert registry.mark_present(path, site_id="alpha") is False
    assert registry.mark_present(Path("/srv/alpha/unknown.php"), site_id="alpha") is False
    assert len(changes) == before


def test_mark_present_restores_a_record_that_was_marked_missing(bundle):
    registry, _changes, _events, _tmp = bundle
    path = Path("/srv/alpha/shell.php")
    registry.add(path, ["webshell-rule"], None, "passive")
    registry.remove(path, site_id="alpha", reason="deleted-on-disk")

    assert registry.mark_present(path, site_id="alpha") is True

    record = registry.get(path, site_id="alpha")
    assert record["file_exists"] is True
    assert record["missing_at"] is None
    assert record["missing_reason"] == ""


# ── startup reconciliation ────────────────────────────────────────────


def test_reconcile_marks_records_whose_file_disappeared(bundle):
    registry, _changes, _events, tmp_path = bundle
    gone = tmp_path / "alpha" / "gone.php"
    kept = tmp_path / "alpha" / "kept.php"
    kept.parent.mkdir(parents=True, exist_ok=True)
    gone.write_text("<?php", encoding="utf-8")
    kept.write_text("<?php", encoding="utf-8")
    registry.add(gone, ["rule"], None, "passive")
    registry.add(kept, ["rule"], None, "passive")

    gone.unlink()
    counters = registry.reconcile_filesystem("alpha")

    assert counters == {"checked": 2, "marked_missing": 1, "marked_present": 0}
    missing = registry.get(gone, site_id="alpha")
    assert missing["file_exists"] is False
    assert missing["missing_reason"] == "gone-while-stopped"
    assert registry.get(kept, site_id="alpha")["file_exists"] is True


def test_reconcile_does_not_undo_an_operator_soft_delete(bundle):
    registry, _changes, _events, tmp_path = bundle
    path = tmp_path / "alpha" / "reviewed.php"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("<?php", encoding="utf-8")
    registry.add(path, ["rule"], None, "passive")
    registry.soft_delete_record(path, site_id="alpha")

    counters = registry.reconcile_filesystem("alpha")

    assert counters["marked_present"] == 0
    record = registry.get(path, site_id="alpha")
    assert record["file_exists"] is False
    assert record["missing_reason"] == ""


def test_reconcile_restores_a_filesystem_recorded_missing_file_that_returned(bundle):
    registry, _changes, _events, tmp_path = bundle
    path = tmp_path / "alpha" / "back.php"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("<?php", encoding="utf-8")
    registry.add(path, ["rule"], None, "passive")
    path.unlink()
    registry.reconcile_filesystem("alpha")

    path.write_text("<?php eval($_POST[1]);", encoding="utf-8")
    counters = registry.reconcile_filesystem("alpha")

    assert counters["marked_present"] == 1
    record = registry.get(path, site_id="alpha")
    assert record["file_exists"] is True
    assert record["missing_reason"] == ""


# ── content fingerprint ───────────────────────────────────────────────


def test_fingerprint_matches_sha256(tmp_path):
    target = tmp_path / "shell.php"
    payload = b"<?php eval($_POST['cmd']); ?>"
    target.write_bytes(payload)

    assert file_content_hash(target) == hashlib.sha256(payload).hexdigest()
    assert file_content_hash(target) == file_content_hash(str(target))


def test_fingerprint_degrades_to_empty_instead_of_raising(tmp_path):
    assert file_content_hash(tmp_path / "absent.php") == ""

    big = tmp_path / "big.bin"
    big.write_bytes(b"x" * 64)
    assert file_content_hash(big, max_bytes=16) == ""


def test_registry_is_json_serializable_after_a_deletion(bundle):
    registry, _changes, _events, tmp_path = bundle
    path = Path("/srv/alpha/shell.php")
    registry.add(path, ["rule"], None, "passive", content_hash="abc")
    registry.remove(path, site_id="alpha", reason="deleted-on-disk")

    payload = json.loads((tmp_path / "suspicious_registry.json").read_text(encoding="utf-8"))
    stored = payload["records"][0] if isinstance(payload, dict) else payload[0]
    assert stored["missing_reason"] == "deleted-on-disk"
    assert stored["file_exists"] is False
