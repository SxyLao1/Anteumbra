"""QuarantineStore filesystem, persistence, and recovery tests."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from anteumbra.domain.site import SiteIdentity
from anteumbra.infrastructure.quarantine import (
    QuarantineDataError,
    QuarantinePersistenceError,
    QuarantineStore,
)


def _resolve_site(_path, site_id=None, site_name=None):
    return SiteIdentity.from_values(
        site_id or "legacy",
        site_name or "Legacy / unassigned",
    )


@pytest.fixture
def store(tmp_path):
    return QuarantineStore(
        tmp_path / "quarantine",
        site_resolver=_resolve_site,
    )


@pytest.fixture
def sample_file(tmp_path):
    path = tmp_path / "shell.php"
    path.write_text("<?php eval($_POST['cmd']);", encoding="utf-8")
    return path


def test_quarantine_moves_file_and_commits_site_metadata(store, sample_file):
    record = store.quarantine_file(
        sample_file,
        "php-eval",
        ["eval", "post"],
        site=SiteIdentity("alpha", "Alpha"),
    )

    assert record is not None
    assert not sample_file.exists()
    assert Path(record["quarantine_path"]).is_file()
    assert record["site_id"] == "alpha"
    assert record["site_name"] == "Alpha"
    assert record["status"] == "quarantined"
    assert json.loads(store.db_path.read_text(encoding="utf-8"))[0] == record


def test_quarantine_missing_source_is_a_clean_noop(store, tmp_path):
    result = store.quarantine_file(
        tmp_path / "missing.php",
        "rule",
        [],
        site=SiteIdentity("alpha", "Alpha"),
    )

    assert result is None
    assert store.list_records() == []


def test_records_are_site_filtered_paginated_and_defensive(store, tmp_path):
    for site_id in ("alpha", "beta", "alpha"):
        path = tmp_path / f"{site_id}-{len(store.list_records())}.php"
        path.write_text("payload", encoding="utf-8")
        store.quarantine_file(
            path,
            site_id,
            [site_id],
            site=SiteIdentity(site_id, site_id.title()),
        )

    alpha = store.list_records(site_id="ALPHA", limit=1)
    alpha[0]["rule_name"] = "mutated"

    assert len(alpha) == 1
    assert len(store.list_records(site_id="alpha")) == 2
    assert store.list_records(site_id="alpha")[0]["rule_name"] != "mutated"
    assert store.get_stats("alpha") == {
        "total": 2,
        "quarantined": 2,
        "restored": 0,
        "deleted": 0,
    }


def test_restore_moves_file_back_and_sets_suppression_guard(store, sample_file):
    record = store.quarantine_file(
        sample_file,
        "rule",
        [],
        site=SiteIdentity("alpha", "Alpha"),
    )

    restored = store.restore_file(record["quarantine_id"])

    assert restored["status"] == "restored"
    assert sample_file.is_file()
    assert not Path(record["quarantine_path"]).exists()
    assert store.is_recently_restored(sample_file)


def test_restore_refuses_to_overwrite_an_existing_destination(store, sample_file):
    record = store.quarantine_file(
        sample_file,
        "rule",
        [],
        site=SiteIdentity("alpha", "Alpha"),
    )
    sample_file.write_text("replacement", encoding="utf-8")

    with pytest.raises(FileExistsError, match="destination exists"):
        store.restore_file(record["quarantine_id"])

    assert sample_file.read_text(encoding="utf-8") == "replacement"
    assert Path(record["quarantine_path"]).is_file()


def test_primary_commit_failure_rolls_quarantined_file_back(store, sample_file, monkeypatch):
    original_atomic_write = store._atomic_write

    def fail_primary(path, content):
        if path == store.db_path:
            raise OSError("disk full")
        return original_atomic_write(path, content)

    monkeypatch.setattr(store, "_atomic_write", fail_primary)

    with pytest.raises(QuarantinePersistenceError, match="cannot commit"):
        store.quarantine_file(
            sample_file,
            "rule",
            [],
            site=SiteIdentity("alpha", "Alpha"),
        )

    assert sample_file.is_file()
    assert store.list_records() == []
    assert not list(store.directory.glob("*/*"))


def test_backup_refresh_failure_does_not_rollback_primary_commit(store, sample_file, monkeypatch):
    original_atomic_write = store._atomic_write

    def fail_backup(path, content):
        if path == store.backup_path:
            raise OSError("backup unavailable")
        return original_atomic_write(path, content)

    monkeypatch.setattr(store, "_atomic_write", fail_backup)
    record = store.quarantine_file(
        sample_file,
        "rule",
        [],
        site=SiteIdentity("alpha", "Alpha"),
    )

    assert record is not None
    assert not sample_file.exists()
    assert store.get_detail(record["quarantine_id"]) is not None
    assert store.db_path.is_file()


def test_restore_commit_failure_moves_file_back_to_quarantine(store, sample_file, monkeypatch):
    record = store.quarantine_file(
        sample_file,
        "rule",
        [],
        site=SiteIdentity("alpha", "Alpha"),
    )
    original_atomic_write = store._atomic_write

    def fail_primary(path, content):
        if path == store.db_path:
            raise OSError("restore commit failed")
        return original_atomic_write(path, content)

    monkeypatch.setattr(store, "_atomic_write", fail_primary)

    with pytest.raises(QuarantinePersistenceError, match="cannot commit"):
        store.restore_file(record["quarantine_id"])

    assert not sample_file.exists()
    assert Path(record["quarantine_path"]).is_file()
    assert store.get_detail(record["quarantine_id"])["status"] == "quarantined"


def test_delete_commit_failure_preserves_file_and_status(store, sample_file, monkeypatch):
    record = store.quarantine_file(
        sample_file,
        "rule",
        [],
        site=SiteIdentity("alpha", "Alpha"),
    )
    original_atomic_write = store._atomic_write
    primary_calls = 0

    def fail_first_primary(path, content):
        nonlocal primary_calls
        if path == store.db_path:
            primary_calls += 1
            if primary_calls == 1:
                raise OSError("delete commit failed")
        return original_atomic_write(path, content)

    monkeypatch.setattr(store, "_atomic_write", fail_first_primary)

    with pytest.raises(QuarantinePersistenceError, match="cannot commit"):
        store.delete_quarantine(record["quarantine_id"])

    assert Path(record["quarantine_path"]).is_file()
    assert store.get_detail(record["quarantine_id"])["status"] == "quarantined"


def test_delete_retains_audit_record(store, sample_file):
    record = store.quarantine_file(
        sample_file,
        "rule",
        [],
        site=SiteIdentity("alpha", "Alpha"),
    )

    deleted = store.delete_quarantine(record["quarantine_id"])

    assert deleted["status"] == "deleted"
    assert not Path(record["quarantine_path"]).exists()
    assert store.get_stats("alpha")["deleted"] == 1


def test_explicit_quarantine_rollback_restores_file_and_removes_record(store, sample_file):
    record = store.quarantine_file(
        sample_file,
        "rule",
        [],
        site=SiteIdentity("alpha", "Alpha"),
    )

    rolled_back = store.rollback_quarantine(record["quarantine_id"])

    assert rolled_back["quarantine_id"] == record["quarantine_id"]
    assert sample_file.is_file()
    assert store.get_detail(record["quarantine_id"]) is None


def test_corrupt_primary_recovers_from_backup(store, sample_file):
    record = store.quarantine_file(
        sample_file,
        "rule",
        [],
        site=SiteIdentity("alpha", "Alpha"),
    )
    store.db_path.write_text("{broken", encoding="utf-8")

    recovered = QuarantineStore(store.directory, site_resolver=_resolve_site)

    assert recovered.get_detail(record["quarantine_id"])["site_id"] == "alpha"
    assert isinstance(json.loads(recovered.db_path.read_text(encoding="utf-8")), list)


def test_all_corrupt_sources_fail_explicitly(tmp_path):
    directory = tmp_path / "quarantine"
    directory.mkdir()
    (directory / "quarantine.json").write_text("{broken", encoding="utf-8")
    (directory / "quarantine.json.bak").write_text("[broken", encoding="utf-8")

    with pytest.raises(QuarantineDataError, match="no valid recovery source"):
        QuarantineStore(directory, site_resolver=_resolve_site)


def test_legacy_object_metadata_is_normalized_and_persisted(tmp_path):
    directory = tmp_path / "quarantine"
    directory.mkdir()
    record = {
        "quarantine_id": "Q-legacy",
        "original_path": str(tmp_path / "legacy.php"),
        "quarantine_path": str(directory / "2026-01-01" / "Q-legacy_legacy.php"),
        "status": "quarantined",
        "features": '["eval"]',
    }
    (directory / "quarantine.json").write_text(
        json.dumps({"Q-legacy": record}),
        encoding="utf-8",
    )

    migrated = QuarantineStore(directory, site_resolver=_resolve_site)
    persisted = json.loads(migrated.db_path.read_text(encoding="utf-8"))

    assert isinstance(persisted, list)
    assert persisted[0]["site_id"] == "legacy"
    assert persisted[0]["features"] == ["eval"]


def test_orphan_file_is_left_untouched_without_fabricating_metadata(tmp_path):
    directory = tmp_path / "quarantine"
    dated = directory / "2026-01-01"
    dated.mkdir(parents=True)
    orphan = dated / "Q-orphan_shell.php"
    orphan.write_text("payload", encoding="utf-8")

    store = QuarantineStore(directory, site_resolver=_resolve_site)

    assert orphan.is_file()
    assert store.list_records() == []


def test_shadow_is_best_effort_and_closed(tmp_path, sample_file):
    saved = []
    shadow = SimpleNamespace(
        save=lambda record_id, data: saved.append((record_id, data)),
        delete=lambda _record_id: False,
        list_all=lambda **_kwargs: [],
        close=lambda: saved.append(("closed", {})),
    )
    store = QuarantineStore(
        tmp_path / "shadow-quarantine",
        site_resolver=_resolve_site,
        shadow_repository=shadow,
    )

    record = store.quarantine_file(
        sample_file,
        "rule",
        [],
        site=SiteIdentity("alpha", "Alpha"),
    )
    store.close()

    assert saved[0][0] == record["quarantine_id"]
    assert saved[-1][0] == "closed"
