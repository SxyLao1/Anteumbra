"""Application-level quarantine consistency tests."""

from __future__ import annotations

from unittest.mock import Mock

import pytest

from anteumbra.application.quarantine_service import (
    QuarantineConsistencyError,
    QuarantineService,
)
from anteumbra.domain.site import SiteIdentity


def _resolver(_path, site_id=None, site_name=None):
    return SiteIdentity.from_values(site_id or "legacy", site_name or "Legacy")


def _record(**changes):
    record = {
        "quarantine_id": "Q-test",
        "original_path": "C:/sites/alpha/shell.php",
        "quarantine_path": "data/quarantine/Q-test_shell.php",
        "site_id": "alpha",
        "site_name": "Alpha",
        "status": "quarantined",
    }
    record.update(changes)
    return record


@pytest.fixture
def dependencies():
    store = Mock()
    registry = Mock()
    service = QuarantineService(store, registry, site_resolver=_resolver)
    return service, store, registry


def test_quarantine_returns_record_after_both_commits(dependencies):
    service, store, registry = dependencies
    record = _record()
    store.quarantine_file.return_value = record
    registry.mark_quarantined.return_value = True

    result = service.quarantine_file(
        record["original_path"],
        "rule",
        ["feature"],
        site_id="alpha",
        site_name="Alpha",
    )

    assert result is record
    registry.mark_quarantined.assert_called_once_with(
        record["original_path"], "Q-test", "alpha"
    )
    store.rollback_quarantine.assert_not_called()


def test_missing_source_does_not_touch_registry(dependencies):
    service, store, registry = dependencies
    store.quarantine_file.return_value = None

    assert service.quarantine_file("missing.php", "rule", []) is None
    registry.mark_quarantined.assert_not_called()


@pytest.mark.parametrize("registry_result", [False, RuntimeError("registry down")])
def test_registry_failure_rolls_quarantine_back(dependencies, registry_result):
    service, store, registry = dependencies
    store.quarantine_file.return_value = _record()
    if isinstance(registry_result, Exception):
        registry.mark_quarantined.side_effect = registry_result
    else:
        registry.mark_quarantined.return_value = registry_result

    with pytest.raises(QuarantineConsistencyError, match="was rolled back"):
        service.quarantine_file(
            "C:/sites/alpha/shell.php",
            "rule",
            [],
            site_id="alpha",
            site_name="Alpha",
        )

    store.rollback_quarantine.assert_called_once_with("Q-test")


def test_registry_and_quarantine_rollback_failure_is_explicit(dependencies):
    service, store, registry = dependencies
    store.quarantine_file.return_value = _record()
    registry.mark_quarantined.return_value = False
    store.rollback_quarantine.side_effect = OSError("rollback blocked")

    with pytest.raises(
        QuarantineConsistencyError,
        match="rollback could not restore",
    ):
        service.quarantine_file(
            "C:/sites/alpha/shell.php",
            "rule",
            [],
            site_id="alpha",
            site_name="Alpha",
        )


def test_restore_updates_only_the_registry_linked_to_that_quarantine(dependencies):
    service, store, registry = dependencies
    record = _record()
    store.get_detail.return_value = record
    store.restore_file.return_value = _record(status="restored")
    registry.get.return_value = {"quarantine_id": "Q-test"}
    registry.mark_restored.return_value = True

    restored = service.restore_file("Q-test")

    assert restored["status"] == "restored"
    registry.get.assert_called_once_with(record["original_path"], "alpha")
    registry.mark_restored.assert_called_once_with(record["original_path"], "alpha")
    store.rollback_restore.assert_not_called()


@pytest.mark.parametrize("linked", [None, {"quarantine_id": None}, {"quarantine_id": "Q-new"}])
def test_restore_keeps_unlinked_registry_state_unchanged(dependencies, linked):
    service, store, registry = dependencies
    store.get_detail.return_value = _record()
    store.restore_file.return_value = _record(status="restored")
    registry.get.return_value = linked

    assert service.restore_file("Q-test")["status"] == "restored"
    registry.mark_restored.assert_not_called()


@pytest.mark.parametrize("registry_result", [False, RuntimeError("registry down")])
def test_registry_restore_failure_is_compensated(dependencies, registry_result):
    service, store, registry = dependencies
    store.get_detail.return_value = _record()
    store.restore_file.return_value = _record(status="restored")
    registry.get.return_value = {"quarantine_id": "Q-test"}
    if isinstance(registry_result, Exception):
        registry.mark_restored.side_effect = registry_result
    else:
        registry.mark_restored.return_value = registry_result

    with pytest.raises(QuarantineConsistencyError, match="was rolled back"):
        service.restore_file("Q-test")

    store.rollback_restore.assert_called_once_with("Q-test")


def test_registry_and_restore_rollback_failure_is_explicit(dependencies):
    service, store, registry = dependencies
    store.get_detail.return_value = _record()
    store.restore_file.return_value = _record(status="restored")
    store.rollback_restore.side_effect = OSError("rollback blocked")
    registry.get.return_value = {"quarantine_id": "Q-test"}
    registry.mark_restored.return_value = False

    with pytest.raises(
        QuarantineConsistencyError,
        match="compensation could not restore",
    ):
        service.restore_file("Q-test")


def test_service_delegates_reads_delete_migration_and_close(dependencies):
    service, store, _registry = dependencies
    store.list_records.return_value = [_record()]
    store.get_detail.return_value = _record()
    store.get_stats.return_value = {"total": 1}
    store.delete_quarantine.return_value = _record(status="deleted")
    store.migrate_site_metadata.return_value = 2

    assert service.list_records("quarantined", 5, 1, "alpha") == [_record()]
    assert service.get_detail("Q-test")["site_id"] == "alpha"
    assert service.get_stats("alpha") == {"total": 1}
    assert service.delete_quarantine("Q-test")["status"] == "deleted"
    assert service.migrate_site_metadata() == 2
    service.close()

    store.list_records.assert_called_once_with("quarantined", 5, 1, "alpha")
    store.close.assert_called_once_with()
