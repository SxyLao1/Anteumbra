"""Application-level quarantine consistency tests."""

import pytest

from anteumbra.application import quarantine_service


def test_registered_quarantine_returns_committed_record(monkeypatch):
    record = {"quarantine_id": "Q-test"}
    monkeypatch.setattr(
        quarantine_service, "quarantine_file", lambda *args, **kwargs: record
    )

    from anteumbra.application import registry_service

    monkeypatch.setattr(registry_service, "mark_quarantined", lambda *_args: True)
    monkeypatch.setattr(
        quarantine_service,
        "rollback_quarantine",
        lambda _qid: pytest.fail("rollback must not run after a successful commit"),
    )

    result = quarantine_service.quarantine_registered_file(
        "sample.php", "rule", ["feature"]
    )

    assert result is record


def test_registry_failure_rolls_quarantine_back(monkeypatch):
    record = {"quarantine_id": "Q-test"}
    rolled_back = []
    monkeypatch.setattr(
        quarantine_service, "quarantine_file", lambda *args, **kwargs: record
    )

    from anteumbra.application import registry_service

    monkeypatch.setattr(registry_service, "mark_quarantined", lambda *_args: False)
    monkeypatch.setattr(
        quarantine_service,
        "rollback_quarantine",
        lambda qid: rolled_back.append(qid),
    )

    with pytest.raises(
        quarantine_service.QuarantineConsistencyError,
        match="was rolled back",
    ):
        quarantine_service.quarantine_registered_file(
            "sample.php", "rule", ["feature"]
        )

    assert rolled_back == ["Q-test"]


def test_registry_and_rollback_failure_is_explicit(monkeypatch):
    record = {"quarantine_id": "Q-test"}
    monkeypatch.setattr(
        quarantine_service, "quarantine_file", lambda *args, **kwargs: record
    )

    from anteumbra.application import registry_service

    monkeypatch.setattr(registry_service, "mark_quarantined", lambda *_args: False)

    def fail_rollback(_qid):
        raise OSError("rollback blocked")

    monkeypatch.setattr(quarantine_service, "rollback_quarantine", fail_rollback)

    with pytest.raises(
        quarantine_service.QuarantineConsistencyError,
        match="rollback could not restore",
    ):
        quarantine_service.quarantine_registered_file(
            "sample.php", "rule", ["feature"]
        )


def test_restore_without_registry_record_remains_supported(monkeypatch):
    record = {
        "quarantine_id": "Q-test",
        "original_path": "sample.php",
        "status": "quarantined",
    }
    restored = dict(record, status="restored")
    monkeypatch.setattr(quarantine_service, "get_quarantine_detail", lambda _qid: record)
    monkeypatch.setattr(quarantine_service, "_restore_file", lambda _qid: restored)

    from anteumbra.application import registry_service

    monkeypatch.setattr(registry_service, "get_all", lambda **_kwargs: [])
    monkeypatch.setattr(
        registry_service,
        "mark_restored",
        lambda _path: pytest.fail("unlinked restore must not mutate Registry"),
    )

    assert quarantine_service.restore_file("Q-test") is restored


def test_restore_ignores_a_same_path_record_from_another_site(monkeypatch):
    record = {
        "quarantine_id": "Q-test",
        "original_path": "sample.php",
        "site_id": "alpha",
        "status": "quarantined",
    }
    restored = dict(record, status="restored")
    monkeypatch.setattr(quarantine_service, "get_quarantine_detail", lambda _qid: record)
    monkeypatch.setattr(quarantine_service, "_restore_file", lambda _qid: restored)

    from anteumbra.application import registry_service

    calls = []

    def get_all(**kwargs):
        calls.append(kwargs)
        return []

    monkeypatch.setattr(registry_service, "get_all", get_all)
    monkeypatch.setattr(
        registry_service,
        "mark_restored",
        lambda *_args: pytest.fail("a different site's record must not be restored"),
    )

    assert quarantine_service.restore_file("Q-test") is restored
    assert calls[0]["site_id"] == "alpha"


def test_registry_restore_failure_is_compensated(monkeypatch):
    record = {
        "quarantine_id": "Q-test",
        "original_path": "sample.php",
        "status": "quarantined",
    }
    monkeypatch.setattr(quarantine_service, "get_quarantine_detail", lambda _qid: record)
    monkeypatch.setattr(
        quarantine_service,
        "_restore_file",
        lambda _qid: dict(record, status="restored"),
    )

    from anteumbra.application import registry_service
    from anteumbra.infrastructure.utils.path_utils import path_to_key

    monkeypatch.setattr(
        registry_service,
        "get_all",
        lambda **_kwargs: [{"file_path": path_to_key("sample.php")}],
    )
    monkeypatch.setattr(registry_service, "mark_restored", lambda _path: False)
    compensated = []
    monkeypatch.setattr(
        quarantine_service,
        "rollback_restore",
        lambda qid: compensated.append(qid),
    )

    with pytest.raises(
        quarantine_service.QuarantineConsistencyError,
        match="was rolled back",
    ):
        quarantine_service.restore_file("Q-test")

    assert compensated == ["Q-test"]
