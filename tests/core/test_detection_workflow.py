import hashlib
import logging
from types import SimpleNamespace

from anteumbra.domain.entities import ScanResult
from anteumbra.domain.site import SiteIdentity


class _QuarantineGuard:
    def __init__(self, restored=False, calls=None):
        self.restored = restored
        self.calls = calls if calls is not None else []

    def is_recently_restored(self, file_path):
        self.calls.append(("restore_guard", str(file_path)))
        return self.restored


def _build_workflow(
    calls, *, quarantine_enabled=True, restored=False, guard=None, already_alerted=False
):
    from anteumbra.application.detection_workflow import DetectionWorkflow

    registry = SimpleNamespace(
        add=lambda path, features, **kwargs: calls.append(("registry", str(path), features, kwargs)),
        was_alerted=lambda path, content_hash, site_id=None: (
            calls.append(("was_alerted", str(path), content_hash)) or already_alerted
        ),
    )
    metrics = SimpleNamespace(
        increment_site=lambda metric, site_id: calls.append(("metric", metric, site_id))
    )
    events = SimpleNamespace(
        publish=lambda event_type, source, payload: calls.append(
            ("event", event_type, source, payload)
        )
    )
    guard = guard or _QuarantineGuard(restored=restored, calls=calls)
    workflow = DetectionWorkflow(
        config={
            "quarantine": {
                "auto_quarantine_enabled": quarantine_enabled,
            }
        },
        registry=registry,
        metrics=metrics,
        events=events,
        quarantine=guard,
        site=SiteIdentity("alpha", "Alpha"),
        logger=logging.getLogger("test.detection-workflow"),
    )
    return workflow


def test_restored_file_is_rejected_before_scanning(tmp_path):
    calls = []
    target = tmp_path / "restored.php"
    workflow = _build_workflow(calls, restored=True)

    workflow.execute(
        target,
        "CREATE",
        scan=lambda _path: calls.append(("scan",)) or None,
        resolve_first_seen_ip=lambda _path: "127.0.0.1",
        emit_alert=lambda *_args, **_kwargs: calls.append(("alert",)),
        emit_file_quarantined=lambda *_args, **_kwargs: calls.append(("quarantine",)),
    )

    assert calls == [("restore_guard", str(target))]


def test_suspicious_detection_preserves_side_effect_order(tmp_path):
    calls = []
    target = tmp_path / "shell.php"
    target.write_bytes(b"<?php eval($_POST['cmd']); ?>")
    result = ScanResult(target, True, ["webshell-rule"], score=0.9, engine="yara")
    workflow = _build_workflow(calls)

    workflow.execute(
        target,
        "CREATE",
        scan=lambda path: calls.append(("scan", str(path))) or result,
        resolve_first_seen_ip=lambda path: calls.append(("attribute", str(path))) or "203.0.113.8",
        emit_alert=lambda *args, **kwargs: calls.append(("alert", args, kwargs)),
        emit_file_quarantined=lambda *args, **kwargs: calls.append(("quarantine", args, kwargs)),
    )

    assert [call[0] for call in calls] == [
        "restore_guard",
        "scan",
        "metric",
        "event",
        "attribute",
        "was_alerted",
        "alert",
        "registry",
        "restore_guard",
        "quarantine",
    ]
    scan_event = calls[3][3]
    assert scan_event == {
        "file_path": str(target),
        "event_type": "CREATE",
        "is_suspicious": True,
        "engine": "yara",
        "features": ["webshell-rule"],
        "score": 0.9,
        "site_id": "alpha",
        "site_name": "Alpha",
    }
    assert calls[7][3]["first_seen_ip"] == "203.0.113.8"
    assert calls[7][3]["detection_source"] == "passive"
    assert calls[7][3]["alert_emitted"] is True
    assert calls[9][2] == {
        "file_path": str(target),
        "rule_name": "webshell-rule",
        "features": ["webshell-rule"],
        "original_path": str(target),
        "first_seen_ip": "203.0.113.8",
    }


def test_already_alerted_content_is_not_reported_again(tmp_path):
    """A re-scan of bytes we already alerted for stays quiet."""
    calls = []
    target = tmp_path / "known.php"
    payload = b"<?php eval($_POST['cmd']); ?>"
    target.write_bytes(payload)
    result = ScanResult(target, True, ["webshell-rule"], engine="yara")
    workflow = _build_workflow(calls, already_alerted=True)

    workflow.execute(
        target,
        "MODIFY",
        scan=lambda _path: result,
        resolve_first_seen_ip=lambda _path: "127.0.0.1",
        emit_alert=lambda *_args, **_kwargs: calls.append(("alert",)),
        emit_file_quarantined=lambda *_args, **_kwargs: calls.append(("quarantine",)),
    )

    assert not [call for call in calls if call[0] == "alert"]
    registry_call = next(call for call in calls if call[0] == "registry")
    assert registry_call[3]["alert_emitted"] is False
    assert registry_call[3]["content_hash"] == hashlib.sha256(payload).hexdigest()


def test_suppression_lookup_receives_the_digest_of_the_current_bytes(tmp_path):
    calls = []
    target = tmp_path / "changed.php"
    payload = b"<?php system($_GET['c']); ?>"
    target.write_bytes(payload)
    result = ScanResult(target, True, ["webshell-rule"], engine="yara")
    workflow = _build_workflow(calls)

    workflow.execute(
        target,
        "MODIFY",
        scan=lambda _path: result,
        resolve_first_seen_ip=lambda _path: "127.0.0.1",
        emit_alert=lambda *_args, **_kwargs: calls.append(("alert",)),
        emit_file_quarantined=lambda *_args, **_kwargs: calls.append(("quarantine",)),
    )

    lookup = next(call for call in calls if call[0] == "was_alerted")
    assert lookup[2] == hashlib.sha256(payload).hexdigest()


def test_disabled_auto_quarantine_registers_without_a_per_hit_skip_alert(tmp_path):
    """A standing switch is announced once at startup, not once per hit.

    The per-hit "quarantine skipped" WARNING doubled the notification volume of
    an operator who turned quarantine off on purpose: 14,198 of them against
    14,000 detections on the live instance.
    """
    calls = []
    target = tmp_path / "shell.php"
    result = ScanResult(target, True, [], engine="static")
    workflow = _build_workflow(calls, quarantine_enabled=False)

    workflow.execute(
        target,
        "MODIFY",
        scan=lambda _path: result,
        resolve_first_seen_ip=lambda _path: "127.0.0.1",
        emit_alert=lambda *args, **kwargs: calls.append(("alert", args, kwargs)),
        emit_file_quarantined=lambda *_args, **_kwargs: calls.append(("quarantine",)),
    )

    assert [call[0] for call in calls].count("registry") == 1
    alerts = [call for call in calls if call[0] == "alert"]
    assert [call[1][0] for call in alerts] == ["local_detection"]
    assert not any(call[0] == "quarantine" for call in calls)


def test_detection_records_a_digest_of_the_flagged_file(tmp_path):
    calls = []
    target = tmp_path / "shell.php"
    payload = b"<?php eval($_POST['cmd']); ?>"
    target.write_bytes(payload)
    result = ScanResult(target, True, ["webshell-rule"], engine="yara")
    workflow = _build_workflow(calls)

    workflow.execute(
        target,
        "CREATE",
        scan=lambda _path: result,
        resolve_first_seen_ip=lambda _path: "127.0.0.1",
        emit_alert=lambda *_args, **_kwargs: calls.append(("alert",)),
        emit_file_quarantined=lambda *_args, **_kwargs: calls.append(("quarantine",)),
    )

    registry_call = next(call for call in calls if call[0] == "registry")
    assert registry_call[3]["content_hash"] == hashlib.sha256(payload).hexdigest()


def test_missing_file_still_produces_a_detection_record(tmp_path):
    calls = []
    target = tmp_path / "vanished.php"
    result = ScanResult(target, True, ["webshell-rule"], engine="yara")
    workflow = _build_workflow(calls)

    workflow.execute(
        target,
        "CREATE",
        scan=lambda _path: result,
        resolve_first_seen_ip=lambda _path: "127.0.0.1",
        emit_alert=lambda *_args, **_kwargs: calls.append(("alert",)),
        emit_file_quarantined=lambda *_args, **_kwargs: calls.append(("quarantine",)),
    )

    registry_call = next(call for call in calls if call[0] == "registry")
    assert registry_call[3]["content_hash"] == ""


def test_second_restore_guard_failure_does_not_emit_quarantine(tmp_path):
    calls = []
    target = tmp_path / "shell.php"
    result = ScanResult(target, True, ["rule"], engine="static")

    class FailingSecondGuard:
        attempts = 0

        def is_recently_restored(self, _file_path):
            self.attempts += 1
            calls.append(("restore_guard", self.attempts))
            if self.attempts == 2:
                raise OSError("guard unavailable")
            return False

    workflow = _build_workflow(calls, guard=FailingSecondGuard())
    workflow.execute(
        target,
        "CREATE",
        scan=lambda _path: result,
        resolve_first_seen_ip=lambda _path: "127.0.0.1",
        emit_alert=lambda *_args, **_kwargs: calls.append(("alert",)),
        emit_file_quarantined=lambda *_args, **_kwargs: calls.append(("quarantine",)),
    )

    assert any(call[0] == "registry" for call in calls)
    assert not any(call[0] == "quarantine" for call in calls)
