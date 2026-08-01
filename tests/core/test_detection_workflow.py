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


def _build_workflow(calls, *, quarantine_enabled=True, restored=False, guard=None):
    from anteumbra.application.detection_workflow import DetectionWorkflow

    registry = SimpleNamespace(
        add=lambda path, features, **kwargs: calls.append(("registry", str(path), features, kwargs))
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
    assert calls[6][3]["first_seen_ip"] == "203.0.113.8"
    assert calls[6][3]["detection_source"] == "passive"
    assert calls[8][2] == {
        "file_path": str(target),
        "rule_name": "webshell-rule",
        "features": ["webshell-rule"],
        "original_path": str(target),
        "first_seen_ip": "203.0.113.8",
    }


def test_disabled_auto_quarantine_still_registers_and_emits_skip_alert(tmp_path):
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
    assert [call[1][0] for call in alerts] == [
        "local_detection",
        "quarantine_skipped",
    ]
    assert alerts[1][2] == {"reason": "auto_quarantine_disabled"}
    assert not any(call[0] == "quarantine" for call in calls)


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
