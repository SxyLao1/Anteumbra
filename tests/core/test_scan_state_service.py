"""Runtime-owned manual scan state tests."""

import threading
import time
from types import SimpleNamespace


def _job(*, completed_at=None, thread=None):
    return {
        "scan_id": "scan",
        "completed_at": completed_at,
        "cancel_flag": {"cancelled": False},
        "thread": thread,
    }


def test_scan_state_instances_are_isolated_and_expire_completed_data():
    from anteumbra.application.scan_state_service import ScanRuntimeState

    first = ScanRuntimeState()
    second = ScanRuntimeState()
    first.register_job("old", _job(completed_at=10.0))
    first.register_job("active", _job())
    first.put_result("old", SimpleNamespace(end_time=10.0))

    assert first.cleanup_jobs(20.0, now=40.0) == 1
    assert first.cleanup_results(20.0, now=40.0) == 1
    assert first.get_job("old") is None
    assert first.get_job("active") is not None
    assert second.get_job("active") is None


def test_scan_state_returns_job_snapshots_and_cancels_selected_job():
    from anteumbra.application.scan_state_service import ScanRuntimeState

    state = ScanRuntimeState()
    state.register_job("alpha", _job())
    state.register_job("beta", _job())

    snapshot = state.get_job("alpha")
    snapshot["completed_at"] = 1.0

    assert state.get_job("alpha")["completed_at"] is None
    assert state.cancel("alpha") == 1
    assert state.get_job("alpha")["cancel_flag"]["cancelled"] is True
    assert state.get_job("beta")["cancel_flag"]["cancelled"] is False


def test_scan_state_shutdown_cancels_and_joins_workers():
    from anteumbra.application.scan_state_service import ScanRuntimeState

    state = ScanRuntimeState()
    started = threading.Event()
    cancel_flag = {"cancelled": False}

    def worker():
        started.set()
        while not cancel_flag["cancelled"]:
            time.sleep(0.01)

    thread = threading.Thread(target=worker)
    job = _job(thread=thread)
    job["cancel_flag"] = cancel_flag
    state.register_job("active", job)
    thread.start()
    assert started.wait(1.0)

    state.shutdown(timeout=1.0)
    state.shutdown(timeout=1.0)

    assert cancel_flag["cancelled"] is True
    assert not thread.is_alive()
    assert state.get_job("active") is None
    assert state.put_result("late", SimpleNamespace(end_time=time.time())) is False
