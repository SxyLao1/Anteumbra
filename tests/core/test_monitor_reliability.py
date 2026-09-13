import logging
import queue
import threading
import time
from pathlib import Path
from types import SimpleNamespace

from anteumbra.domain.entities import ScanResult
from anteumbra.domain.runtime import RuntimeContext, RuntimeServices
from anteumbra.infrastructure.models import ScanOptions, Website


def _scanner_config():
    return {
        "scanner": {
            "event_queue_size": 1,
            "event_queue_put_timeout_seconds": 0.01,
            "scan_existing_on_start": True,
        },
        "monitor": {},
        "paths": {"monitor_extensions": [".php"]},
        "website": {"scan_options": {}},
    }


def _services(
    _base_path,
    *,
    config=None,
    website=None,
    registry=None,
    quarantine=None,
):
    runtime_config = config or _scanner_config()
    websites = [website] if website is not None and hasattr(website, "path") else []
    context = RuntimeContext.from_websites(runtime_config, websites)
    return RuntimeServices(
        context=context,
        registry=registry
        or SimpleNamespace(
            add=lambda *_args, **_kwargs: None,
            remove=lambda *_args, **_kwargs: True,
            was_alerted=lambda *_args, **_kwargs: False,
            mark_present=lambda *_args, **_kwargs: False,
        ),
        metrics=SimpleNamespace(
            increment=lambda *_args, **_kwargs: None,
            increment_site=lambda *_args, **_kwargs: None,
        ),
        events=SimpleNamespace(publish=lambda *_args, **_kwargs: None),
        quarantine=quarantine or SimpleNamespace(is_recently_restored=lambda _path: False),
    )


def test_full_scan_queue_falls_back_to_synchronous_processing(monkeypatch, tmp_path):
    from anteumbra.infrastructure.monitoring import monitor as monitor_module

    handler = monitor_module.FileMonitorHandler(
        scan_callback=lambda *_args: None,
        scan_options=ScanOptions(monitor_extensions=[".php"]),
        base_path=tmp_path,
        logger=logging.getLogger("test.monitor.queue"),
        services=_services(tmp_path),
    )
    try:
        handler._stop_scan_worker()
        handler._scan_worker_shutdown.clear()
        handler._scan_queue = queue.Queue(maxsize=1)
        handler._scan_queue.put((tmp_path / "queued.php", "CREATE"))
        calls = []
        monkeypatch.setattr(
            handler,
            "_do_scan",
            lambda path, event_type: calls.append((path, event_type)),
        )

        handler.enqueue_scan(tmp_path / "overflow.php", "CREATE")

        assert calls == [(tmp_path / "overflow.php", "CREATE")]
    finally:
        handler.shutdown()


def test_baseline_sweep_waits_for_capacity_instead_of_scanning_inline(monkeypatch, tmp_path):
    """A site sweep must never turn into a YARA scan on the sweep's own thread.

    The sweep offers thousands of files at once, so the queue fills; the event
    path falls back to scanning inline, which is what produced the "queue full"
    warnings seen dozens of times per run.  Baseline work waits instead.
    """
    from anteumbra.infrastructure.monitoring import monitor as monitor_module

    blocker = threading.Event()
    calls: list[tuple[str, str]] = []

    def record(path, event_type):
        calls.append((threading.current_thread().name, str(path)))
        blocker.wait(3)

    handler = monitor_module.FileMonitorHandler(
        scan_callback=lambda *_args: None,
        scan_options=ScanOptions(monitor_extensions=[".php"]),
        base_path=tmp_path,
        logger=logging.getLogger("test.monitor.baseline-capacity"),
        services=_services(tmp_path),
    )
    try:
        monkeypatch.setattr(handler, "_do_scan", record)
        handler._scan_queue = queue.Queue(maxsize=4)
        handler._baseline_queue_reserve = 2
        handler._scan_queue.put((tmp_path / "occupies-worker.php", "BASELINE"))
        time.sleep(0.3)  # let the worker take it and park on the blocker
        for index in range(2):  # fill up to the sweep's limit (4 - 2)
            handler._scan_queue.put((tmp_path / f"f{index}.php", "BASELINE"))

        def release():
            time.sleep(0.4)
            handler._scan_queue.get()

        releaser = threading.Thread(target=release, daemon=True, name="Releaser")
        releaser.start()
        started = time.time()
        accepted = handler.enqueue_baseline_scan(tmp_path / "sweep.php")
        elapsed = time.time() - started
        blocker.set()
        releaser.join(timeout=3)

        assert accepted is True
        assert elapsed >= 0.3, f"the sweep did not wait for capacity ({elapsed:.2f}s)"
        inline = [entry for entry in calls if entry[0] != "ScanWorker"]
        assert inline == [], f"the sweep scanned a file inline: {inline}"
    finally:
        blocker.set()
        handler.shutdown()


def test_baseline_sweep_stops_waiting_when_the_monitor_stops(tmp_path):
    from anteumbra.infrastructure.monitoring import monitor as monitor_module

    handler = monitor_module.FileMonitorHandler(
        scan_callback=lambda *_args: None,
        scan_options=ScanOptions(monitor_extensions=[".php"]),
        base_path=tmp_path,
        logger=logging.getLogger("test.monitor.baseline-stop"),
        services=_services(tmp_path),
    )
    try:
        handler._stop_scan_worker()
        handler._scan_queue = queue.Queue(maxsize=2)
        handler._baseline_queue_reserve = 2
        handler._scan_queue.put((tmp_path / "queued.php", "BASELINE"))
        stop = threading.Event()
        stop.set()

        assert handler.enqueue_baseline_scan(tmp_path / "sweep.php", stop) is False
    finally:
        handler.shutdown()


def test_baseline_sweep_leaves_room_for_real_events(monkeypatch, tmp_path):
    from anteumbra.infrastructure.monitoring import monitor as monitor_module

    blocker = threading.Event()
    calls: list[tuple[str, str]] = []

    def record(path, event_type):
        calls.append((threading.current_thread().name, str(path)))
        blocker.wait(3)

    handler = monitor_module.FileMonitorHandler(
        scan_callback=lambda *_args: None,
        scan_options=ScanOptions(monitor_extensions=[".php"]),
        base_path=tmp_path,
        logger=logging.getLogger("test.monitor.baseline-reserve"),
        services=_services(tmp_path),
    )
    try:
        monkeypatch.setattr(handler, "_do_scan", record)
        handler._scan_queue = queue.Queue(maxsize=10)
        handler._baseline_queue_reserve = 3
        handler._scan_queue.put((tmp_path / "occupies-worker.php", "BASELINE"))
        time.sleep(0.3)  # the worker parks on the blocker

        for index in range(7):  # 10 - 3 is the sweep's own limit
            assert handler.enqueue_baseline_scan(tmp_path / f"sweep{index}.php") is True

        assert handler._scan_queue.qsize() == 7
        # the reserve is still free, so an event is queued rather than scanned inline
        handler.enqueue_scan(tmp_path / "event.php", "CREATE")
        assert handler._scan_queue.qsize() == 8
        assert "event.php" not in [Path(path).name for _thread, path in calls]
    finally:
        blocker.set()
        handler.shutdown()


def test_handler_shutdown_stops_scan_worker(monkeypatch, tmp_path):
    from anteumbra.infrastructure.monitoring import monitor as monitor_module

    handler = monitor_module.FileMonitorHandler(
        scan_callback=lambda *_args: None,
        scan_options=ScanOptions(monitor_extensions=[".php"]),
        base_path=tmp_path,
        logger=logging.getLogger("test.monitor.shutdown"),
        services=_services(tmp_path),
    )
    worker = handler._scan_worker_thread

    handler.shutdown()

    assert worker is not None
    assert not worker.is_alive()


def test_baseline_scan_queues_existing_script_files(monkeypatch, tmp_path):
    from anteumbra.infrastructure.monitoring import monitor as monitor_module

    class Observer:
        def __init__(self):
            self.running = False

        def schedule(self, *_args, **_kwargs):
            return None

        def start(self):
            self.running = True

        def stop(self):
            self.running = False

        def join(self, *_args, **_kwargs):
            return None

        def is_alive(self):
            return self.running

    sample = tmp_path / "existing.php"
    sample.write_text("<?php echo 'baseline';", encoding="utf-8")
    (tmp_path / "ignore.txt").write_text("not monitored", encoding="utf-8")
    seen = threading.Event()

    def scan_callback(path, *_args):
        if path == sample:
            seen.set()
        return ScanResult(path, False, [], engine="test")

    monkeypatch.setattr(
        "anteumbra.infrastructure.utils.platform_utils.get_optimal_observer",
        Observer,
    )
    website = Website(
        name="Baseline",
        path=tmp_path,
        port=8080,
        enabled=True,
        scan_options=ScanOptions(monitor_extensions=[".php"]),
    )
    monitor = monitor_module.WebsiteMonitor(
        website,
        scan_callback,
        logging.getLogger("test.monitor.baseline"),
        services=_services(tmp_path, website=website),
    )
    try:
        monitor.start()
        assert seen.wait(timeout=3.0)
    finally:
        monitor.stop()


def _run_suspicious_scan_with_log_attribution(
    monkeypatch, tmp_path, *, log_monitor_enabled, analyzer_factory
):
    from anteumbra.infrastructure.monitoring import log_analyzer
    from anteumbra.infrastructure.monitoring import monitor as monitor_module

    hit = tmp_path / "hit.php"
    hit.write_text("<?php", encoding="utf-8")
    recorded = []
    website = SimpleNamespace(
        log_config={"log_monitor_enabled": log_monitor_enabled},
    )
    registry = SimpleNamespace(
        add=lambda path, features, **kwargs: recorded.append((path, features, kwargs)),
        remove=lambda *_args, **_kwargs: True,
        was_alerted=lambda *_args, **_kwargs: False,
        mark_present=lambda *_args, **_kwargs: False,
    )
    config = _scanner_config()
    config["quarantine"] = {"auto_quarantine_enabled": False}
    handler = monitor_module.FileMonitorHandler(
        scan_callback=lambda path, *_args: ScanResult(path, True, ["test-rule"], engine="test"),
        scan_options=ScanOptions(monitor_extensions=[".php"]),
        base_path=tmp_path,
        logger=logging.getLogger("test.monitor.log-attribution"),
        website=website,
        services=_services(
            tmp_path,
            config=config,
            website=website,
            registry=registry,
        ),
    )
    try:
        monkeypatch.setattr(log_analyzer, "LogAnalyzer", analyzer_factory)
        monkeypatch.setattr(handler, "_emit_alert", lambda *_args, **_kwargs: None)

        handler._do_scan(hit, "CREATE")
        return recorded
    finally:
        handler.shutdown()


def test_file_detection_skips_log_attribution_when_log_monitor_is_disabled(monkeypatch, tmp_path):
    def unexpected_analyzer(*_args, **_kwargs):
        raise AssertionError("disabled log monitor must not inspect access logs")

    recorded = _run_suspicious_scan_with_log_attribution(
        monkeypatch,
        tmp_path,
        log_monitor_enabled=False,
        analyzer_factory=unexpected_analyzer,
    )

    assert recorded[0][2]["first_seen_ip"] == "127.0.0.1"


def test_file_detection_uses_log_attribution_when_log_monitor_is_enabled(monkeypatch, tmp_path):
    class FakeAnalyzer:
        def __init__(self, *_args, **_kwargs):
            pass

        def analyze_shell_access(self, _path):
            return {"suspicious_ips": {"203.0.113.8": 2}, "log_path": "access.log"}

    recorded = _run_suspicious_scan_with_log_attribution(
        monkeypatch,
        tmp_path,
        log_monitor_enabled=True,
        analyzer_factory=FakeAnalyzer,
    )

    assert recorded[0][2]["first_seen_ip"] == "203.0.113.8"


def test_recently_restored_file_does_not_emit_a_duplicate_detection(monkeypatch, tmp_path):
    from anteumbra.infrastructure.monitoring import monitor as monitor_module

    restored = tmp_path / "restored.php"
    restored.write_text("<?php", encoding="utf-8")
    registry = SimpleNamespace(
        add=lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("restored files must not be registered again")
        ),
        remove=lambda *_args, **_kwargs: True,
    )
    handler = monitor_module.FileMonitorHandler(
        scan_callback=lambda path, *_args: ScanResult(path, True, ["test-rule"], engine="test"),
        scan_options=ScanOptions(monitor_extensions=[".php"]),
        base_path=tmp_path,
        logger=logging.getLogger("test.monitor.restore-guard"),
        website=SimpleNamespace(log_config={"log_monitor_enabled": False}),
        services=_services(
            tmp_path,
            registry=registry,
            quarantine=SimpleNamespace(is_recently_restored=lambda _path: True),
        ),
    )
    try:
        monkeypatch.setattr(
            handler,
            "_emit_alert",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(
                AssertionError("restored files must not alert again")
            ),
        )

        handler._do_scan(restored, "CREATE")
    finally:
        handler.shutdown()


def test_reupload_inside_the_duplicate_window_is_still_scanned(monkeypatch, tmp_path):
    """A file deleted and put back seconds later must not be filtered away.

    The duplicate window exists to collapse the MODIFY/CLOSE burst that follows
    one write.  Applying it to a CREATE hid the exact case that matters: an
    identical webshell re-uploaded 1.4s after deletion was dropped, so it was
    never scanned and its record stayed "missing" while the file sat on disk.
    """
    from anteumbra.infrastructure.monitoring import monitor as monitor_module

    order = []
    registry = SimpleNamespace(
        add=lambda *_args, **_kwargs: None,
        remove=lambda *_args, **_kwargs: True,
        mark_present=lambda path, **kwargs: order.append(("mark_present", str(path))),
    )
    returning = tmp_path / "back.php"
    returning.write_text("<?php", encoding="utf-8")
    handler = monitor_module.FileMonitorHandler(
        scan_callback=lambda *_args: None,
        scan_options=ScanOptions(monitor_extensions=[".php"]),
        base_path=tmp_path,
        logger=logging.getLogger("test.monitor.reupload-window"),
        website=SimpleNamespace(log_config={"log_monitor_enabled": False}),
        services=_services(tmp_path, registry=registry),
    )
    try:
        monkeypatch.setattr(
            handler, "enqueue_scan", lambda path, event_type: order.append(("scan", str(path)))
        )
        handler._recent_files[monitor_module.path_to_key(returning.resolve())] = time.time() - 1.0

        handler._handle_event(SimpleNamespace(src_path=str(returning)), "CREATE")
    finally:
        handler.shutdown()

    assert [entry[0] for entry in order] == ["mark_present", "scan"]


def test_touch_noise_inside_the_duplicate_window_is_still_dropped(monkeypatch, tmp_path):
    from anteumbra.infrastructure.monitoring import monitor as monitor_module

    queued = []
    touched = tmp_path / "noisy.php"
    touched.write_text("<?php", encoding="utf-8")
    handler = monitor_module.FileMonitorHandler(
        scan_callback=lambda *_args: None,
        scan_options=ScanOptions(monitor_extensions=[".php"]),
        base_path=tmp_path,
        logger=logging.getLogger("test.monitor.touch-window"),
        website=SimpleNamespace(log_config={"log_monitor_enabled": False}),
        services=_services(tmp_path),
    )
    try:
        monkeypatch.setattr(
            handler, "enqueue_scan", lambda path, event_type: queued.append((path, event_type))
        )
        handler._handle_event(SimpleNamespace(src_path=str(touched)), "MODIFY")
        handler._handle_event(SimpleNamespace(src_path=str(touched)), "MODIFY")
        handler._handle_event(SimpleNamespace(src_path=str(touched)), "CLOSE")
    finally:
        handler.shutdown()

    assert queued == [(touched.resolve(), "MODIFY")]


def test_out_of_band_delete_marks_the_registry_record_missing(tmp_path):
    from anteumbra.infrastructure.monitoring import monitor as monitor_module

    removed = []
    registry = SimpleNamespace(
        get=lambda *_args, **_kwargs: None,
        remove=lambda path, **kwargs: removed.append((path, kwargs)) or True,
        mark_present=lambda *_args, **_kwargs: False,
    )
    gone = tmp_path / "cleaned-up.php"
    handler = monitor_module.FileMonitorHandler(
        scan_callback=lambda *_args: None,
        scan_options=ScanOptions(monitor_extensions=[".php"]),
        base_path=tmp_path,
        logger=logging.getLogger("test.monitor.delete-reason"),
        services=_services(tmp_path, registry=registry),
    )
    try:
        handler.on_deleted(SimpleNamespace(src_path=str(gone)))
    finally:
        handler.shutdown()

    assert len(removed) == 1
    assert removed[0][1]["reason"] == "deleted-on-disk"
    assert removed[0][1]["site"] == handler.site


def test_quarantine_completion_is_not_recorded_as_an_operator_deletion(tmp_path):
    from anteumbra.infrastructure.monitoring import monitor as monitor_module

    removed = []
    registry = SimpleNamespace(
        get=lambda *_args, **_kwargs: {"quarantine_id": "q-1", "file_exists": False},
        remove=lambda path, **kwargs: removed.append((path, kwargs)) or True,
        mark_present=lambda *_args, **_kwargs: False,
    )
    gone = tmp_path / "quarantined.php"
    handler = monitor_module.FileMonitorHandler(
        scan_callback=lambda *_args: None,
        scan_options=ScanOptions(monitor_extensions=[".php"]),
        base_path=tmp_path,
        logger=logging.getLogger("test.monitor.delete-quarantine"),
        services=_services(tmp_path, registry=registry),
    )
    try:
        handler.on_deleted(SimpleNamespace(src_path=str(gone)))
    finally:
        handler.shutdown()

    assert removed[0][1]["reason"] == "quarantined"


def test_touched_path_clears_a_missing_record_before_the_scan_is_queued(monkeypatch, tmp_path):
    from anteumbra.infrastructure.monitoring import monitor as monitor_module

    order = []
    registry = SimpleNamespace(
        add=lambda *_args, **_kwargs: None,
        remove=lambda *_args, **_kwargs: True,
        mark_present=lambda path, **kwargs: order.append(("mark_present", str(path))),
    )
    returning = tmp_path / "back.php"
    returning.write_text("<?php", encoding="utf-8")
    handler = monitor_module.FileMonitorHandler(
        scan_callback=lambda *_args: None,
        scan_options=ScanOptions(monitor_extensions=[".php"]),
        base_path=tmp_path,
        logger=logging.getLogger("test.monitor.mark-present"),
        website=SimpleNamespace(log_config={"log_monitor_enabled": False}),
        services=_services(tmp_path, registry=registry),
    )
    try:
        monkeypatch.setattr(
            handler, "enqueue_scan", lambda path, event_type: order.append(("scan", str(path)))
        )

        handler._handle_event(SimpleNamespace(src_path=str(returning)), "CREATE")
    finally:
        handler.shutdown()

    assert [entry[0] for entry in order] == ["mark_present", "scan"]


def test_startup_announces_a_disabled_quarantine_switch(tmp_path, caplog):
    from anteumbra.infrastructure.monitoring import monitor as monitor_module

    config = _scanner_config()
    config["quarantine"] = {"auto_quarantine_enabled": False}
    logger = logging.getLogger("test.monitor.quarantine-announcement")
    website = Website(
        name="Quiet",
        path=tmp_path,
        port=8080,
        enabled=True,
        scan_options=ScanOptions(monitor_extensions=[".php"]),
    )
    monitor = monitor_module.WebsiteMonitor(
        website,
        lambda *_args: None,
        logger,
        services=_services(tmp_path, config=config, website=website),
    )

    with caplog.at_level(logging.INFO, logger=logger.name):
        monitor._announce_quarantine_state()

    announcements = [record for record in caplog.records if "自动隔离总开关关闭" in record.message]
    assert len(announcements) == 1
    assert announcements[0].levelno == logging.INFO


def test_startup_stays_silent_while_quarantine_is_enabled(tmp_path, caplog):
    from anteumbra.infrastructure.monitoring import monitor as monitor_module

    config = _scanner_config()
    config["quarantine"] = {"auto_quarantine_enabled": True}
    logger = logging.getLogger("test.monitor.quarantine-silent")
    website = Website(
        name="Loud",
        path=tmp_path,
        port=8080,
        enabled=True,
        scan_options=ScanOptions(monitor_extensions=[".php"]),
    )
    monitor = monitor_module.WebsiteMonitor(
        website,
        lambda *_args: None,
        logger,
        services=_services(tmp_path, config=config, website=website),
    )

    with caplog.at_level(logging.DEBUG, logger=logger.name):
        monitor._announce_quarantine_state()

    assert not [record for record in caplog.records if "自动隔离总开关关闭" in record.message]


def test_startup_reconcile_aligns_registry_with_the_filesystem(monkeypatch, tmp_path):
    from anteumbra.infrastructure.monitoring import monitor as monitor_module

    class Observer:
        def schedule(self, *_args, **_kwargs):
            return None

        def start(self):
            return None

        def stop(self):
            return None

        def join(self, *_args, **_kwargs):
            return None

        def is_alive(self):
            return True

    calls = []
    registry = SimpleNamespace(
        add=lambda *_args, **_kwargs: None,
        remove=lambda *_args, **_kwargs: True,
        mark_present=lambda *_args, **_kwargs: False,
        reconcile_filesystem=lambda *args: (
            calls.append(args) or {"checked": 940, "marked_missing": 2, "marked_present": 0}
        ),
    )
    monkeypatch.setattr(
        "anteumbra.infrastructure.utils.platform_utils.get_optimal_observer", Observer
    )
    website = Website(
        name="Reconcile",
        path=tmp_path,
        port=8080,
        enabled=True,
        scan_options=ScanOptions(monitor_extensions=[".php"]),
    )
    monitor = monitor_module.WebsiteMonitor(
        website,
        lambda *_args: None,
        logging.getLogger("test.monitor.reconcile"),
        services=_services(tmp_path, config=_scanner_config(), website=website, registry=registry),
    )

    monitor._reconcile_registry_state()

    # Unfiltered on purpose: records that belong to no configured site would
    # otherwise never be checked against the filesystem.
    assert calls == [()]


def test_startup_reconcile_failure_does_not_stop_the_monitor(monkeypatch, tmp_path):
    from anteumbra.infrastructure.monitoring import monitor as monitor_module

    class Observer:
        def schedule(self, *_args, **_kwargs):
            return None

        def start(self):
            return None

        def stop(self):
            return None

        def join(self, *_args, **_kwargs):
            return None

        def is_alive(self):
            return True

    def explode(_site_id):
        raise OSError("registry unavailable")

    registry = SimpleNamespace(
        add=lambda *_args, **_kwargs: None,
        remove=lambda *_args, **_kwargs: True,
        mark_present=lambda *_args, **_kwargs: False,
        reconcile_filesystem=explode,
    )
    monkeypatch.setattr(
        "anteumbra.infrastructure.utils.platform_utils.get_optimal_observer", Observer
    )
    website = Website(
        name="ReconcileFail",
        path=tmp_path,
        port=8080,
        enabled=True,
        scan_options=ScanOptions(monitor_extensions=[".php"]),
    )
    monitor = monitor_module.WebsiteMonitor(
        website,
        lambda *_args: None,
        logging.getLogger("test.monitor.reconcile-failure"),
        services=_services(tmp_path, config=_scanner_config(), website=website, registry=registry),
    )

    monitor._reconcile_registry_state()  # must not raise


def test_stale_delete_event_does_not_hide_a_restored_file(tmp_path):
    from anteumbra.infrastructure.monitoring import monitor as monitor_module

    restored = tmp_path / "restored.php"
    restored.write_text("<?php", encoding="utf-8")
    registry = SimpleNamespace(
        get=lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("stale deletes must not read Registry state")
        ),
        remove=lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("stale deletes must not hide restored files")
        ),
    )
    handler = monitor_module.FileMonitorHandler(
        scan_callback=lambda *_args: None,
        scan_options=ScanOptions(monitor_extensions=[".php"]),
        base_path=tmp_path,
        logger=logging.getLogger("test.monitor.stale-delete-guard"),
        services=_services(tmp_path, registry=registry),
    )
    try:
        handler.on_deleted(SimpleNamespace(src_path=str(restored)))
    finally:
        handler.shutdown()


def test_recently_restored_moved_file_is_not_scanned(monkeypatch, tmp_path):
    from anteumbra.infrastructure.monitoring import monitor as monitor_module

    destination = tmp_path / "restored.php"
    destination.write_text("<?php", encoding="utf-8")
    scans = []
    handler = monitor_module.FileMonitorHandler(
        scan_callback=lambda *args: scans.append(args),
        scan_options=ScanOptions(monitor_extensions=[".php"]),
        base_path=tmp_path,
        logger=logging.getLogger("test.monitor.restore-move-guard"),
        website=SimpleNamespace(log_config={"log_monitor_enabled": False}),
        services=_services(
            tmp_path,
            quarantine=SimpleNamespace(is_recently_restored=lambda _path: True),
        ),
    )
    try:
        monkeypatch.setattr(handler, "_verify_directory", lambda _path: False)
        monkeypatch.setattr(handler, "_should_monitor", lambda _path: True)
        monkeypatch.setattr(handler, "_update_cache_on_move", lambda *_args: None)
        handler.on_moved(
            SimpleNamespace(
                src_path=str(tmp_path / "quarantine-source.php"),
                dest_path=str(destination),
            )
        )

        assert scans == []
    finally:
        handler.shutdown()


def test_moved_file_uses_the_standard_scan_queue(monkeypatch, tmp_path):
    from anteumbra.infrastructure.monitoring import monitor as monitor_module

    destination = tmp_path / "moved.php"
    destination.write_text("<?php", encoding="utf-8")
    handler = monitor_module.FileMonitorHandler(
        scan_callback=lambda *_args: None,
        scan_options=ScanOptions(monitor_extensions=[".php"]),
        base_path=tmp_path,
        logger=logging.getLogger("test.monitor.moved-queue"),
        website=SimpleNamespace(log_config={"log_monitor_enabled": False}),
        services=_services(tmp_path),
    )
    queued = []
    try:
        monkeypatch.setattr(handler, "_verify_directory", lambda _path: False)
        monkeypatch.setattr(handler, "_update_cache_on_move", lambda *_args: None)
        monkeypatch.setattr(
            handler,
            "enqueue_scan",
            lambda path, event_type: queued.append((path, event_type)),
        )

        handler.on_moved(
            SimpleNamespace(
                src_path=str(tmp_path / "staged.php"),
                dest_path=str(destination),
            )
        )

        assert queued == [(destination.resolve(), "MOVE")]
    finally:
        handler.shutdown()
