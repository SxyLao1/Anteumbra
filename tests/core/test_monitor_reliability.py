import logging
import queue
import threading
from types import SimpleNamespace

from anteumbra.domain.entities import ScanResult
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


def test_full_scan_queue_falls_back_to_synchronous_processing(monkeypatch, tmp_path):
    from anteumbra.infrastructure.monitoring import monitor as monitor_module

    monkeypatch.setattr(monitor_module, "_runtime_config", _scanner_config)
    handler = monitor_module.FileMonitorHandler(
        scan_callback=lambda *_args: None,
        scan_options=ScanOptions(monitor_extensions=[".php"]),
        base_path=tmp_path,
        logger=logging.getLogger("test.monitor.queue"),
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


def test_handler_shutdown_stops_scan_worker(monkeypatch, tmp_path):
    from anteumbra.infrastructure.monitoring import monitor as monitor_module

    monkeypatch.setattr(monitor_module, "_runtime_config", _scanner_config)
    handler = monitor_module.FileMonitorHandler(
        scan_callback=lambda *_args: None,
        scan_options=ScanOptions(monitor_extensions=[".php"]),
        base_path=tmp_path,
        logger=logging.getLogger("test.monitor.shutdown"),
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

    monkeypatch.setattr(monitor_module, "_runtime_config", _scanner_config)
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
    )
    try:
        monitor.start()
        assert seen.wait(timeout=3.0)
    finally:
        monitor.stop()


def _run_suspicious_scan_with_log_attribution(
    monkeypatch, tmp_path, *, log_monitor_enabled, analyzer_factory
):
    from anteumbra.application import plugin_manager
    from anteumbra.infrastructure import quarantine, suspicious_registry
    from anteumbra.infrastructure.monitoring import log_analyzer
    from anteumbra.infrastructure.monitoring import monitor as monitor_module

    hit = tmp_path / "hit.php"
    hit.write_text("<?php", encoding="utf-8")
    recorded = []
    website = SimpleNamespace(
        log_config={"log_monitor_enabled": log_monitor_enabled},
    )
    handler = monitor_module.FileMonitorHandler(
        scan_callback=lambda path, *_args: ScanResult(
            path, True, ["test-rule"], engine="test"
        ),
        scan_options=ScanOptions(monitor_extensions=[".php"]),
        base_path=tmp_path,
        logger=logging.getLogger("test.monitor.log-attribution"),
        website=website,
    )
    try:
        monkeypatch.setattr(monitor_module.ConfigRegistry, "get_raw_config", lambda: {
            "quarantine": {"auto_quarantine_enabled": False}
        })
        monkeypatch.setattr(
            plugin_manager,
            "get_plugin_manager",
            lambda: SimpleNamespace(is_enabled=False),
        )
        monkeypatch.setattr(quarantine, "is_recently_restored", lambda _path: False)
        monkeypatch.setattr(
            suspicious_registry,
            "add",
            lambda path, features, **kwargs: recorded.append((path, features, kwargs)),
        )
        monkeypatch.setattr(log_analyzer, "LogAnalyzer", analyzer_factory)
        monkeypatch.setattr(handler, "_emit_alert", lambda *_args, **_kwargs: None)

        handler._do_scan(hit, "CREATE")
        return recorded
    finally:
        handler.shutdown()


def test_file_detection_skips_log_attribution_when_log_monitor_is_disabled(
    monkeypatch, tmp_path
):
    def unexpected_analyzer(*_args, **_kwargs):
        raise AssertionError("disabled log monitor must not inspect access logs")

    recorded = _run_suspicious_scan_with_log_attribution(
        monkeypatch,
        tmp_path,
        log_monitor_enabled=False,
        analyzer_factory=unexpected_analyzer,
    )

    assert recorded[0][2]["first_seen_ip"] == "127.0.0.1"


def test_file_detection_uses_log_attribution_when_log_monitor_is_enabled(
    monkeypatch, tmp_path
):
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


def test_recently_restored_file_does_not_emit_a_duplicate_detection(
    monkeypatch, tmp_path
):
    from anteumbra.application import plugin_manager
    from anteumbra.infrastructure import quarantine, suspicious_registry
    from anteumbra.infrastructure.monitoring import monitor as monitor_module

    restored = tmp_path / "restored.php"
    restored.write_text("<?php", encoding="utf-8")
    handler = monitor_module.FileMonitorHandler(
        scan_callback=lambda path, *_args: ScanResult(
            path, True, ["test-rule"], engine="test"
        ),
        scan_options=ScanOptions(monitor_extensions=[".php"]),
        base_path=tmp_path,
        logger=logging.getLogger("test.monitor.restore-guard"),
        website=SimpleNamespace(log_config={"log_monitor_enabled": False}),
    )
    try:
        monkeypatch.setattr(
            plugin_manager,
            "get_plugin_manager",
            lambda: SimpleNamespace(is_enabled=False),
        )
        monkeypatch.setattr(quarantine, "is_recently_restored", lambda _path: True)
        monkeypatch.setattr(
            suspicious_registry,
            "add",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(
                AssertionError("restored files must not be registered again")
            ),
        )
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


def test_recently_restored_moved_file_is_not_scanned(monkeypatch, tmp_path):
    from anteumbra.infrastructure import quarantine
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
    )
    try:
        monkeypatch.setattr(handler, "_verify_directory", lambda _path: False)
        monkeypatch.setattr(handler, "_should_monitor", lambda _path: True)
        monkeypatch.setattr(handler, "_update_cache_on_move", lambda *_args: None)
        monkeypatch.setattr(quarantine, "is_recently_restored", lambda _path: True)

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
