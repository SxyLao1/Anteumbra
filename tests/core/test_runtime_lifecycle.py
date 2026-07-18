"""Runtime worker and launcher lifecycle regression tests."""

from pathlib import Path
from types import SimpleNamespace


def test_sse_worker_start_is_idempotent_and_stop_disconnects_clients():
    from anteumbra.infrastructure.utils import sse_manager

    sse_manager.stop_sse_worker()
    try:
        sse_manager.start_sse_worker()
        first_thread = sse_manager._worker_thread
        sse_manager.start_sse_worker()

        assert sse_manager.is_sse_worker_running() is True
        assert sse_manager._worker_thread is first_thread

        sse_manager.register_sse_client()
        assert sse_manager.get_connected_client_count() == 1
        assert sse_manager.stop_sse_worker() is True
        assert sse_manager.is_sse_worker_running() is False
        assert sse_manager.get_connected_client_count() == 0
    finally:
        sse_manager.stop_sse_worker()


def test_sse_cleanup_leaves_a_disconnect_signal_for_the_generator():
    from anteumbra.infrastructure.utils import sse_manager

    sse_manager.stop_sse_worker()
    client_queue = sse_manager.register_sse_client()

    assert sse_manager.cleanup_sse_connections() == 1
    assert sse_manager.get_connected_client_count() == 0
    assert client_queue.get_nowait() is None


def test_metrics_worker_start_is_idempotent_and_stops(tmp_path, monkeypatch):
    from anteumbra.infrastructure.monitoring import metrics

    metrics.stop_metrics(persist=False)
    collector = metrics.MetricsCollector(tmp_path / "metrics.json")
    monkeypatch.setattr(metrics, "_metrics_instance", collector)
    monkeypatch.setattr(collector, "record_memory_usage", lambda: None)
    monkeypatch.setattr(collector, "get", lambda: dict(collector._stats))

    try:
        metrics.preload_metrics()
        first_thread = metrics._metrics_thread
        metrics.preload_metrics()

        assert metrics.is_metrics_running() is True
        assert metrics._metrics_thread is first_thread
        assert metrics.stop_metrics() is True
        assert metrics.is_metrics_running() is False
        assert collector.data_path.exists()
    finally:
        metrics.stop_metrics(persist=False)


def test_metrics_reports_total_registry_size(tmp_path, monkeypatch):
    from anteumbra.infrastructure.monitoring.metrics import MetricsCollector
    from anteumbra.infrastructure import suspicious_registry

    collector = MetricsCollector(tmp_path / "metrics.json")

    def fake_get_all(*, include_deleted=False, include_false_positive=False):
        if include_deleted and include_false_positive:
            return [{"file_path": "a"}, {"file_path": "b"}, {"file_path": "c"}]
        return [{"file_path": "a"}]

    monkeypatch.setattr(suspicious_registry, "get_all", fake_get_all)

    snapshot = collector.get()

    assert snapshot["scan_suspicious"] == 1
    assert snapshot["registry_size"] == 3


def test_site_monitors_start_for_every_enabled_website(tmp_path):
    from anteumbra.application.launcher import _start_site_monitors

    websites = [
        SimpleNamespace(
            name="alpha", path=tmp_path / "alpha", log_config={"log_monitor_enabled": False}
        ),
        SimpleNamespace(
            name="beta", path=tmp_path / "beta", log_config={"log_monitor_enabled": True}
        ),
    ]

    class FakeMonitor:
        def __init__(self, website, _scan, _logger):
            self.website = website
            self.is_running = False

        def start(self):
            self.is_running = True

    class FakeLogMonitor:
        def __init__(self, _logger, analyzer):
            self.analyzer = analyzer
            self.is_running = False

        def start(self):
            self.is_running = True

    monitors, log_monitors, warnings = _start_site_monitors(
        websites,
        monitor_factory=FakeMonitor,
        logger_factory=lambda name: SimpleNamespace(name=name, exception=lambda *_a: None),
        scan_callback=lambda *_args: None,
        analyzer_factory=lambda website, _logger: website.name,
        log_monitor_factory=FakeLogMonitor,
    )

    assert [monitor.website.name for monitor in monitors] == ["alpha", "beta"]
    assert [monitor.analyzer for monitor in log_monitors] == ["beta"]
    assert warnings == []


def test_config_registry_parses_per_site_log_configuration(tmp_path):
    from anteumbra.infrastructure.config.registry import ConfigRegistry

    websites = ConfigRegistry._parse_websites({
        "website": [
            {
                "name": "Alpha",
                "path": str(tmp_path / "alpha"),
                "port": 80,
                "enabled": True,
                "log_config": {
                    "log_monitor_enabled": True,
                    "access_log_path": str(tmp_path / "alpha.log"),
                },
            },
            {
                "name": "Beta",
                "path": str(tmp_path / "beta"),
                "port": 8080,
                "enabled": True,
                "log_config": {"log_monitor_enabled": False},
            },
        ]
    })

    assert [website.name for website in websites] == ["Alpha", "Beta"]
    assert websites[0].log_config["log_monitor_enabled"] is True
    assert websites[0].scan_options.access_log_path == str(tmp_path / "alpha.log")


def test_stop_all_is_idempotent_and_releases_resources(tmp_path, monkeypatch):
    from anteumbra.application import launcher
    from anteumbra.infrastructure.monitoring import metrics
    from anteumbra.infrastructure.utils import sse_manager

    monkeypatch.chdir(tmp_path)
    calls = []

    class Resource:
        def __init__(self, name):
            self.name = name

        def stop(self):
            calls.append(self.name)

    manager = SimpleNamespace(shutdown=lambda: calls.append("plugins"))
    graph = SimpleNamespace(persist=lambda: calls.append("graph"))
    stop_event = __import__("threading").Event()
    monkeypatch.setattr(sse_manager, "stop_sse_worker", lambda: calls.append("sse"))
    monkeypatch.setattr(metrics, "stop_metrics", lambda: calls.append("metrics"))

    launcher._launcher_state.clear()
    launcher._launcher_state.update({
        "running": True,
        "stop_event": stop_event,
        "warnings": ["degraded"],
        "websites": ["alpha"],
        "monitors": [Resource("file")],
        "log_monitors": [Resource("log")],
        "waf_poller": Resource("waf"),
        "plugin_manager": manager,
        "threat_graph": graph,
        "sse_started": True,
        "threads": [],
    })

    launcher.stop_all()
    launcher.stop_all()

    assert stop_event.is_set()
    assert calls == ["log", "file", "waf", "plugins", "sse", "metrics", "graph"]
    assert launcher.get_runtime_status() == {
        "running": False,
        "websites": ["alpha"],
        "warnings": ["degraded"],
        "monitor_count": 0,
        "log_monitor_count": 0,
    }
