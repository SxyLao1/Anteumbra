"""Runtime worker and launcher lifecycle regression tests."""

from types import SimpleNamespace


def test_metrics_worker_start_is_idempotent_and_stops(tmp_path, monkeypatch):
    from anteumbra.infrastructure.monitoring.metrics import MetricsCollector

    collector = MetricsCollector(tmp_path / "metrics.json")
    monkeypatch.setattr(collector, "record_memory_usage", lambda: None)
    monkeypatch.setattr(collector, "get", lambda: dict(collector._stats))

    try:
        collector.start()
        first_thread = collector._worker
        collector.start()

        assert collector.is_running is True
        assert collector._worker is first_thread
        assert collector.stop() is True
        assert collector.is_running is False
        assert collector.data_path.exists()
    finally:
        collector.stop(persist=False)


def test_metrics_reports_total_registry_size(tmp_path):
    from anteumbra.infrastructure.monitoring.metrics import MetricsCollector

    def fake_get_all(*, include_deleted=False, include_false_positive=False):
        if include_deleted and include_false_positive:
            return [{"file_path": "a"}, {"file_path": "b"}, {"file_path": "c"}]
        return [{"file_path": "a"}]

    collector = MetricsCollector(
        tmp_path / "metrics.json", registry_reader=fake_get_all
    )

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

    monkeypatch.chdir(tmp_path)
    calls = []

    class Resource:
        def __init__(self, name):
            self.name = name

        def stop(self):
            calls.append(self.name)

    manager = SimpleNamespace(shutdown=lambda: calls.append("plugins"))
    graph = SimpleNamespace(
        persist=lambda: calls.append("graph"),
        close=lambda: calls.append("graph-close"),
    )
    stop_event = __import__("threading").Event()
    container = SimpleNamespace(
        metrics=SimpleNamespace(stop=lambda: calls.append("metrics")),
        sse=SimpleNamespace(stop=lambda: calls.append("sse")),
        waf_poller=Resource("waf"),
        logging=SimpleNamespace(close=lambda: calls.append("runtime-logging")),
    )

    launcher._launcher_state.clear()
    launcher._launcher_state.update({
        "running": True,
        "stop_event": stop_event,
        "warnings": ["degraded"],
        "websites": ["alpha"],
        "monitors": [Resource("file")],
        "log_monitors": [Resource("log")],
        "plugin_manager": manager,
        "threat_graph": graph,
        "sse_started": True,
        "threads": [],
        "container": container,
    })

    launcher.stop_all()
    launcher.stop_all()

    assert stop_event.is_set()
    assert calls == [
        "log",
        "file",
        "waf",
        "plugins",
        "sse",
        "metrics",
        "graph",
        "graph-close",
        "runtime-logging",
    ]
    assert launcher.get_runtime_status() == {
        "running": False,
        "websites": ["alpha"],
        "warnings": ["degraded"],
        "monitor_count": 0,
        "log_monitor_count": 0,
    }
