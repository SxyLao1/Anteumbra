"""Runtime worker and launcher lifecycle regression tests."""

import threading
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
            site_id="alpha",
            name="Alpha Display",
            path=tmp_path / "alpha",
            log_config={"log_monitor_enabled": False},
        ),
        SimpleNamespace(
            site_id="beta",
            name="Beta Display",
            path=tmp_path / "beta",
            log_config={"log_monitor_enabled": True},
        ),
    ]
    logger_sites = []

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

    def site_logger_factory(site):
        logger_sites.append(site)
        return SimpleNamespace(name=site.site_id, exception=lambda *_a: None)

    monitors, log_monitors, warnings = _start_site_monitors(
        websites,
        monitor_factory=FakeMonitor,
        logger_factory=site_logger_factory,
        scan_callback=lambda *_args: None,
        analyzer_factory=lambda website, _logger: website.name,
        log_monitor_factory=FakeLogMonitor,
    )

    assert [site.site_id for site in logger_sites] == ["alpha", "beta"]
    assert [monitor.website.name for monitor in monitors] == [
        "Alpha Display",
        "Beta Display",
    ]
    assert [monitor.analyzer for monitor in log_monitors] == ["Beta Display"]
    assert warnings == []


def test_config_provider_parses_per_site_log_configuration(tmp_path):
    from anteumbra.infrastructure.config.provider import parse_websites

    websites = parse_websites({
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


def test_runtime_lifecycle_stop_is_idempotent_and_releases_resources(
    tmp_path, monkeypatch
):
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
    stop_event = threading.Event()
    container = SimpleNamespace(
        plugin_manager=manager,
        threat_graph=graph,
        metrics=SimpleNamespace(stop=lambda: calls.append("metrics")),
        sse=SimpleNamespace(stop=lambda: calls.append("sse")),
        waf_poller=Resource("waf"),
        logging=SimpleNamespace(close=lambda: calls.append("runtime-logging")),
        scan_state=SimpleNamespace(shutdown=lambda: calls.append("scan-state")),
    )

    lifecycle = launcher.RuntimeLifecycle()
    lifecycle._state = launcher.RuntimeState(
        running=True,
        stop_event=stop_event,
        warnings=["degraded"],
        websites=["alpha"],
        monitors=[Resource("file")],
        log_monitors=[Resource("log")],
        sse_started=True,
        container=container,
    )

    lifecycle.stop()
    lifecycle.stop()

    assert stop_event.is_set()
    assert calls == [
        "log",
        "file",
        "scan-state",
        "waf",
        "plugins",
        "sse",
        "metrics",
        "graph",
        "graph-close",
        "runtime-logging",
    ]
    assert lifecycle.status() == {
        "running": False,
        "websites": ["alpha"],
        "warnings": ["degraded"],
        "monitor_count": 0,
        "log_monitor_count": 0,
    }


def test_runtime_startup_failure_rolls_back_already_started_resources(tmp_path, monkeypatch):
    """Startup failures must release the container assembled before monitor startup."""
    import pytest

    from anteumbra.application import launcher
    from anteumbra.application.runtime_builder import RuntimeLifecycleDependencies

    calls = []

    class Resource:
        def __init__(self, name):
            self.name = name

        def stop(self):
            calls.append(self.name)

    class RuntimeLogger:
        def exception(self, *_args):
            calls.append("startup-error")

    class Logging:
        def get_logger(self, _name):
            return RuntimeLogger()

        def close(self):
            calls.append("logging")

    container = SimpleNamespace(
        logging=Logging(),
        metrics=Resource("metrics"),
        notifier=None,
        siem_exporter=None,
        threat_graph=SimpleNamespace(
            persist=lambda: calls.append("graph-persist"),
            close=lambda: calls.append("graph-close"),
        ),
        quarantine=None,
        events=SimpleNamespace(bind=lambda manager: calls.append(f"bind:{manager is None}")),
        ip_blocker=None,
        registry=None,
        scanner=SimpleNamespace(scan=lambda *_args: None),
        waf_poller=None,
        scan_state=None,
        block_ledger=None,
    )
    manager = SimpleNamespace(shutdown=lambda: calls.append("plugins"))
    provider = SimpleNamespace(
        get=lambda: {"paths": {"data_dir": str(tmp_path / "data")}},
        get_enabled_websites=lambda: [
            SimpleNamespace(name="Test Site", path=tmp_path, site_id="test")
        ],
    )

    dependencies = RuntimeLifecycleDependencies(
        config_provider_factory=lambda: provider,
        path_normalizer=lambda value: value if hasattr(value, "exists") else tmp_path / value,
        version_getter=lambda: "test",
        process_identity_writer=lambda *_args: object(),
        process_identity_remover=lambda *_args: calls.append("pid"),
        container_builder=lambda **_kwargs: container,
        runtime_services_builder=lambda *_args, **_kwargs: object(),
        app_factory=lambda **_kwargs: object(),
        server_factory=lambda *_args: object(),
        monitor_factory=lambda *_args, **_kwargs: object(),
        analyzer_factory=lambda *_args: object(),
        log_monitor_factory=lambda *_args, **_kwargs: object(),
        alert_formatter=lambda _context: "",
    )
    monkeypatch.setattr(launcher, "_start_plugins", lambda *_args, **_kwargs: manager)
    monkeypatch.setattr(launcher, "assess_runtime_capabilities", lambda _config: {"warnings": []})
    monkeypatch.setattr(launcher, "_start_site_monitors", lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("monitor failure")))

    lifecycle = launcher.RuntimeLifecycle(config_provider=provider, dependencies=dependencies)
    with pytest.raises(launcher.RuntimeStartupError, match="Runtime startup failed"):
        lifecycle.run()

    assert calls == [
        "bind:False",
        "startup-error",
        "plugins",
        "bind:True",
        "metrics",
        "graph-persist",
        "graph-close",
        "pid",
        "logging",
    ]
    assert lifecycle.status()["running"] is False
