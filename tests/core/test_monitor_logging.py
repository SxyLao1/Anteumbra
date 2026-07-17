from types import SimpleNamespace
from unittest.mock import Mock


class _Observer:
    def schedule(self, *_args, **_kwargs):
        return None

    def start(self):
        return None

    def is_alive(self):
        return True


def test_successful_monitor_startup_does_not_emit_critical_logs(monkeypatch, tmp_path):
    from anteumbra.infrastructure.monitoring import monitor as monitor_module
    from anteumbra.infrastructure.utils import platform_utils

    emitted = []
    logger = Mock()
    website = SimpleNamespace(
        name="Test Site",
        path=tmp_path,
        scan_options=object(),
    )

    monkeypatch.setattr(monitor_module, "FileMonitorHandler", Mock())
    monkeypatch.setattr(platform_utils, "get_optimal_observer", _Observer)
    monkeypatch.setattr(monitor_module.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(
        monitor_module,
        "log_with_symbol",
        lambda symbol, level, message, _logger: emitted.append(
            (symbol, level, message)
        ),
    )

    monitor = monitor_module.WebsiteMonitor(website, Mock(), logger)
    monitor.start()

    logger.debug.assert_called_once_with("[DEBUG][CONFIG] Website配置: Test Site")
    logger.critical.assert_not_called()
    assert ("success", "info", "Monitor started successfully") in emitted
