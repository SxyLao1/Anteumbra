from pathlib import Path


def test_config_history_logger_imports_with_package_paths(monkeypatch, tmp_path):
    """Config panel helper must work from package paths."""
    monkeypatch.chdir(tmp_path)

    from anteumbra.application import config_history_service as logger_mod

    monkeypatch.setattr(logger_mod, "_history_logger", None)

    logger = logger_mod.get_config_history_logger()

    assert logger.history_file == Path("data/config_history.json").resolve()
    assert logger.get_history() == []
    assert logger.history_file.exists()


def test_config_watcher_logger_legacy_wrapper(monkeypatch, tmp_path):
    """Legacy tools import remains available for local scripts."""
    monkeypatch.chdir(tmp_path)

    from anteumbra.application import config_history_service as service_mod
    from tools import config_watcher_logger as wrapper_mod

    monkeypatch.setattr(service_mod, "_history_logger", None)

    logger = wrapper_mod.get_config_watcher_logger()

    assert isinstance(logger, service_mod.ConfigHistoryLogger)
    assert logger.history_file == Path("data/config_history.json").resolve()
