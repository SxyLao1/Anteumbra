from pathlib import Path


def test_config_watcher_logger_imports_with_package_paths(monkeypatch, tmp_path):
    """Config panel helper must import outside the source tree root."""
    monkeypatch.chdir(tmp_path)

    from tools import config_watcher_logger as logger_mod

    monkeypatch.setattr(logger_mod, "_watcher_logger", None)

    logger = logger_mod.get_config_watcher_logger()

    assert logger.history_file == Path("data/config_history.json").resolve()
    assert logger.get_history() == []
    assert logger.history_file.exists()
