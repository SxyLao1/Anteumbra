"""Runtime-owned logger construction and teardown tests."""

from __future__ import annotations

import logging
from pathlib import Path


class _Config:
    def __init__(self, path: Path, symbol: str) -> None:
        self.path = path
        self._symbol = symbol

    def get(self) -> dict:
        return {
            "paths": {"log_base_dir": "logs"},
            "filesizes": {
                "log_rotation_size_mb": 1,
                "log_backup_count": 2,
            },
            "logging": {
                "symbols": {"notice": self._symbol},
                "flask": {
                    "flask_log_path": "logs/Anteumbra/access.log",
                    "flask_log_rotation_mb": 1,
                    "flask_log_backup_count": 2,
                },
            },
        }


def test_runtime_logger_factories_are_isolated_and_close_owned_handlers(
    tmp_path,
    monkeypatch,
):
    from anteumbra.domain.logging import log_with_symbol
    from anteumbra.infrastructure.utils.logger_factory import RuntimeLoggerFactory

    monkeypatch.delenv("ANTEUMBRA_TOOL_MODE", raising=False)
    first_root = tmp_path / "first"
    second_root = tmp_path / "second"
    first = RuntimeLoggerFactory(_Config(first_root / "config.toml", "[FIRST]"))
    second = RuntimeLoggerFactory(_Config(second_root / "config.toml", "[SECOND]"))

    first_logger = first.get_logger("same/site")
    second_logger = second.get_logger("same/site")
    first_handlers = tuple(first_logger.handlers)
    second_handlers = tuple(second_logger.handlers)

    assert first_logger is first.get_logger("same/site")
    assert first_logger is not second_logger
    assert not set(first_handlers).intersection(second_handlers)
    assert any(
        str(first_root / "logs") in handler.baseFilename
        for handler in first_handlers
        if hasattr(handler, "baseFilename")
    )
    assert any(
        str(second_root / "logs") in handler.baseFilename
        for handler in second_handlers
        if hasattr(handler, "baseFilename")
    )

    log_with_symbol("notice", "warning", "first runtime", first_logger)
    log_with_symbol("notice", "warning", "second runtime", second_logger)
    first.close()

    assert first_logger.handlers == []
    assert second_logger.handlers
    second_logger.warning("still open")
    second.close()
    second.close()

    first_log = first_root / "logs" / "same_site" / "monitor.log"
    second_log = second_root / "logs" / "same_site" / "monitor.log"
    assert "[FIRST] first runtime" in first_log.read_text(encoding="utf-8")
    second_text = second_log.read_text(encoding="utf-8")
    assert "[SECOND] second runtime" in second_text
    assert "still open" in second_text
    assert all(
        handler.stream is None
        for handler in (*first_handlers, *second_handlers)
        if isinstance(handler, logging.FileHandler)
    )


def test_tool_mode_does_not_create_log_files(tmp_path, monkeypatch):
    from anteumbra.infrastructure.utils.logger_factory import RuntimeLoggerFactory

    monkeypatch.setenv("ANTEUMBRA_TOOL_MODE", "true")
    root = tmp_path / "tool"
    factory = RuntimeLoggerFactory(_Config(root / "config.toml", "[TOOL]"))

    logger = factory.get_application_logger()

    assert len(logger.handlers) == 1
    assert isinstance(logger.handlers[0], logging.NullHandler)
    assert not (root / "logs").exists()
    factory.close()
