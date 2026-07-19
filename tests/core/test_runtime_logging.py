"""Runtime-owned logger construction and teardown tests."""

from __future__ import annotations

import logging
from pathlib import Path
from types import SimpleNamespace


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


def test_site_logger_uses_stable_id_and_migrates_display_name_history(
    tmp_path,
    monkeypatch,
):
    from anteumbra.domain.site import SiteIdentity
    from anteumbra.infrastructure.utils.logger_factory import RuntimeLoggerFactory

    monkeypatch.delenv("ANTEUMBRA_TOOL_MODE", raising=False)
    root = tmp_path / "runtime"
    legacy_log = root / "logs" / "Old Name" / "monitor.log"
    legacy_log.parent.mkdir(parents=True)
    legacy_log.write_text("legacy history\n", encoding="utf-8")
    factory = RuntimeLoggerFactory(_Config(root / "config.toml", "[SITE]"))
    old_identity = SiteIdentity("default", "Old Name")
    renamed_identity = SiteIdentity("default", "Renamed Site")

    site_logger = factory.get_site_logger(old_identity)
    site_logger.info("stable history")
    factory.close()

    stable_log = root / "logs" / "default" / "monitor.log"
    assert factory.get_site_log_path(old_identity) == stable_log
    assert factory.get_site_log_path(renamed_identity) == stable_log
    assert not legacy_log.exists()
    assert "legacy history" in stable_log.read_text(encoding="utf-8")
    assert "stable history" in stable_log.read_text(encoding="utf-8")
    assert "[site=default] stable history" in stable_log.read_text(encoding="utf-8")
    assert factory.get_site_history_paths(renamed_identity) == (stable_log,)


def test_site_log_migration_preserves_conflicting_active_files(tmp_path, monkeypatch):
    from anteumbra.domain.site import SiteIdentity
    from anteumbra.infrastructure.utils.logger_factory import RuntimeLoggerFactory

    monkeypatch.delenv("ANTEUMBRA_TOOL_MODE", raising=False)
    root = tmp_path / "runtime"
    stable_log = root / "logs" / "default" / "monitor.log"
    legacy_log = root / "logs" / "Old_Name" / "monitor.log"
    stable_log.parent.mkdir(parents=True)
    legacy_log.parent.mkdir(parents=True)
    stable_log.write_text("stable before migration\n", encoding="utf-8")
    legacy_log.write_text("legacy before migration\n", encoding="utf-8")
    factory = RuntimeLoggerFactory(_Config(root / "config.toml", "[SITE]"))
    identity = SiteIdentity("default", "Old Name")

    factory.get_site_logger(identity)
    factory.close()

    history_paths = factory.get_site_history_paths(identity)
    contents = {path.read_text(encoding="utf-8") for path in history_paths}
    assert len(history_paths) == 2
    assert not legacy_log.exists()
    assert any("stable before migration" in content for content in contents)
    assert any("legacy before migration" in content for content in contents)


def test_web_log_history_uses_runtime_ports_and_escapes_content(tmp_path):
    from anteumbra.interfaces.web.log_history import (
        collect_log_history,
        render_log_history,
    )

    alpha_log = tmp_path / "owned" / "alpha.log"
    beta_log = tmp_path / "owned" / "beta.log"
    alpha_log.parent.mkdir()
    alpha_log.write_text(
        "[2026-07-19 12:02:00] INFO - file history\n"
        "[2026-07-19 12:03:00] ERROR - <script>alert(1)</script>\n",
        encoding="utf-8",
    )
    beta_log.write_text(
        "[2026-07-19 12:01:00] WARNING - beta history\n",
        encoding="utf-8",
    )
    websites = [
        SimpleNamespace(site_id="default", name="Renamed Site"),
        SimpleNamespace(site_id="beta", name="Beta Site"),
    ]
    resolved_sites = []

    def history_paths(site):
        resolved_sites.append(site)
        return (alpha_log if site.site_id == "default" else beta_log,)

    runtime = SimpleNamespace(
        config=SimpleNamespace(get_enabled_websites=lambda: websites),
        logging=SimpleNamespace(get_site_history_paths=history_paths),
        sse=SimpleNamespace(
            get_log_buffer=lambda: [
                "[2026-07-19 12:02:00] INFO - [site=default] file history",
                "[SSE] Connected to log stream",
                "[2026-07-19 12:04:00] WARNING - buffered history",
            ]
        ),
    )

    lines = collect_log_history(runtime, limit=10)
    rendered = render_log_history(lines)

    assert [(site.site_id, site.site_name) for site in resolved_sites] == [
        ("default", "Renamed Site"),
        ("beta", "Beta Site"),
    ]
    assert lines == [
        "[2026-07-19 12:01:00] WARNING - [site=beta] beta history",
        "[2026-07-19 12:02:00] INFO - [site=default] file history",
        "[2026-07-19 12:03:00] ERROR - [site=default] <script>alert(1)</script>",
        "[2026-07-19 12:04:00] WARNING - buffered history",
    ]
    assert "<script>" not in rendered
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in rendered
    assert "Connected to log stream" not in rendered


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
