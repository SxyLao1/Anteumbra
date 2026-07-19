"""Runtime-owned logger and handler construction."""

from __future__ import annotations

import logging
import os
import re
import threading
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any

from anteumbra.domain.logging import bind_symbols
from anteumbra.domain.runtime import ConfigProviderPort


def _is_tool_mode() -> bool:
    return os.environ.get("ANTEUMBRA_TOOL_MODE", "false").lower() == "true"


class RuntimeLoggerFactory:
    """Own all handlers created for one Anteumbra runtime."""

    def __init__(self, config: ConfigProviderPort) -> None:
        self._config = config
        self._lock = threading.RLock()
        self._loggers: dict[str, logging.Logger] = {}

    def get_logger(self, site_name: str) -> logging.Logger:
        """Return one monitor logger scoped to this factory instance."""
        key = f"monitor:{site_name}"
        with self._lock:
            existing = self._loggers.get(key)
            if existing is not None:
                return existing
            config = self._config.get()
            filesizes = config.get("filesizes", {})
            safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "_", str(site_name)).strip("._")
            safe_name = safe_name or "Anteumbra"
            path = self._resolve_path(
                config.get("paths", {}).get("log_base_dir", "logs")
            ) / safe_name / "monitor.log"
            logger = self._build_logger(
                key,
                path=path,
                level=logging.DEBUG,
                file_level=logging.DEBUG,
                console_level=logging.WARNING if _is_tool_mode() else logging.INFO,
                max_bytes=self._megabytes(
                    filesizes.get("log_rotation_size_mb", 100), 100
                ),
                backup_count=self._positive_int(
                    filesizes.get("log_backup_count", 5), 5
                ),
                formatter="[%(asctime)s] %(levelname)s - %(message)s",
                config=config,
            )
            self._loggers[key] = logger
            return logger

    def get_access_logger(self) -> logging.Logger:
        """Return the HTTP access logger for this runtime."""
        key = "access"
        with self._lock:
            existing = self._loggers.get(key)
            if existing is not None:
                return existing
            config = self._config.get()
            flask_config = config.get("logging", {}).get("flask", {})
            logger = self._build_logger(
                key,
                path=self._resolve_path(
                    flask_config.get("flask_log_path", "logs/Anteumbra/access.log")
                ),
                level=logging.INFO,
                file_level=logging.INFO,
                console_level=None,
                max_bytes=self._megabytes(
                    flask_config.get("flask_log_rotation_mb", 10), 10
                ),
                backup_count=self._positive_int(
                    flask_config.get("flask_log_backup_count", 5), 5
                ),
                formatter="%(message)s",
                config=config,
            )
            self._loggers[key] = logger
            return logger

    def get_application_logger(self) -> logging.Logger:
        """Return the application logger for this runtime."""
        key = "application"
        with self._lock:
            existing = self._loggers.get(key)
            if existing is not None:
                return existing
            config = self._config.get()
            filesizes = config.get("filesizes", {})
            base = self._resolve_path(
                config.get("paths", {}).get("log_base_dir", "logs")
            )
            logger = self._build_logger(
                key,
                path=base / "Anteumbra" / "flask_runtime.log",
                level=logging.DEBUG,
                file_level=logging.DEBUG,
                console_level=logging.ERROR if _is_tool_mode() else logging.INFO,
                max_bytes=self._megabytes(
                    filesizes.get("log_rotation_size_mb", 100), 100
                ),
                backup_count=self._positive_int(
                    filesizes.get("log_backup_count", 5), 5
                ),
                formatter="[%(asctime)s] %(levelname)s - [%(name)s] %(message)s",
                config=config,
            )
            self._loggers[key] = logger
            return logger

    def close(self) -> None:
        """Flush and close every handler owned by this runtime."""
        with self._lock:
            loggers = list(self._loggers.values())
            self._loggers.clear()
        errors: list[Exception] = []
        for logger in loggers:
            for handler in list(logger.handlers):
                logger.removeHandler(handler)
                try:
                    handler.flush()
                except Exception as exc:
                    errors.append(exc)
                try:
                    handler.close()
                except Exception as exc:
                    errors.append(exc)
        if errors:
            raise RuntimeError(
                f"Failed to close {len(errors)} runtime logging handler operation(s)"
            ) from errors[0]

    def _build_logger(
        self,
        name: str,
        *,
        path: Path,
        level: int,
        file_level: int,
        console_level: int | None,
        max_bytes: int,
        backup_count: int,
        formatter: str,
        config: dict[str, Any],
    ) -> logging.Logger:
        logger = logging.Logger(f"anteumbra.{id(self)}.{name}", level=level)
        logger.propagate = False
        bind_symbols(logger, config)
        if _is_tool_mode():
            logger.addHandler(logging.NullHandler())
            return logger

        path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = RotatingFileHandler(
            path,
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding="utf-8",
        )
        file_handler.setLevel(file_level)
        file_handler.setFormatter(logging.Formatter(formatter))
        logger.addHandler(file_handler)

        if console_level is not None:
            console = logging.StreamHandler()
            console.setLevel(console_level)
            console.setFormatter(logging.Formatter("%(message)s"))
            logger.addHandler(console)
        return logger

    def _resolve_path(self, value: str | Path) -> Path:
        path = Path(value).expanduser()
        if not path.is_absolute():
            path = self._config.path.parent / path
        return path.resolve()

    @staticmethod
    def _positive_int(value: Any, default: int) -> int:
        try:
            parsed = int(value)
        except (TypeError, ValueError):
            return default
        return parsed if parsed > 0 else default

    @classmethod
    def _megabytes(cls, value: Any, default: int) -> int:
        return cls._positive_int(value, default) * 1024 * 1024


__all__ = ["RuntimeLoggerFactory"]
