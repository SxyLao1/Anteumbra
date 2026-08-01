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
from anteumbra.domain.site import SiteIdentity

logger = logging.getLogger(__name__)


def _is_tool_mode() -> bool:
    return os.environ.get("ANTEUMBRA_TOOL_MODE", "false").lower() == "true"


class RuntimeLoggerFactory:
    """Own all handlers created for one Anteumbra runtime."""

    def __init__(self, config: ConfigProviderPort) -> None:
        self._config = config
        self._lock = threading.RLock()
        self._loggers: dict[str, logging.Logger] = {}

    def get_logger(self, component: str) -> logging.Logger:
        """Return one component logger scoped to this factory instance."""
        return self._get_monitor_logger(
            key=f"component:{component}",
            path=self._monitor_log_path(component),
            formatter="[%(asctime)s] %(levelname)s - %(message)s",
        )

    def get_site_logger(self, site: SiteIdentity) -> logging.Logger:
        """Return a monitor logger keyed and stored by stable site ID."""
        key = f"site:{site.site_id}"
        with self._lock:
            existing = self._loggers.get(key)
            if existing is not None:
                return existing
            if not _is_tool_mode():
                self._migrate_legacy_site_logs(site)
            return self._get_monitor_logger(
                key=key,
                path=self.get_site_log_path(site),
                formatter=(f"[%(asctime)s] %(levelname)s - [site={site.site_id}] %(message)s"),
            )

    def get_site_log_path(self, site: SiteIdentity) -> Path:
        """Return the stable active monitor log path for one site."""
        return self._monitor_log_path(site.site_id)

    def get_site_history_paths(self, site: SiteIdentity) -> tuple[Path, ...]:
        """Return stable logs plus legacy display-name log files."""
        primary_dir = self.get_site_log_path(site).parent
        directories = (primary_dir, *self._legacy_site_log_dirs(site))
        paths: list[Path] = []
        seen: set[str] = set()
        for directory in directories:
            directory_key = str(directory).casefold()
            if directory_key in seen or not directory.is_dir():
                continue
            seen.add(directory_key)
            paths.extend(path for path in directory.glob("monitor.log*") if path.is_file())
        return tuple(sorted(paths, key=self._history_sort_key))

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
                max_bytes=self._megabytes(flask_config.get("flask_log_rotation_mb", 10), 10),
                backup_count=self._positive_int(flask_config.get("flask_log_backup_count", 5), 5),
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
            base = self._resolve_path(config.get("paths", {}).get("log_base_dir", "logs"))
            logger = self._build_logger(
                key,
                path=base / "Anteumbra" / "flask_runtime.log",
                level=logging.DEBUG,
                file_level=logging.DEBUG,
                console_level=logging.ERROR if _is_tool_mode() else logging.INFO,
                max_bytes=self._megabytes(filesizes.get("log_rotation_size_mb", 100), 100),
                backup_count=self._positive_int(filesizes.get("log_backup_count", 5), 5),
                formatter="[%(asctime)s] %(levelname)s - [%(name)s] %(message)s",
                config=config,
            )
            self._loggers[key] = logger
            return logger

    def _get_monitor_logger(
        self,
        *,
        key: str,
        path: Path,
        formatter: str,
    ) -> logging.Logger:
        with self._lock:
            existing = self._loggers.get(key)
            if existing is not None:
                return existing
            config = self._config.get()
            filesizes = config.get("filesizes", {})
            runtime_logger = self._build_logger(
                key,
                path=path,
                level=logging.DEBUG,
                file_level=logging.DEBUG,
                console_level=logging.WARNING if _is_tool_mode() else logging.INFO,
                max_bytes=self._megabytes(filesizes.get("log_rotation_size_mb", 100), 100),
                backup_count=self._positive_int(filesizes.get("log_backup_count", 5), 5),
                formatter=formatter,
                config=config,
            )
            self._loggers[key] = runtime_logger
            return runtime_logger

    def _monitor_log_path(self, scope: str) -> Path:
        return self._monitor_log_base() / self._safe_scope(scope) / "monitor.log"

    def _monitor_log_base(self) -> Path:
        config = self._config.get()
        return self._resolve_path(config.get("paths", {}).get("log_base_dir", "logs"))

    def _legacy_site_log_dirs(self, site: SiteIdentity) -> tuple[Path, ...]:
        base = self._monitor_log_base()
        candidates = [base / self._safe_scope(site.site_name)]
        raw_name = str(site.site_name).strip()
        if raw_name not in {"", ".", ".."} and "/" not in raw_name and "\\" not in raw_name:
            candidates.append(base / raw_name)

        directories: list[Path] = []
        seen: set[str] = set()
        for directory in candidates:
            key = str(directory).casefold()
            if key not in seen:
                seen.add(key)
                directories.append(directory)
        return tuple(directories)

    def _migrate_legacy_site_logs(self, site: SiteIdentity) -> None:
        primary_dir = self.get_site_log_path(site).parent
        primary_key = str(primary_dir).casefold()
        for legacy_dir in self._legacy_site_log_dirs(site):
            if str(legacy_dir).casefold() == primary_key or not legacy_dir.is_dir():
                continue
            primary_dir.mkdir(parents=True, exist_ok=True)
            for source in sorted(legacy_dir.glob("monitor.log*")):
                if not source.is_file():
                    continue
                target = primary_dir / source.name
                if target.exists():
                    target = self._next_legacy_archive(target, site.site_name)
                try:
                    source.replace(target)
                except OSError:
                    logger.warning(
                        "Could not migrate legacy site log %s to %s",
                        source,
                        target,
                        exc_info=True,
                    )
            try:
                legacy_dir.rmdir()
            except OSError:
                pass

    @classmethod
    def _next_legacy_archive(cls, target: Path, site_name: str) -> Path:
        suffix = f"legacy-{cls._safe_scope(site_name)}"
        candidate = target.with_name(f"{target.name}.{suffix}")
        index = 2
        while candidate.exists():
            candidate = target.with_name(f"{target.name}.{suffix}-{index}")
            index += 1
        return candidate

    @staticmethod
    def _history_sort_key(path: Path) -> tuple[int, str]:
        try:
            modified = path.stat().st_mtime_ns
        except OSError:
            modified = 0
        return modified, path.name

    @staticmethod
    def _safe_scope(value: str) -> str:
        safe_value = re.sub(r"[^A-Za-z0-9_.-]+", "_", str(value)).strip("._")
        return safe_value or "Anteumbra"

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
