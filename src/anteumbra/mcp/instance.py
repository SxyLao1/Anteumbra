"""Read-only view of one Anteumbra instance, plus the CLI bridge it shares.

Every mutation an MCP tool performs goes through :func:`run_cli`, which invokes
the real Click command in-process - the same code path a human gets from the
shell. Nothing here writes ``config.toml`` by hand: configuration edits use the
``anteumbra config`` commands, and the readers only ever open files.
"""

from __future__ import annotations

import io
import json
import os
import sqlite3
from collections.abc import Mapping, Sequence
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from anteumbra.mcp.redaction import (
    load_env_secrets,
    redact_config,
    redact_secret_values,
)

DEFAULT_DATA_DIR = "data"
DEFAULT_LOG_DIR = "logs"
REGISTRY_FILENAME = "suspicious_registry.json"
QUARANTINE_FILENAME = "quarantine.json"


@dataclass(frozen=True, slots=True)
class CliResult:
    """Captured outcome of one in-process CLI invocation."""

    exit_code: int
    stdout: str
    stderr: str
    command: str = ""

    @property
    def ok(self) -> bool:
        return self.exit_code == 0

    def lines(self) -> list[str]:
        return [line for line in self.stdout.splitlines() if line.strip()]

    def as_dict(self) -> dict[str, Any]:
        return {
            "command": self.command,
            "exit_code": self.exit_code,
            "stdout": self.lines(),
            "stderr": [line for line in self.stderr.splitlines() if line.strip()],
        }


def run_cli(args: Sequence[str], *, home: Path | None = None) -> CliResult:
    """Run an ``anteumbra`` Click command in-process and capture its output.

    Using the real command object is deliberate: the MCP surface must not have a
    second implementation of "set a config value" that can drift from the CLI.
    """
    from click.exceptions import ClickException

    from anteumbra.cli.main import cli as cli_group

    argv = [*(("--home", str(home)) if home is not None else ()), *args]
    stdout = io.StringIO()
    stderr = io.StringIO()
    previous_home = os.environ.get("ANTEUMBRA_HOME")
    exit_code = 0
    try:
        with redirect_stdout(stdout), redirect_stderr(stderr):
            try:
                cli_group.main(
                    args=argv,
                    prog_name="anteumbra",
                    standalone_mode=False,
                )
            except SystemExit as exc:
                exit_code = exc.code if isinstance(exc.code, int) else 1
            except ClickException as exc:
                stderr.write(f"Error: {exc.format_message()}\n")
                exit_code = exc.exit_code
            except Exception as exc:  # noqa: BLE001 - a tool must report, not crash
                stderr.write(f"Error: {type(exc).__name__}: {exc}\n")
                exit_code = 1
    finally:
        if previous_home is None:
            os.environ.pop("ANTEUMBRA_HOME", None)
        else:
            os.environ["ANTEUMBRA_HOME"] = previous_home
    return CliResult(
        exit_code=exit_code,
        stdout=stdout.getvalue(),
        stderr=stderr.getvalue(),
        command="anteumbra " + " ".join(argv),
    )


@dataclass
class Instance:
    """One runtime instance directory, read through the production loaders."""

    root: Path
    allow_write: bool = False
    _env_secrets: tuple[str, ...] | None = field(default=None, repr=False)

    # ── paths ────────────────────────────────────────────────────────
    @property
    def config_path(self) -> Path:
        return self.root / "config.toml"

    @property
    def env_path(self) -> Path:
        return self.root / ".env"

    @property
    def pid_path(self) -> Path:
        return self.root / "data" / "anteumbra.pid"

    @property
    def has_config(self) -> bool:
        return self.config_path.is_file()

    def data_dir(self, config: Mapping[str, Any] | None = None) -> Path:
        return self._resolve_path(_paths_setting(config, "data_dir", DEFAULT_DATA_DIR))

    def log_dir(self, config: Mapping[str, Any] | None = None) -> Path:
        return self._resolve_path(_paths_setting(config, "log_base_dir", DEFAULT_LOG_DIR))

    def _resolve_path(self, value: object) -> Path:
        path = Path(str(value))
        return path if path.is_absolute() else (self.root / path)

    # ── configuration ────────────────────────────────────────────────
    def load_config(self) -> tuple[dict[str, Any], str | None]:
        """Load the effective configuration, or explain why it cannot be read."""
        if not self.has_config:
            return {}, (
                f"No config.toml at {self.config_path}. Create the runtime first with "
                f'`anteumbra install "{self.root}"`.'
            )
        from anteumbra.infrastructure.config.loader import load_toml_config

        try:
            return dict(load_toml_config(str(self.config_path))), None
        except Exception as exc:  # noqa: BLE001 - reported, never raised outward
            return {}, f"Failed to load {self.config_path}: {type(exc).__name__}: {exc}"

    def config_provider(self):
        """Return the production config provider for this instance, or ``None``."""
        if not self.has_config:
            return None
        from anteumbra.infrastructure.config.provider import TomlConfigProvider

        try:
            return TomlConfigProvider(self.config_path)
        except Exception:  # noqa: BLE001 - invalid config is reported by validate_config
            return None

    def websites(self, config: Mapping[str, Any] | None = None) -> list[Any]:
        """Return every configured site, enabled or not."""
        provider = self.config_provider()
        if provider is not None:
            try:
                return list(provider.get_websites())
            except Exception:  # noqa: BLE001
                return []
        return []

    def resolve_site_identity(self, file_path: str) -> tuple[str, str]:
        """Resolve a stored path to ``(site_id, site_name)`` without touching disk."""
        provider = self.config_provider()
        if provider is None:
            return "", ""
        try:
            identity = provider.resolve_site_identity(file_path)
        except Exception:  # noqa: BLE001
            return "", ""
        return identity.site_id, identity.site_name

    # ── secrets ──────────────────────────────────────────────────────
    def env_secrets(self) -> tuple[str, ...]:
        if self._env_secrets is None:
            self._env_secrets = load_env_secrets(self.env_path)
        return self._env_secrets

    def forget_secrets(self) -> None:
        """Re-read ``.env`` on the next redaction (after a mutating call)."""
        self._env_secrets = None

    def redact(self, value: Any) -> Any:
        """Apply both redaction mechanisms to one response object."""
        return redact_secret_values(value, self.env_secrets())

    def redacted_config(self, config: Mapping[str, Any] | None = None) -> dict[str, Any]:
        """Return the effective configuration with credentials removed."""
        source = self.load_config()[0] if config is None else config
        return redact_config(source)

    # ── CLI bridge ───────────────────────────────────────────────────
    def cli(self, *args: str) -> CliResult:
        return run_cli(list(args), home=self.root)

    def validate(self) -> dict[str, Any]:
        """Run the validation path the CLI uses and describe its result."""
        from anteumbra.cli import config_support

        result = self.cli("config", "validate")
        errors, warnings = config_support.validate_config_file(self.config_path)
        return {
            "config_path": str(self.config_path),
            "valid": result.exit_code == 0 and not errors,
            "exit_code": result.exit_code,
            "cli_output": result.lines() + [line for line in result.stderr.splitlines() if line],
            "errors": list(errors),
            "warnings": list(warnings),
        }

    # ── records ──────────────────────────────────────────────────────
    def registry_records(self, config: Mapping[str, Any] | None = None) -> dict[str, Any]:
        """Read detection records, preferring the store the runtime considers authoritative."""
        settings = self.load_config()[0] if config is None else config
        json_path = self.data_dir(settings) / REGISTRY_FILENAME
        sqlite_attempt = self._sqlite_authoritative(settings, json_path)
        if sqlite_attempt:
            records = self._read_sqlite_registry(settings)
            if records is not None:
                return {"records": records, "source": "sqlite", "note": ""}
            note = (
                "SQLite is marked authoritative but could not be opened read-only; "
                "reading the JSON snapshot instead, which may lag the newest detections."
            )
        else:
            note = ""
        records = _read_json_list(json_path)
        if records is None:
            return {
                "records": [],
                "source": "json",
                "note": note or f"No registry data at {json_path}.",
            }
        return {"records": records, "source": "json", "note": note}

    def quarantine_records(self, config: Mapping[str, Any] | None = None) -> dict[str, Any]:
        """Read quarantine metadata without importing the quarantine store."""
        settings = self.load_config()[0] if config is None else config
        path = self.data_dir(settings) / "quarantine" / QUARANTINE_FILENAME
        records = _read_json_list(path)
        if records is None:
            records = _read_json_list(path.with_name(f"{path.name}.bak"))
        if records is None:
            return {"records": [], "source": "json", "note": f"No quarantine data at {path}."}
        return {"records": records, "source": "json", "note": ""}

    # ── internals ────────────────────────────────────────────────────
    def _sqlite_authoritative(self, settings: Mapping[str, Any], json_path: Path) -> bool:
        storage = settings.get("storage", {})
        if not isinstance(storage, Mapping):
            return False
        backend = str(storage.get("backend", "json")).strip().lower()
        if backend not in {"sqlite", "both"}:
            return False
        return json_path.with_name(f"{json_path.name}.sqlite-authority").is_file()

    def _database_path(self, settings: Mapping[str, Any]) -> Path:
        storage = settings.get("storage", {})
        raw = DEFAULT_DATA_DIR + "/anteumbra.db"
        if isinstance(storage, Mapping):
            raw = storage.get("db_path") or storage.get("sqlite_path") or raw
        return self._resolve_path(raw)

    def _read_sqlite_registry(self, settings: Mapping[str, Any]) -> list[dict[str, Any]] | None:
        """Read ``registry`` rows through a strictly read-only connection.

        A WAL database refuses read-only access when the shared-memory index is
        unavailable, so failure is reported instead of escalated to a writable
        connection: this surface must never be the process that opens the
        runtime's database for writing.
        """
        database = self._database_path(settings)
        if not database.is_file():
            return None
        from anteumbra.infrastructure.persistence.sqlite_repository import SqliteRepository

        uri = f"file:{database.as_posix()}?mode=ro"
        connection = None
        try:
            connection = sqlite3.connect(uri, uri=True, timeout=2.0)
            connection.row_factory = sqlite3.Row
            rows = connection.execute("SELECT * FROM registry").fetchall()
        except (sqlite3.Error, OSError, ValueError):
            return None
        finally:
            if connection is not None:
                connection.close()
        return [SqliteRepository._row_to_data(row) for row in rows]


def _read_json_list(path: Path) -> list[dict[str, Any]] | None:
    """Read a JSON array (or a ``{path: record}`` map) and return its records."""
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        records: list[dict[str, Any]] = []
        for key, value in payload.items():
            if isinstance(value, dict):
                records.append({"file_path": key, **value})
        return records
    return None


def _paths_setting(config: Mapping[str, Any] | None, key: str, default: str) -> str:
    if not isinstance(config, Mapping):
        return default
    paths = config.get("paths", {})
    if not isinstance(paths, Mapping):
        return default
    return str(paths.get(key) or default)


__all__ = [
    "CliResult",
    "Instance",
    "run_cli",
]
