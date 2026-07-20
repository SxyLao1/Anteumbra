"""Persist and verify ownership of one Anteumbra runtime process."""

from __future__ import annotations

import json
import math
import os
import sys
from dataclasses import dataclass
from enum import Enum
from pathlib import Path


@dataclass(frozen=True, slots=True)
class ProcessIdentity:
    """Stable identity recorded by a running Anteumbra process."""

    pid: int
    process_create_time: float | None = None
    runtime_root: str | None = None
    process_start_token: str | None = None

    @property
    def is_legacy(self) -> bool:
        """Return whether this came from the old integer-only PID format."""
        return self.process_create_time is None and self.process_start_token is None


class ProcessIdentityState(str, Enum):
    """Result of comparing a PID record with the current OS process table."""

    RUNNING = "running"
    STOPPED = "stopped"
    MISMATCH = "mismatch"
    UNKNOWN = "unknown"


def _normalize_root(value: str | Path) -> str:
    return os.path.normcase(os.path.abspath(os.path.expanduser(str(value))))


def _valid_pid(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        pid = int(value)
    except (TypeError, ValueError):
        return None
    return pid if pid > 0 else None


def read_process_identity(path: str | Path) -> ProcessIdentity | None:
    """Read JSON identity metadata or a legacy integer-only PID file."""
    identity_path = Path(path)
    try:
        raw = identity_path.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    if not raw:
        return None

    legacy_pid = _valid_pid(raw)
    if legacy_pid is not None:
        return ProcessIdentity(pid=legacy_pid)

    try:
        payload = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return None
    if not isinstance(payload, dict):
        return None

    pid = _valid_pid(payload.get("pid"))
    if pid is None:
        return None

    process_start_token = payload.get("process_start_token")
    if process_start_token is not None:
        if not isinstance(process_start_token, str) or not process_start_token.strip():
            return None
        process_start_token = process_start_token.strip()

    process_create_time = payload.get("process_create_time")
    if process_create_time is not None:
        try:
            process_create_time = float(process_create_time)
        except (TypeError, ValueError):
            return None
        if not math.isfinite(process_create_time) or process_create_time <= 0:
            return None
    if process_start_token is None and process_create_time is None:
        return None

    runtime_root = payload.get("runtime_root")
    if not isinstance(runtime_root, str) or not runtime_root.strip():
        return None

    return ProcessIdentity(
        pid=pid,
        process_create_time=process_create_time,
        runtime_root=_normalize_root(runtime_root),
        process_start_token=process_start_token,
    )


def _capture_process_start_token(process, create_time: float | None = None) -> str:
    if sys.platform.startswith("linux"):
        stat_path = Path(f"/proc/{process.pid}/stat")
        raw = stat_path.read_text(encoding="utf-8", errors="replace")
        command_end = raw.rfind(")")
        fields_after_command = raw[command_end + 1 :].split()
        if command_end < 0 or len(fields_after_command) <= 19:
            raise OSError(f"invalid Linux process stat record for PID {process.pid}")
        return f"linux:{fields_after_command[19]}"

    stable_create_time = process.create_time() if create_time is None else create_time
    return f"{sys.platform}:{stable_create_time:.6f}"


def capture_process_identity(runtime_root: str | Path) -> ProcessIdentity:
    """Capture the current process with a PID-reuse-resistant timestamp."""
    import psutil

    process = psutil.Process(os.getpid())
    process_create_time = process.create_time()
    return ProcessIdentity(
        pid=process.pid,
        process_create_time=process_create_time,
        runtime_root=_normalize_root(runtime_root),
        process_start_token=_capture_process_start_token(
            process,
            process_create_time,
        ),
    )


def write_process_identity(
    path: str | Path,
    runtime_root: str | Path,
) -> ProcessIdentity:
    """Atomically write the current process identity and return it."""
    identity_path = Path(path)
    identity_path.parent.mkdir(parents=True, exist_ok=True)
    identity = capture_process_identity(runtime_root)
    payload = {
        "schema": 2,
        "pid": identity.pid,
        "process_create_time": identity.process_create_time,
        "process_start_token": identity.process_start_token,
        "runtime_root": identity.runtime_root,
    }
    temp_path = identity_path.with_name(
        f".{identity_path.name}.{identity.pid}.tmp"
    )
    try:
        temp_path.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        temp_path.replace(identity_path)
    finally:
        temp_path.unlink(missing_ok=True)
    return identity


def _is_anteumbra_run_command(command: list[str]) -> bool:
    normalized = [str(item).strip().casefold() for item in command]
    if any(
        normalized[index : index + 3] == ["-m", "anteumbra", "run"]
        for index in range(max(0, len(normalized) - 2))
    ):
        return True

    for index in range(max(0, len(normalized) - 1)):
        executable_name = normalized[index].replace("\\", "/").rsplit("/", 1)[-1]
        if executable_name in {
            "anteumbra",
            "anteumbra.exe",
            "anteumbra-script.py",
        } and normalized[index + 1] == "run":
            return True
    return False


def probe_process_identity(
    identity: ProcessIdentity,
    runtime_root: str | Path,
) -> ProcessIdentityState:
    """Safely decide whether an OS process still owns this runtime record."""
    expected_root = _normalize_root(runtime_root)
    if identity.runtime_root and identity.runtime_root != expected_root:
        return ProcessIdentityState.MISMATCH

    try:
        import psutil
    except ImportError:
        return ProcessIdentityState.UNKNOWN

    try:
        process = psutil.Process(identity.pid)
        if not process.is_running():
            return ProcessIdentityState.STOPPED
        try:
            if process.status() == psutil.STATUS_ZOMBIE:
                return ProcessIdentityState.STOPPED
        except psutil.AccessDenied:
            pass

        if identity.process_start_token is not None:
            current_start_token = _capture_process_start_token(process)
            if current_start_token != identity.process_start_token:
                return ProcessIdentityState.MISMATCH
            return ProcessIdentityState.RUNNING

        if identity.process_create_time is not None:
            current_create_time = process.create_time()
            if not math.isclose(
                current_create_time,
                identity.process_create_time,
                rel_tol=0.0,
                abs_tol=0.01,
            ):
                return ProcessIdentityState.UNKNOWN
            return ProcessIdentityState.RUNNING

        command = process.cmdline()
        process_root = _normalize_root(process.cwd())
        if not _is_anteumbra_run_command(command) or process_root != expected_root:
            return ProcessIdentityState.MISMATCH
        return ProcessIdentityState.RUNNING
    except psutil.NoSuchProcess:
        return ProcessIdentityState.STOPPED
    except (psutil.AccessDenied, OSError):
        return ProcessIdentityState.UNKNOWN


def remove_process_identity(
    path: str | Path,
    expected: ProcessIdentity,
) -> bool:
    """Remove a PID record only when another process has not replaced it."""
    identity_path = Path(path)
    current = read_process_identity(identity_path)
    if current != expected:
        return False
    try:
        identity_path.unlink()
    except FileNotFoundError:
        return False
    return True
