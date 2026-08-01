"""PID ownership persistence and reuse-safety regression tests."""

from __future__ import annotations

import builtins
import json
import os
from dataclasses import replace


def test_process_identity_round_trip_and_current_process_probe(tmp_path):
    from anteumbra.infrastructure.process_identity import (
        ProcessIdentityState,
        probe_process_identity,
        read_process_identity,
        write_process_identity,
    )

    identity_path = tmp_path / "data" / "anteumbra.pid"
    identity = write_process_identity(identity_path, tmp_path)

    payload = json.loads(identity_path.read_text(encoding="utf-8"))
    assert payload["schema"] == 2
    assert payload["pid"] == identity.pid
    assert payload["process_create_time"] == identity.process_create_time
    assert payload["process_start_token"] == identity.process_start_token
    assert read_process_identity(identity_path) == identity
    assert probe_process_identity(identity, tmp_path) is ProcessIdentityState.RUNNING


def test_legacy_integer_pid_is_still_readable(tmp_path):
    from anteumbra.infrastructure.process_identity import (
        ProcessIdentity,
        read_process_identity,
    )

    identity_path = tmp_path / "anteumbra.pid"
    identity_path.write_text("12345\n", encoding="utf-8")

    assert read_process_identity(identity_path) == ProcessIdentity(pid=12345)


def test_process_start_token_detects_pid_reuse(tmp_path):
    from anteumbra.infrastructure.process_identity import (
        ProcessIdentityState,
        capture_process_identity,
        probe_process_identity,
    )

    identity = capture_process_identity(tmp_path)
    stale_identity = replace(
        identity,
        process_start_token=f"{identity.process_start_token}:reused",
    )

    assert (
        probe_process_identity(stale_identity, tmp_path)
        is ProcessIdentityState.MISMATCH
    )


def test_schema_one_clock_drift_is_unknown_instead_of_pid_reuse(tmp_path):
    from anteumbra.infrastructure.process_identity import (
        ProcessIdentityState,
        capture_process_identity,
        probe_process_identity,
    )

    current = capture_process_identity(tmp_path)
    schema_one_identity = replace(
        current,
        process_create_time=current.process_create_time - 2.0,
        process_start_token=None,
    )

    assert (
        probe_process_identity(schema_one_identity, tmp_path)
        is ProcessIdentityState.UNKNOWN
    )

def test_runtime_root_mismatch_rejects_foreign_identity(tmp_path):
    from anteumbra.infrastructure.process_identity import (
        ProcessIdentityState,
        capture_process_identity,
        probe_process_identity,
    )

    identity = capture_process_identity(tmp_path / "first")

    assert (
        probe_process_identity(identity, tmp_path / "second")
        is ProcessIdentityState.MISMATCH
    )


def test_legacy_pid_requires_matching_command_and_working_directory(tmp_path):
    from anteumbra.infrastructure.process_identity import (
        ProcessIdentity,
        ProcessIdentityState,
        probe_process_identity,
    )

    identity = ProcessIdentity(pid=os.getpid())

    assert (
        probe_process_identity(identity, tmp_path)
        is ProcessIdentityState.MISMATCH
    )


def test_legacy_console_script_process_is_recognized(tmp_path, monkeypatch):
    import psutil

    from anteumbra.infrastructure.process_identity import (
        ProcessIdentity,
        ProcessIdentityState,
        probe_process_identity,
    )

    class ConsoleScriptProcess:
        pid = 12345

        @staticmethod
        def is_running():
            return True

        @staticmethod
        def status():
            return psutil.STATUS_RUNNING

        @staticmethod
        def cmdline():
            return ["/usr/bin/python", "/usr/local/bin/anteumbra", "run"]

        @staticmethod
        def cwd():
            return str(tmp_path)

    monkeypatch.setattr(psutil, "Process", lambda _pid: ConsoleScriptProcess())

    assert (
        probe_process_identity(ProcessIdentity(pid=12345), tmp_path)
        is ProcessIdentityState.RUNNING
    )


def test_remove_process_identity_never_unlinks_a_replacement(tmp_path):
    from anteumbra.infrastructure.process_identity import (
        ProcessIdentity,
        read_process_identity,
        remove_process_identity,
        write_process_identity,
    )

    identity_path = tmp_path / "anteumbra.pid"
    original = write_process_identity(identity_path, tmp_path)
    replacement = ProcessIdentity(
        pid=original.pid + 1,
        process_create_time=original.process_create_time,
        runtime_root=original.runtime_root,
        process_start_token=original.process_start_token,
    )
    identity_path.write_text(
        json.dumps(
            {
                "schema": 2,
                "pid": replacement.pid,
                "process_create_time": replacement.process_create_time,
                "process_start_token": replacement.process_start_token,
                "runtime_root": replacement.runtime_root,
            }
        ),
        encoding="utf-8",
    )

    assert remove_process_identity(identity_path, original) is False
    assert read_process_identity(identity_path) == replacement


def test_invalid_process_identity_is_not_treated_as_missing_ownership(tmp_path):
    from anteumbra.infrastructure.process_identity import read_process_identity

    identity_path = tmp_path / "anteumbra.pid"
    identity_path.write_text('{"pid": "invalid"}', encoding="utf-8")

    assert read_process_identity(identity_path) is None
    assert identity_path.exists()


def test_missing_psutil_makes_process_ownership_unknown(tmp_path, monkeypatch):
    from anteumbra.infrastructure.process_identity import (
        ProcessIdentity,
        ProcessIdentityState,
        probe_process_identity,
    )

    original_import = builtins.__import__

    def import_without_psutil(name, *args, **kwargs):
        if name == "psutil":
            raise ImportError("psutil unavailable")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", import_without_psutil)

    assert (
        probe_process_identity(ProcessIdentity(pid=12345), tmp_path)
        is ProcessIdentityState.UNKNOWN
    )
