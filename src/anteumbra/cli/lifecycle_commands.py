"""Click commands that control the Anteumbra process lifecycle."""

from __future__ import annotations

import logging
import signal
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType

import click

from anteumbra.infrastructure.process_identity import (
    ProcessIdentity,
    ProcessIdentityState,
    remove_process_identity,
)


@dataclass(frozen=True)
class LifecycleCommandDependencies:
    """Runtime capabilities kept injectable for CLI tests and platform behavior."""

    version: str
    find_project_root: Callable[[], Path]
    pid_path: Callable[[Path | None], Path]
    read_runtime_identity: Callable[[Path | None], ProcessIdentity | None]
    process_state: Callable[[ProcessIdentity, Path | None], ProcessIdentityState]
    service_ready: Callable[[str, int, float], bool]
    wait_for_process_exit: Callable[..., bool]
    get_python: Callable[[], str]
    resolve_bind_options: Callable[[Path, str | None, int | None], tuple[str, int]]
    os_module: ModuleType
    subprocess_module: ModuleType
    sys_module: ModuleType
    time_module: ModuleType


def register_lifecycle_commands(
    root: click.Group,
    dependencies: LifecycleCommandDependencies,
) -> dict[str, click.Command]:
    """Register process lifecycle commands on ``root``."""
    deps = dependencies

    @root.command()
    @click.option("--host", default=None, help="Bind address (default: config web_admin.host)")
    @click.option("--port", default=None, type=int, help="Bind port (default: config web_admin.port)")
    @click.option("--debug/--no-debug", default=False, help="Enable debug mode")
    def run(host, port, debug):
        """Start all Anteumbra subsystems in the foreground.

        This launches the web server, file monitor, WAF poller,
        profile engine, and all background workers in one process.
        Use Ctrl+C to stop.
        """
        instance_root = deps.find_project_root()
        host, port = deps.resolve_bind_options(instance_root, host, port)
        deps.os_module.chdir(str(instance_root))
        deps.sys_module.path.insert(0, str(instance_root))

        click.echo(f"Anteumbra v{deps.version} starting...")
        click.echo(f"  Root:    {instance_root}")
        click.echo(f"  Address: {host}:{port}")
        click.echo(f"  PID:     {deps.os_module.getpid()}")

        from anteumbra.application.launcher import RuntimeLifecycle, RuntimeStartupError

        try:
            RuntimeLifecycle(host=host, port=port).run()
        except RuntimeStartupError as exc:
            raise click.ClickException(str(exc)) from exc

    @root.command()
    @click.option("--host", default=None, help="Bind address (default: config web_admin.host)")
    @click.option("--port", default=None, type=int, help="Bind port (default: config web_admin.port)")
    def start(host, port):
        """Start Anteumbra as a background process.

        On Windows this uses pythonw.exe (no console window).
        On Linux/macOS this forks to the background.
        """
        instance_root = deps.find_project_root()
        host, port = deps.resolve_bind_options(instance_root, host, port)
        identity_path = deps.pid_path(instance_root)
        identity = deps.read_runtime_identity(instance_root)

        if identity is None and identity_path.exists():
            raise click.ClickException(
                f"Cannot verify the invalid PID identity file at {identity_path}. "
                "Confirm no Anteumbra process is running before removing it."
            )
        if identity:
            state = deps.process_state(identity, instance_root)
            if state is ProcessIdentityState.RUNNING:
                click.echo(
                    f"Anteumbra is already running (PID {identity.pid}). "
                    "Use 'anteumbra stop' first."
                )
                raise SystemExit(1)
            if state is ProcessIdentityState.UNKNOWN:
                raise click.ClickException(
                    f"Cannot verify ownership of PID {identity.pid}; refusing to start "
                    "a second instance. Retry with permission to inspect the process."
                )
            remove_process_identity(identity_path, identity)
            click.echo(f"Removed stale PID identity for process {identity.pid}.")

        log_file = instance_root / "data" / "anteumbra.log"
        log_file.parent.mkdir(parents=True, exist_ok=True)
        command = [
            str(deps.get_python()),
            "-u",
            "-m",
            "anteumbra",
            "run",
            "--host",
            host,
            "--port",
            str(port),
        ]

        popen_kwargs = {
            "cwd": str(instance_root),
            "stderr": deps.subprocess_module.STDOUT,
            # Startup failures must remain visible even when stdout is redirected.
            "env": {
                **deps.os_module.environ,
                "PYTHONIOENCODING": "utf-8",
                "PYTHONUNBUFFERED": "1",
            },
        }
        if deps.sys_module.platform == "win32":
            pythonw = Path(deps.sys_module.exec_prefix) / "pythonw.exe"
            if not pythonw.exists():
                pythonw = Path(deps.sys_module.executable)
            command[0] = str(pythonw)
            popen_kwargs["creationflags"] = (
                deps.subprocess_module.CREATE_NO_WINDOW
                if hasattr(deps.subprocess_module, "CREATE_NO_WINDOW")
                else 0
            )
        else:
            popen_kwargs["start_new_session"] = True

        with log_file.open("a", encoding="utf-8", buffering=1) as log_stream:
            popen_kwargs["stdout"] = log_stream
            process = deps.subprocess_module.Popen(command, **popen_kwargs)

        # A PID file or bound socket is not readiness. Require two health
        # responses so startup work after the server bind is also covered.
        ready_checks = 0
        for _ in range(60):
            deps.time_module.sleep(0.25)
            poll = getattr(process, "poll", None)
            if callable(poll) and poll() is not None:
                click.echo(f"Anteumbra failed to start. Check {log_file}", err=True)
                raise SystemExit(1)
            identity = deps.read_runtime_identity(instance_root)
            if identity and deps.service_ready(host, port):
                ready_checks += 1
                if ready_checks < 2:
                    continue
                click.echo(f"Anteumbra started (PID {identity.pid}).")
                click.echo(f"  Admin: http://{host}:{port}/admin")
                click.echo(f"  Log:   {log_file}")
                return
            ready_checks = 0

        click.echo(
            f"Anteumbra did not become ready within 15 seconds. Check {log_file}",
            err=True,
        )
        raise SystemExit(1)

    @root.command()
    def stop():
        """Stop a running Anteumbra instance via its PID file."""
        instance_root = deps.find_project_root()
        identity_path = deps.pid_path(instance_root)
        identity = deps.read_runtime_identity(instance_root)

        if identity is None and not identity_path.exists():
            click.echo("No PID file found. Anteumbra may not be running.")
            raise SystemExit(1)
        if identity is None:
            raise click.ClickException(
                f"Cannot verify the invalid PID identity file at {identity_path}; "
                "refusing to terminate any process."
            )

        state = deps.process_state(identity, instance_root)
        if state in {ProcessIdentityState.STOPPED, ProcessIdentityState.MISMATCH}:
            click.echo(
                f"PID {identity.pid} no longer owns this runtime. "
                "Removing stale PID identity."
            )
            remove_process_identity(identity_path, identity)
            return
        if state is ProcessIdentityState.UNKNOWN:
            raise click.ClickException(
                f"Cannot verify ownership of PID {identity.pid}; refusing to terminate it. "
                "Retry with permission to inspect the process."
            )

        pid = identity.pid
        click.echo(f"Stopping Anteumbra (PID {pid})...")
        try:
            if deps.sys_module.platform == "win32":
                result = deps.subprocess_module.run(
                    ["taskkill", "/PID", str(pid), "/F"],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                if (
                    result.returncode != 0
                    and deps.process_state(identity, instance_root)
                    in {ProcessIdentityState.RUNNING, ProcessIdentityState.UNKNOWN}
                ):
                    detail = (result.stderr or result.stdout or "unknown error").strip()
                    raise RuntimeError(
                        f"taskkill failed ({result.returncode}): {detail}"
                    )
                stopped = deps.wait_for_process_exit(identity, instance_root)
            else:
                deps.os_module.kill(pid, signal.SIGTERM)
                stopped = deps.wait_for_process_exit(identity, instance_root)
                if not stopped:
                    deps.os_module.kill(pid, signal.SIGKILL)
                    stopped = deps.wait_for_process_exit(identity, instance_root)
            if not stopped:
                raise RuntimeError(f"process {pid} is still running after termination")
        except Exception as exc:
            click.echo(f"Error stopping process: {exc}", err=True)
            raise SystemExit(1) from exc

        remove_process_identity(identity_path, identity)
        click.echo("Anteumbra stopped.")

    @root.command()
    def status():
        """Check if Anteumbra is running."""
        instance_root = deps.find_project_root()
        identity_path = deps.pid_path(instance_root)
        identity = deps.read_runtime_identity(instance_root)

        if identity is None and not identity_path.exists():
            click.echo("Status: STOPPED (no PID file)")
            return
        if identity is None:
            click.echo(f"Status: UNKNOWN (invalid PID identity file at {identity_path})")
            return

        state = deps.process_state(identity, instance_root)
        pid = identity.pid
        if state is ProcessIdentityState.RUNNING:
            click.echo(f"Status: RUNNING (PID {pid})")
            try:
                import psutil

                process = psutil.Process(pid)
                click.echo(
                    f"  Uptime: {deps.time_module.time() - process.create_time():.0f}s"
                )
                click.echo(
                    f"  Memory: {process.memory_info().rss / 1024 / 1024:.1f} MB"
                )
            except ImportError:
                logging.getLogger(__name__).debug(
                    "psutil not available for uptime/memory stats", exc_info=True
                )
        elif state is ProcessIdentityState.UNKNOWN:
            click.echo(f"Status: UNKNOWN (cannot verify ownership of PID {pid})")
        else:
            click.echo(f"Status: STOPPED (PID {pid} no longer owns this runtime)")
            remove_process_identity(identity_path, identity)

    return {"run": run, "start": start, "stop": stop, "status": status}
