#!/usr/bin/env python3
"""
Anteumbra v1.0 CLI — unified command-line interface.

Usage:
  anteumbra run              Start all subsystems (foreground)
  anteumbra start            Start in background (daemon)
  anteumbra stop             Stop via PID file
  anteumbra status           Check if running
  anteumbra config           Interactive config wizard
  anteumbra --version        Show version
"""
import logging
import os
import sys
import time
import signal
import subprocess
from pathlib import Path

import click

from anteumbra import __version__

PID_FILE = Path("data/anteumbra.pid")


def _find_project_root() -> Path:
    """Walk up from cwd to find package root (contains config.toml or setup.py)."""
    d = Path.cwd().resolve()
    for _ in range(6):
        if (d / "config.toml").exists() or (d / "pyproject.toml").exists():
            return d
        if d.parent == d:
            break
        d = d.parent
    return Path.cwd().resolve()


def _read_pid() -> int | None:
    pf = _find_project_root() / PID_FILE
    if pf.exists():
        try:
            return int(pf.read_text().strip())
        except (ValueError, OSError):
            logging.getLogger(__name__).debug("Failed to read PID file", exc_info=True)
    return None


def _is_running(pid: int) -> bool:
    """Check if a process with the given PID is alive."""
    try:
        import psutil
        return psutil.pid_exists(pid)
    except ImportError:
        try:
            os.kill(pid, 0)
            return True
        except OSError:
            return False


def _get_python() -> str:
    """Returns the path to the Python interpreter used to invoke this CLI."""
    return sys.executable


@click.group(invoke_without_command=True)
@click.version_option(__version__, prog_name="anteumbra")
@click.pass_context
def cli(ctx):
    """Anteumbra — Lightweight Web Perimeter Security Platform."""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())
        # Show quick status
        pid = _read_pid()
        if pid and _is_running(pid):
            click.echo(f"\n  Status: RUNNING (PID {pid})")
        else:
            click.echo(f"\n  Status: STOPPED")


# ── Run (foreground) ─────────────────────────────────

@cli.command()
@click.option("--host", default="127.0.0.1", help="Bind address")
@click.option("--port", default=5000, help="Bind port")
@click.option("--debug/--no-debug", default=False, help="Enable debug mode")
def run(host, port, debug):
    """Start all Anteumbra subsystems in the foreground.

    This launches the web server, file monitor, WAF poller,
    profile engine, and all background workers in one process.
    Use Ctrl+C to stop.
    """
    root = _find_project_root()
    os.chdir(str(root))
    sys.path.insert(0, str(root))

    click.echo(f"Anteumbra v{__version__} starting...")
    click.echo(f"  Root:    {root}")
    click.echo(f"  Address: {host}:{port}")
    click.echo(f"  PID:     {os.getpid()}")

    # Write PID file
    pid_dir = root / "data"
    pid_dir.mkdir(parents=True, exist_ok=True)
    (pid_dir / "anteumbra.pid").write_text(str(os.getpid()))

    try:
        # Delegate to the full application runner
        from run import main as run_main
        run_main()
    except ImportError:
        # Fallback: just start Flask dev server
        from anteumbra.interfaces.web.factory import create_app, run_app
        app = create_app()
        click.echo(f"  Admin: http://{host}:{port}/admin")
        run_app(host=host, port=port)


# ── Start (daemon / background) ─────────────────────────────

@cli.command()
@click.option("--host", default="127.0.0.1", help="Bind address")
@click.option("--port", default=5000, help="Bind port")
def start(host, port):
    """Start Anteumbra as a background process.

    On Windows this uses pythonw.exe (no console window).
    On Linux/macOS this forks to the background.
    """
    root = _find_project_root()
    pid = _read_pid()

    if pid and _is_running(pid):
        click.echo(f"Anteumbra is already running (PID {pid}). Use 'anteumbra stop' first.")
        raise SystemExit(1)

    run_py = root / "run.py"
    if not run_py.exists():
        click.echo("Error: run.py not found in project root.", err=True)
        raise SystemExit(1)

    log_file = root / "data" / "anteumbra.log"
    log_file.parent.mkdir(parents=True, exist_ok=True)

    if sys.platform == "win32":
        # Windows: use pythonw.exe (no console window)
        pythonw = Path(sys.exec_prefix) / "pythonw.exe"
        if not pythonw.exists():
            pythonw = Path(sys.executable)  # fallback
        subprocess.Popen(
            [str(pythonw), str(run_py)],
            cwd=str(root),
            creationflags=subprocess.CREATE_NO_WINDOW
            if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,
        )
    else:
        # Unix: fork + redirect output
        subprocess.Popen(
            [_get_python(), str(run_py)],
            cwd=str(root),
            stdout=open(str(log_file), "a"),
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )

    # Wait briefly for PID file to appear
    for _ in range(20):
        time.sleep(0.25)
        pid = _read_pid()
        if pid:
            click.echo(f"Anteumbra started (PID {pid}).")
            click.echo(f"  Admin: http://{host}:{port}/admin")
            click.echo(f"  Log:   {log_file}")
            return

    click.echo("Anteumbra started (PID file not yet written).")


# ── Stop ────────────────────────────────────────

@cli.command()
def stop():
    """Stop a running Anteumbra instance via its PID file."""
    pid = _read_pid()

    if not pid:
        click.echo("No PID file found. Anteumbra may not be running.")
        raise SystemExit(1)

    if not _is_running(pid):
        click.echo(f"PID {pid} is not alive. Removing stale PID file.")
        (Path.cwd() / PID_FILE).unlink(missing_ok=True)
        return

    click.echo(f"Stopping Anteumbra (PID {pid})...")
    try:
        if sys.platform == "win32":
            subprocess.run(["taskkill", "/PID", str(pid), "/F"],
                         capture_output=True)
        else:
            os.kill(pid, signal.SIGTERM)
            time.sleep(1)
            if _is_running(pid):
                os.kill(pid, signal.SIGKILL)
    except Exception as e:
        click.echo(f"Error stopping process: {e}", err=True)
        raise SystemExit(1) from e

    (Path.cwd() / PID_FILE).unlink(missing_ok=True)
    click.echo("Anteumbra stopped.")


# ── Status ────────────────────────────────────────

@cli.command()
def status():
    """Check if Anteumbra is running."""
    pid = _read_pid()

    if not pid:
        click.echo("Status: STOPPED (no PID file)")
        return

    if _is_running(pid):
        click.echo(f"Status: RUNNING (PID {pid})")
        try:
            import psutil
            proc = psutil.Process(pid)
            click.echo(f"  Uptime: {time.time() - proc.create_time():.0f}s")
            click.echo(f"  Memory: {proc.memory_info().rss / 1024 / 1024:.1f} MB")
        except ImportError:
            logging.getLogger(__name__).debug("psutil not available for uptime/memory stats", exc_info=True)
    else:
        click.echo(f"Status: STOPPED (PID {pid} is dead — removing stale PID)")
        (Path.cwd() / PID_FILE).unlink(missing_ok=True)


# ── Config wizard ─────────────────────────────────

@cli.command()
@click.option("--output", "-o", default=None, help="Output path (default: ./config.toml)")
def config(output):
    """Generate a config.toml from the bundled template."""
    import shutil

    root = _find_project_root()
    template = root / "config.toml"
    target = Path(output) if output else root / "config.toml"

    if not template.exists():
        # Try looking in the package
        pkg_template = Path(__file__).parent.parent.parent.parent / "config.toml"
        if pkg_template.exists():
            template = pkg_template

    if not template.exists():
        click.echo("No config.toml template found. Run this from the Anteumbra project root.", err=True)
        raise SystemExit(1)

    if target.exists():
        if not click.confirm(f"{target} already exists. Overwrite?"):
            click.echo("Aborted.")
            return

    shutil.copy(template, target)
    click.echo(f"Config template written to {target}")
    click.echo("Edit it to configure websites, WAF, notifications, etc.")


if __name__ == "__main__":
    cli()
