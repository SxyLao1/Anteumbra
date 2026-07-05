#!/usr/bin/env python3
"""
Anteumbra v1.0 CLI — unified command-line interface.

Usage:
  anteumbra install [PATH]   Set up a deployment instance
  anteumbra run              Start all subsystems (foreground)
  anteumbra start            Start in background (daemon)
  anteumbra stop             Stop via PID file
  anteumbra status           Check if running
  anteumbra config           Interactive config wizard
  anteumbra --version        Show version
"""
import json
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
    """Walk up from cwd / install registry to find project root.

    Priority:
    1. ANTEUMBRA_HOME environment variable
    2. Global install registry (~/.anteumbra/installs.json)
    3. CWD upward walk (config.toml / pyproject.toml / PID file)
    """
    # 1. 环境变量
    env_home = os.environ.get("ANTEUMBRA_HOME")
    if env_home:
        p = Path(env_home).resolve()
        if p.exists():
            return p

    # 2. 全局安装注册表
    try:
        from anteumbra.cli.install_registry import get_install_info
        info = get_install_info()
        if info:
            p = Path(info["install_path"])
            if p.exists():
                return p
    except Exception:
        pass

    # 3. CWD 向上遍历
    d = Path.cwd().resolve()
    for _ in range(6):
        if ((d / "config.toml").exists()
            or (d / "pyproject.toml").exists()
            or (d / "data" / "anteumbra.pid").exists()):
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

    # v1.0.10: 使用包内 launcher 启动全部子系统（不再依赖 run.py）
    from anteumbra.application.launcher import start_all
    start_all(host=host, port=port)


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
    import anteumbra as _anteumbra_pkg

    root = _find_project_root()
    template = root / "config.toml"
    target = Path(output) if output else root / "config.toml"

    if not template.exists():
        # v1.0.9: 从包所在源码树查找（dev install）
        pkg_dir = Path(_anteumbra_pkg.__file__).parent
        pkg_template = pkg_dir.parent.parent / "config.toml"
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

    # v1.0.9: 同时生成 .env 文件（含随机管理员密码）
    env_file = target.parent / ".env"
    if not env_file.exists() or click.confirm(f"{env_file} already exists. Overwrite?"):
        import secrets as _sec
        import string as _str
        from werkzeug.security import generate_password_hash
        pwd = ''.join(_sec.choice(_str.ascii_letters + _str.digits) for _ in range(12))
        h = generate_password_hash(pwd)
        env_file.write_text(
            f"# Anteumbra admin password hash\n"
            f"# Regenerate: python -c \"from werkzeug.security import generate_password_hash; print(generate_password_hash('your_password'))\"\n"
            f"ANTEUMBRA_PASSWORD_HASH={h}\n",
            encoding="utf-8"
        )
        click.echo(f".env written to {env_file}")
        click.echo(f"  Admin username: admin")
        click.echo(f"  Admin password: {pwd}")
        click.echo(f"  (change via Settings → Config Editor in the web dashboard)")

    # v1.0.9: 同时复制 YARA 规则目录
    rules_src = None
    for candidate in [
        template.parent / "rules",                    # 与 config.toml 同目录
        Path(_anteumbra_pkg.__file__).parent / "rules",  # v1.0.9: 包内置规则
    ]:
        if candidate.is_dir():
            rules_src = candidate
            break

    rules_dst = target.parent / "rules"
    if rules_src and not rules_dst.exists():
        shutil.copytree(rules_src, rules_dst)
        click.echo(f"YARA rules copied to {rules_dst}")
    elif rules_src and rules_dst.exists():
        click.echo(f"YARA rules already exist at {rules_dst} (skipped)")
    elif not rules_src:
        click.echo("Warning: YARA rules source not found — rules will be unavailable until added")
        click.echo("  You can manually copy rules/ from the Anteumbra repository")

    click.echo("Edit config.toml to configure websites, WAF, notifications, etc.")


# ── Install ────────────────────────────────────────

@cli.command()
@click.argument("path", required=False)
@click.option("--force", is_flag=True, help="Force reinstall even if already installed")
def install(path, force):
    """Set up an Anteumbra deployment instance.

    Copies config template, YARA rules, generates admin password,
    and registers this as the single machine-wide installation.

    PATH defaults to the current working directory.
    """
    import shutil
    import secrets as _sec
    import string as _str
    import anteumbra as _anteumbra_pkg
    from datetime import datetime
    from anteumbra.cli.install_registry import get_install_info, register_install

    target = Path(path).resolve() if path else Path.cwd().resolve()

    # ── 检查已有安装 ──────────────────────────────
    existing = get_install_info()
    if existing:
        existing_path = Path(existing["install_path"])
        if existing_path == target:
            if not force:
                click.echo(f"Anteumbra is already installed at this location:")
                click.echo(f"  {existing_path}")
                click.echo(f"  Version: {existing.get('version', 'unknown')}")
                click.echo(f"  Installed: {existing.get('installed_at', 'unknown')}")
                click.echo(f"\nUse --force to reinstall.")
                raise SystemExit(1)
            else:
                click.echo(f"Reinstalling at {target} (--force)...")
        else:
            if not force:
                click.echo(f"Anteumbra is already installed on this machine:")
                click.echo(f"  {existing_path}")
                click.echo(f"  Version: {existing.get('version', 'unknown')}")
                click.echo(f"  Installed: {existing.get('installed_at', 'unknown')}")
                click.echo(f"\nOnly one instance per machine is supported.")
                click.echo(f"To move the installation, reinstall with --force at the new path.")
                click.echo(f"To reinstall at the existing path, run: anteumbra install --force")
                raise SystemExit(1)
            else:
                click.echo(f"Moving installation from {existing_path} to {target}...")

    # ── 确认目标目录 ──────────────────────────────
    if target.exists() and not (target / ".anteumbra_install").exists():
        # 目录存在但不是 Anteumbra 安装目录
        existing_files = list(target.iterdir())
        if existing_files and not force:
            click.echo(f"Target directory {target} already exists and is not empty.")
            click.echo(f"It does not appear to be an Anteumbra installation.")
            if not click.confirm("Continue anyway?"):
                click.echo("Aborted.")
                return

    target.mkdir(parents=True, exist_ok=True)

    # ── 创建子目录 ────────────────────────────────
    for sub in ["data", "data/sessions", "data/quarantine", "data/threat_intel",
                "data/siem", "logs", "rules"]:
        (target / sub).mkdir(parents=True, exist_ok=True)

    # ── 提取 config.toml 模板 ─────────────────────
    config_dst = target / "config.toml"
    config_src = None
    pkg_dir = Path(_anteumbra_pkg.__file__).parent

    # 查找 config.toml 模板：源码树 → 包内
    for candidate in [
        pkg_dir.parent.parent / "config.toml",       # dev: src/anteumbra/ → project/
        pkg_dir / "config.toml",                      # pip: 包内
    ]:
        if candidate.exists():
            config_src = candidate
            break

    if config_src and config_src != config_dst:
        shutil.copy(config_src, config_dst)
        click.echo(f"Config template → {config_dst}")
    elif not config_dst.exists():
        click.echo("Warning: config.toml template not found in package — please create one manually")
        click.echo("  See: https://github.com/SxyLao1/Anteumbra/blob/main/config.toml")

    # ── 复制 YARA 规则 ────────────────────────────
    rules_src = pkg_dir / "rules"
    rules_dst = target / "rules"
    if rules_src.exists() and rules_src.is_dir():
        # 只复制 webshell 子目录（不复制整个 rules/ 包裹层）
        webshell_src = rules_src / "webshell"
        webshell_dst = rules_dst / "webshell"
        if webshell_src.exists() and not webshell_dst.exists():
            shutil.copytree(webshell_src, webshell_dst)
            yar_count = len(list(webshell_dst.glob("*.yar")))
            click.echo(f"YARA rules → {webshell_dst} ({yar_count} files)")
        elif webshell_dst.exists():
            click.echo(f"YARA rules already exist at {webshell_dst} (skipped)")
    else:
        click.echo("Warning: YARA rules not found in package")

    # ── 生成 .env ─────────────────────────────────
    env_file = target / ".env"
    if not env_file.exists() or force:
        from werkzeug.security import generate_password_hash
        pwd = ''.join(_sec.choice(_str.ascii_letters + _str.digits) for _ in range(12))
        h = generate_password_hash(pwd)
        env_file.write_text(
            f"# Anteumbra auto-generated admin password hash\n"
            f"# Regenerate: python -c \"from werkzeug.security import generate_password_hash; print(generate_password_hash('your_password'))\"\n"
            f"ANTEUMBRA_PASSWORD_HASH={h}\n",
            encoding="utf-8"
        )
        click.echo(f".env written to {env_file}")
    else:
        click.echo(f".env already exists at {env_file} (skipped)")
        pwd = None

    # ── 写安装锁 ──────────────────────────────────
    lock_file = target / ".anteumbra_install"
    lock_data = {
        "version": __version__,
        "installed_at": datetime.now().isoformat(),
        "install_path": str(target),
        "python": sys.executable,
    }
    lock_file.write_text(
        f"# Anteumbra installation marker — do not delete manually\n"
        f"# {json.dumps(lock_data)}\n",
        encoding="utf-8"
    )

    # ── 注册全局安装 ──────────────────────────────
    register_install(str(target), __version__)

    # ── 完成 ──────────────────────────────────────
    click.echo(f"\n{'='*60}")
    click.echo(f"  Anteumbra v{__version__} installed successfully!")
    click.echo(f"  Location: {target}")
    click.echo(f"  Admin:    http://127.0.0.1:8080/admin")
    click.echo(f"  Username: admin")
    if pwd:
        click.echo(f"  Password: {pwd}")
    else:
        click.echo(f"  Password: (see {env_file})")
    click.echo(f"\n  Start:    cd {target} && anteumbra run")
    click.echo(f"  Status:   anteumbra status")
    click.echo(f"  Config:   edit {target / 'config.toml'}")
    click.echo(f"{'='*60}\n")


if __name__ == "__main__":
    cli()
