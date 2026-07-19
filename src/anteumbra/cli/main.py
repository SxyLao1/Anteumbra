#!/usr/bin/env python3
"""
Anteumbra v1.0 CLI — unified command-line interface.

Usage:
  anteumbra install [PATH]   Set up a deployment instance
  anteumbra run              Start all subsystems (foreground)
  anteumbra start            Start in background (daemon)
  anteumbra stop             Stop via PID file
  anteumbra status           Check if running
  anteumbra config           Manage configuration files
  anteumbra --version        Show version
"""
import json
import logging
import os
import posixpath
import re
import sys
import time
import signal
import subprocess
from pathlib import Path
from urllib import error as urlerror
from urllib import request as urlrequest

import click

from anteumbra import __version__

PID_FILE = Path("data/anteumbra.pid")
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8080
DEFAULT_SITE_DIR = Path("sites/default")


def _package_dir() -> Path:
    import anteumbra as _anteumbra_pkg

    return Path(_anteumbra_pkg.__file__).parent


def _find_config_template() -> Path | None:
    """Return the bundled config template for both wheel and editable installs."""
    pkg_dir = _package_dir()
    for candidate in [
        pkg_dir / "config.toml",
        pkg_dir.parent.parent / "config.toml",
    ]:
        if candidate.exists():
            return candidate
    return None


def _ensure_default_site_dir(root: Path) -> Path:
    """Create the default monitored website directory inside a deployment root."""
    site_dir = root / DEFAULT_SITE_DIR
    site_dir.mkdir(parents=True, exist_ok=True)
    return site_dir


def _find_project_root() -> Path:
    """Resolve a runtime root without crossing into another installation.

    Priority:
    1. ANTEUMBRA_HOME environment variable
    2. CWD upward walk (config.toml / pyproject.toml / PID file)
    3. Global install registry (~/.anteumbra/installs.json)
    """
    # 1. 环境变量
    env_home = os.environ.get("ANTEUMBRA_HOME")
    if env_home:
        p = Path(env_home).resolve()
        if p.exists():
            return p

    # 2. CWD 向上遍历. A local config always owns its runtime even when a
    # machine-wide PyPI installation is registered elsewhere.
    d = Path.cwd().resolve()
    for _ in range(6):
        if ((d / "config.toml").exists()
            or (d / "pyproject.toml").exists()
            or (d / "data" / "anteumbra.pid").exists()):
            return d
        if d.parent == d:
            break
        d = d.parent

    # 3. Global install registry
    try:
        from anteumbra.infrastructure.config.install_registry import get_install_info
        info = get_install_info()
        if info:
            p = Path(info["install_path"])
            if p.exists():
                return p
    except Exception:
        logging.getLogger(__name__).debug(
            "Failed to discover the registered Anteumbra installation",
            exc_info=True,
        )

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


def _service_ready(host: str, port: int, timeout: float = 0.25) -> bool:
    """Return whether the running service answers its public health endpoint."""
    connect_host = host
    if host in {"0.0.0.0", "::", "[::]"}:
        connect_host = "127.0.0.1"
    if ":" in connect_host and not connect_host.startswith("["):
        connect_host = f"[{connect_host}]"
    health_url = f"http://{connect_host}:{port}/api/v1/health"
    try:
        with urlrequest.urlopen(health_url, timeout=timeout) as response:
            return 200 <= response.status < 300
    except (OSError, ValueError, urlerror.URLError):
        return False


def _wait_for_process_exit(
    pid: int,
    *,
    timeout: float = 5.0,
    interval: float = 0.1,
) -> bool:
    """Wait until a process exits instead of trusting a kill command result."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not _is_running(pid):
            return True
        time.sleep(interval)
    return not _is_running(pid)


def _get_python() -> str:
    """Returns the path to the Python interpreter used to invoke this CLI."""
    return sys.executable


def _resolve_bind_options(root: Path, host: str | None, port: int | None) -> tuple[str, int]:
    """Resolve run/start bind address from CLI options, then config, then defaults."""
    resolved_host = host
    resolved_port = port

    if resolved_host is not None and resolved_port is not None:
        return resolved_host, resolved_port

    config_path = root / "config.toml"
    if config_path.exists():
        try:
            cfg = _load_toml_file(config_path)
            web_admin = cfg.get("web_admin", {})
            if isinstance(web_admin, dict):
                if resolved_host is None:
                    resolved_host = str(web_admin.get("host") or DEFAULT_HOST)
                if resolved_port is None:
                    configured_port = web_admin.get("port", DEFAULT_PORT)
                    resolved_port = int(configured_port)
        except Exception as exc:
            click.echo(
                f"Warning: failed to read {config_path}; using default bind: {exc}",
                err=True,
            )

    return resolved_host or DEFAULT_HOST, resolved_port or DEFAULT_PORT


@click.group(invoke_without_command=True)
@click.version_option(__version__, prog_name="anteumbra")
@click.pass_context
def cli(ctx):
    """Anteumbra - Lightweight Web Perimeter Security Platform."""
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
@click.option("--host", default=None, help="Bind address (default: config web_admin.host)")
@click.option("--port", default=None, type=int, help="Bind port (default: config web_admin.port)")
@click.option("--debug/--no-debug", default=False, help="Enable debug mode")
def run(host, port, debug):
    """Start all Anteumbra subsystems in the foreground.

    This launches the web server, file monitor, WAF poller,
    profile engine, and all background workers in one process.
    Use Ctrl+C to stop.
    """
    root = _find_project_root()
    host, port = _resolve_bind_options(root, host, port)
    os.chdir(str(root))
    sys.path.insert(0, str(root))

    click.echo(f"Anteumbra v{__version__} starting...")
    click.echo(f"  Root:    {root}")
    click.echo(f"  Address: {host}:{port}")
    click.echo(f"  PID:     {os.getpid()}")

    # v1.0.10: 使用包内 launcher 启动全部子系统（不再依赖 run.py）
    from anteumbra.application.launcher import start_all
    start_all(host=host, port=port)


# ── Start (daemon / background) ─────────────────────────────

@cli.command()
@click.option("--host", default=None, help="Bind address (default: config web_admin.host)")
@click.option("--port", default=None, type=int, help="Bind port (default: config web_admin.port)")
def start(host, port):
    """Start Anteumbra as a background process.

    On Windows this uses pythonw.exe (no console window).
    On Linux/macOS this forks to the background.
    """
    root = _find_project_root()
    host, port = _resolve_bind_options(root, host, port)
    pid = _read_pid()

    if pid and _is_running(pid):
        click.echo(f"Anteumbra is already running (PID {pid}). Use 'anteumbra stop' first.")
        raise SystemExit(1)
    if pid:
        stale_pid_file = root / PID_FILE
        stale_pid_file.unlink(missing_ok=True)
        click.echo(f"Removed stale PID file for process {pid}.")

    log_file = root / "data" / "anteumbra.log"
    log_file.parent.mkdir(parents=True, exist_ok=True)
    cmd = [
        str(_get_python()),
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
        "cwd": str(root),
        "stderr": subprocess.STDOUT,
        # Keep startup failures and runtime progress visible in anteumbra.log.
        # Redirected stdout is block-buffered by default on Windows.
        "env": {
            **os.environ,
            "PYTHONIOENCODING": "utf-8",
            "PYTHONUNBUFFERED": "1",
        },
    }
    if sys.platform == "win32":
        pythonw = Path(sys.exec_prefix) / "pythonw.exe"
        if not pythonw.exists():
            pythonw = Path(sys.executable)
        cmd[0] = str(pythonw)
        popen_kwargs["creationflags"] = (
            subprocess.CREATE_NO_WINDOW
            if hasattr(subprocess, "CREATE_NO_WINDOW")
            else 0
        )
    else:
        popen_kwargs["start_new_session"] = True

    with open(log_file, "a", encoding="utf-8", buffering=1) as log_stream:
        popen_kwargs["stdout"] = log_stream
        process = subprocess.Popen(cmd, **popen_kwargs)

    # A PID file or bound socket is not readiness. Wait for a successful HTTP
    # health response so startup work that follows Waitress binding is included.
    ready_checks = 0
    for _ in range(60):
        time.sleep(0.25)
        poll = getattr(process, "poll", None)
        if callable(poll) and poll() is not None:
            click.echo(f"Anteumbra failed to start. Check {log_file}", err=True)
            raise SystemExit(1)
        pid = _read_pid()
        if pid and _service_ready(host, port):
            ready_checks += 1
            if ready_checks < 2:
                continue
            click.echo(f"Anteumbra started (PID {pid}).")
            click.echo(f"  Admin: http://{host}:{port}/admin")
            click.echo(f"  Log:   {log_file}")
            return
        ready_checks = 0

    click.echo(
        f"Anteumbra did not become ready within 15 seconds. Check {log_file}",
        err=True,
    )
    raise SystemExit(1)


# ── Stop ────────────────────────────────────────

@cli.command()
def stop():
    """Stop a running Anteumbra instance via its PID file."""
    root = _find_project_root()
    pid = _read_pid()

    if not pid:
        click.echo("No PID file found. Anteumbra may not be running.")
        raise SystemExit(1)

    if not _is_running(pid):
        click.echo(f"PID {pid} is not alive. Removing stale PID file.")
        (root / PID_FILE).unlink(missing_ok=True)
        return

    click.echo(f"Stopping Anteumbra (PID {pid})...")
    try:
        if sys.platform == "win32":
            result = subprocess.run(
                ["taskkill", "/PID", str(pid), "/F"],
                capture_output=True,
                text=True,
                check=False,
            )
            if result.returncode != 0 and _is_running(pid):
                detail = (result.stderr or result.stdout or "unknown error").strip()
                raise RuntimeError(f"taskkill failed ({result.returncode}): {detail}")
            stopped = _wait_for_process_exit(pid)
        else:
            os.kill(pid, signal.SIGTERM)
            stopped = _wait_for_process_exit(pid)
            if not stopped:
                os.kill(pid, signal.SIGKILL)
                stopped = _wait_for_process_exit(pid)
        if not stopped:
            raise RuntimeError(f"process {pid} is still running after termination")
    except Exception as e:
        click.echo(f"Error stopping process: {e}", err=True)
        raise SystemExit(1) from e

    (root / PID_FILE).unlink(missing_ok=True)
    click.echo("Anteumbra stopped.")


# ── Status ────────────────────────────────────────

@cli.command()
def status():
    """Check if Anteumbra is running."""
    root = _find_project_root()
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
        click.echo(f"Status: STOPPED (PID {pid} is dead; removing stale PID)")
        (root / PID_FILE).unlink(missing_ok=True)


# ── Config management ──────────────────────────────

def _load_toml_file(path: Path) -> dict:
    """Load a TOML file without install-registry fallbacks."""
    if sys.version_info >= (3, 11):
        import tomllib
    else:
        import tomli as tomllib

    with open(path, "rb") as f:
        return tomllib.load(f)


def _write_toml_file(path: Path, data: dict) -> None:
    import tomli_w

    path.write_text(tomli_w.dumps(data), encoding="utf-8")


def _config_target(config_path: str | None = None) -> Path:
    if config_path:
        return Path(config_path).expanduser().resolve()
    return (_find_project_root() / "config.toml").resolve()


def _load_toml_value(value: str):
    if sys.version_info >= (3, 11):
        import tomllib
    else:
        import tomli as tomllib

    return tomllib.loads(f"value = {value}")["value"]


def _parse_config_value(raw: str):
    value = raw.strip()
    lower = value.lower()
    if lower == "true":
        return True
    if lower == "false":
        return False
    if lower in {"none", "null"}:
        return None
    try:
        if "." not in value:
            return int(value)
        return float(value)
    except ValueError:
        pass
    try:
        return _load_toml_value(value)
    except Exception:
        return raw


def _path_to_config_string(path: Path) -> str:
    """Write paths with forward slashes so TOML examples work across shells."""
    return path.as_posix()


def _has_glob(pattern: str) -> bool:
    return any(ch in pattern for ch in "*?[")


def _glob_for_config_path(pattern: str, config_path: Path) -> list[str]:
    import glob

    glob_path = Path(pattern)
    if not glob_path.is_absolute():
        glob_path = config_path.parent / glob_path
    return glob.glob(str(glob_path), recursive="**" in pattern)


def _collapse_expanded_access_log_paths(values: tuple[str, ...]) -> str | None:
    """Recover a wildcard when PowerShell expands an access-log glob."""
    if len(values) < 2:
        return None

    paths = [Path(value) for value in values]
    parent = paths[0].parent
    if any(path.parent != parent for path in paths):
        return None

    names = [path.name for path in paths]
    if all(re.match(r"^localhost_access_log\..+\.txt$", name) for name in names):
        return _path_to_config_string(parent / "localhost_access_log.*.txt")

    prefix = os.path.commonprefix(names)
    suffix = os.path.commonprefix([name[::-1] for name in names])[::-1]
    if not prefix and not suffix:
        return None

    shortest = min(len(name) for name in names)
    if len(prefix) + len(suffix) >= shortest:
        suffix = suffix[: max(0, shortest - len(prefix) - 1)]

    return _path_to_config_string(parent / f"{prefix}*{suffix}")


def _normalize_config_set_value(key: str, values: tuple[str, ...]) -> tuple[str, str | None]:
    if not values:
        raise click.ClickException("Config value cannot be empty.")
    if len(values) == 1:
        return values[0], None

    if key == "website.log_config.access_log_path":
        collapsed = _collapse_expanded_access_log_paths(values)
        if collapsed:
            return (
                collapsed,
                "Multiple paths were received; treating them as an expanded shell wildcard.",
            )

    raise click.ClickException(
        "Received multiple values. Quote the value, or use `anteumbra config access-log` for web access logs."
    )


def _infer_access_log_server(access_log_path: str) -> str:
    lower = access_log_path.lower()
    if "localhost_access_log" in lower or "tomcat" in lower:
        return "tomcat"
    if "nginx" in lower:
        return "nginx"
    if "apache" in lower or "httpd" in lower:
        return "apache"
    return "custom"


def _infer_tomcat_base(access_log_path: str) -> str | None:
    if not access_log_path:
        return None
    path = Path(access_log_path)
    if path.name.lower().startswith("localhost_access_log") and path.parent.name.lower() == "logs":
        return _path_to_config_string(path.parent.parent)
    return None


def _access_log_preset_path(server_type: str, log_path: str | None = None, base_path: str | None = None) -> str:
    server = server_type.lower()
    if log_path:
        return log_path
    if server == "nginx":
        return "/var/log/nginx/access.log"
    if server == "apache":
        return "/var/log/apache2/access.log"
    if server == "tomcat":
        if base_path:
            return _path_to_config_string(Path(base_path) / "logs" / "localhost_access_log.*.txt")
        return posixpath.join("logs", "localhost_access_log.*.txt")
    if server == "custom":
        raise click.ClickException("Custom access-log setup requires --path or wizard input.")
    raise click.ClickException(f"Unsupported access-log server type: {server_type}")


def _set_dotted_value(data: dict, dotted_key: str, value) -> None:
    parts = [part for part in dotted_key.split(".") if part]
    if not parts:
        raise click.ClickException("Config key cannot be empty.")
    node = data
    for part in parts[:-1]:
        child = node.setdefault(part, {})
        if not isinstance(child, dict):
            raise click.ClickException(
                f"Cannot set {dotted_key}: {part} is not a table."
            )
        node = child
    node[parts[-1]] = value


def _get_dotted_value(data: dict, dotted_key: str, default=None):
    node = data
    for part in dotted_key.split("."):
        if not isinstance(node, dict) or part not in node:
            return default
        node = node[part]
    return node


def _write_env_value(env_path: Path, key: str, value: str) -> None:
    env_path.parent.mkdir(parents=True, exist_ok=True)
    lines = env_path.read_text(encoding="utf-8").splitlines() if env_path.exists() else []
    replacement = f"{key}={value}"
    replaced = False

    for index, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("#") or "=" not in line:
            continue
        if line.split("=", 1)[0].strip() == key:
            lines[index] = replacement
            replaced = True
            break

    if not replaced:
        if lines and lines[-1].strip():
            lines.append("")
        lines.append(replacement)

    env_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    os.environ[key] = value


def _secret_prompt(text: str, default: str = "") -> str:
    """Prompt for a secret, without blocking piped/non-interactive input."""
    return click.prompt(
        text,
        default=default,
        show_default=False,
        hide_input=sys.stdin.isatty(),
    )


def _generate_deployment_credentials() -> tuple[str, str, str]:
    """Return a plaintext admin password, its hash, and a session secret."""
    import secrets as secrets_module
    import string
    from werkzeug.security import generate_password_hash

    password = "".join(
        secrets_module.choice(string.ascii_letters + string.digits)
        for _ in range(16)
    )
    return password, generate_password_hash(password), secrets_module.token_urlsafe(48)


def _write_generated_env(env_file: Path) -> str:
    """Create a complete deployment .env and return the admin password."""
    password, password_hash, secret_key = _generate_deployment_credentials()
    env_file.write_text(
        "# Anteumbra deployment environment\n"
        "# Restart Anteumbra after changing these values.\n\n"
        "# Admin credentials\n"
        f"ANTEUMBRA_PASSWORD_HASH={password_hash}\n\n"
        "# Flask session and CSRF signing key\n"
        f"ANTEUMBRA_SECRET_KEY={secret_key}\n\n"
        "# Email notifications (disabled until enabled in config.toml)\n"
        "ANTEUMBRA_EMAIL_USERNAME=\n"
        "ANTEUMBRA_EMAIL_PASSWORD=\n"
        "ANTEUMBRA_EMAIL_FROM=\n"
        "ANTEUMBRA_EMAIL_TO=\n\n"
        "# ServerChan/WeChat notifications (disabled until enabled in config.toml)\n"
        "ANTEUMBRA_WECHAT_API_KEY=\n\n"
        "# External WAF integration\n"
        "ANTEUMBRA_WAF_API_KEY=\n",
        encoding="utf-8",
    )
    return password


def _create_config_template(target: Path, overwrite: bool | None = None) -> str | None:
    """Generate config.toml, .env, default site dir, and bundled rules."""
    import shutil

    template = _find_config_template()
    target.parent.mkdir(parents=True, exist_ok=True)

    if not template:
        # v1.0.9: 从包所在源码树查找（dev install）
        click.echo("No bundled config.toml template found. Reinstall the anteumbra package.", err=True)
        raise SystemExit(1)

    if target.exists():
        should_overwrite = overwrite
        if should_overwrite is None:
            should_overwrite = click.confirm(f"{target} already exists. Overwrite?")
        if not should_overwrite:
            click.echo("Aborted.")
            return None

    shutil.copy(template, target)
    click.echo(f"Config template written to {target}")
    site_dir = _ensure_default_site_dir(target.parent)
    click.echo(f"Default website directory ready at {site_dir}")

    # v1.0.10: 生成完整 .env 文件（含所有通知推送字段）
    env_file = target.parent / ".env"
    if not env_file.exists() or overwrite is True or click.confirm(f"{env_file} already exists. Overwrite?"):
        pwd = _write_generated_env(env_file)
        click.echo(f".env written to {env_file}")
        click.echo(f"  Admin username: admin")
        click.echo(f"  Admin password: {pwd}")
        click.echo(f"  (fill in email/WeChat fields to enable notifications)")
    else:
        pwd = None

    # v1.0.9: 同时复制 YARA 规则目录
    rules_src = None
    for candidate in [
        template.parent / "rules",                    # 与 config.toml 同目录
        _package_dir() / "rules",                     # 包内置规则
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
        click.echo("Warning: YARA rules source not found; rules will be unavailable until added")
        click.echo("  You can manually copy rules/ from the Anteumbra repository")

    click.echo("Edit config.toml to configure websites, WAF, notifications, etc.")
    return pwd


def _validate_config_file(config_path: Path) -> tuple[list[str], list[str]]:
    from anteumbra.infrastructure.config.loader import load_toml_config

    errors: list[str] = []
    warnings: list[str] = []

    if not config_path.exists():
        return [f"Config file does not exist: {config_path}"], warnings

    try:
        cfg = load_toml_config(str(config_path))
    except Exception as exc:
        return [f"Failed to load config: {exc}"], warnings

    raw_websites = cfg.get("website", {})
    if isinstance(raw_websites, dict):
        websites = [raw_websites]
    elif isinstance(raw_websites, list) and all(
        isinstance(item, dict) for item in raw_websites
    ):
        websites = raw_websites
    else:
        errors.append("[website] must be a table or an array of tables.")
        websites = []

    enabled_websites = 0
    for index, website in enumerate(websites, start=1):
        label = "[website]" if len(websites) == 1 else f"[[website]] #{index}"
        if not website.get("enabled", True):
            continue
        enabled_websites += 1

        site_name = str(website.get("name", "")).strip()
        if (
            not site_name
            or site_name in {".", ".."}
            or "/" in site_name
            or "\\" in site_name
        ):
            errors.append(f"{label}.name is required and must not contain path separators.")

        site_path = str(website.get("path", "")).strip()
        if not site_path:
            errors.append(f"{label}.path is required when enabled=true.")
        else:
            resolved = Path(site_path)
            if not resolved.is_absolute():
                resolved = config_path.parent / resolved
            if not resolved.exists():
                errors.append(f"Website path does not exist ({label}): {resolved.resolve()}")

        site_port = website.get("port")
        if not isinstance(site_port, int) or not (1 <= site_port <= 65535):
            errors.append(f"{label}.port must be an integer between 1 and 65535.")

        log_config = website.get("log_config", {})
        if isinstance(log_config, dict) and log_config.get("log_monitor_enabled"):
            access_log = str(log_config.get("access_log_path", "")).strip()
            if not access_log:
                errors.append(f"{label} enables access log monitoring without a path.")
            elif _has_glob(access_log):
                matches = _glob_for_config_path(access_log, config_path)
                if not matches:
                    errors.append(f"Access log wildcard has no matches ({label}): {access_log}")
            else:
                log_path = Path(access_log)
                if not log_path.is_absolute():
                    log_path = config_path.parent / log_path
                if not log_path.exists():
                    errors.append(
                        f"Access log path does not exist ({label}): {log_path.resolve()}"
                    )

    if not enabled_websites:
        errors.append("At least one website must be enabled.")

    web_admin = cfg.get("web_admin", {})
    if not isinstance(web_admin, dict):
        errors.append("[web_admin] must be a table.")
        web_admin = {}

    port = web_admin.get("port")
    if not isinstance(port, int) or not (1 <= port <= 65535):
        errors.append("[web_admin].port must be an integer between 1 and 65535.")

    if not str(web_admin.get("password_hash", "")).strip():
        warnings.append("Admin password hash is empty. Set ANTEUMBRA_PASSWORD_HASH in .env.")

    from ipaddress import ip_network

    for key in ("allowed_ips", "trusted_proxy_ips"):
        values = web_admin.get(key, [] if key == "trusted_proxy_ips" else ["127.0.0.1"])
        if isinstance(values, str):
            values = [values]
        if not isinstance(values, list):
            errors.append(f"[web_admin].{key} must be an array of IP addresses or CIDR ranges.")
            continue
        for value in values:
            try:
                ip_network(str(value).strip(), strict=False)
            except ValueError:
                errors.append(f"[web_admin].{key} contains an invalid IP/CIDR: {value!r}")

    secure_cookie = web_admin.get("session_cookie_secure", "auto")
    if isinstance(secure_cookie, str) and secure_cookie.strip().lower() not in {
        "auto", "true", "false", "yes", "no", "on", "off", "1", "0",
    }:
        errors.append("[web_admin].session_cookie_secure must be true, false, or 'auto'.")
    if web_admin.get("trusted_proxy_ips") and secure_cookie is False:
        warnings.append(
            "Trusted proxy is configured while session_cookie_secure=false; HTTPS session cookies are not protected."
        )

    security = cfg.get("security", {})
    secret = security.get("secret_key", "") if isinstance(security, dict) else ""
    if not secret or secret in {
        "change_this_to_a_random_32_char_string",
        "YOUR_SECRET_KEY_HERE",
    }:
        warnings.append("ANTEUMBRA_SECRET_KEY is not customized.")

    waf_source = cfg.get("waf_source", {})
    if isinstance(waf_source, dict) and waf_source.get("enabled"):
        if not str(waf_source.get("url", "")).strip():
            errors.append("WAF source is enabled but [waf_source].url is empty.")

    from anteumbra.application.runtime_health_service import assess_runtime_capabilities

    warnings.extend(
        warning["message"]
        for warning in assess_runtime_capabilities(cfg)["warnings"]
    )

    return errors, warnings


@cli.group(invoke_without_command=True)
@click.option("--output", "-o", default=None, help="Output path (default: ./config.toml)")
@click.pass_context
def config(ctx, output):
    """Manage config.toml and .env files."""
    if ctx.invoked_subcommand is None:
        target = Path(output).expanduser().resolve() if output else _config_target()
        _create_config_template(target)


@config.command("init")
@click.option("--output", "-o", default=None, help="Output path (default: ./config.toml)")
@click.option("--force", is_flag=True, help="Overwrite existing files without prompting")
def config_init(output, force):
    """Create config.toml, .env, default site dir, and bundled rules."""
    target = Path(output).expanduser().resolve() if output else _config_target()
    _create_config_template(target, overwrite=True if force else None)


@config.command("set")
@click.argument("key")
@click.argument("value", nargs=-1, required=True)
@click.option("--config", "config_path", default=None, help="Path to config.toml")
def config_set(key, value, config_path):
    """Set a dotted config key, for example website.path or web_admin.port."""
    target = _config_target(config_path)
    if not target.exists():
        raise click.ClickException(f"Config file does not exist: {target}")

    data = _load_toml_file(target)
    raw_value, note = _normalize_config_set_value(key, value)
    parsed = _parse_config_value(raw_value)
    _set_dotted_value(data, key, parsed)
    _write_toml_file(target, data)
    if note:
        click.echo(f"Note: {note}")
    click.echo(f"Set {key} = {parsed!r} in {target}")


@config.command("access-log")
@click.argument(
    "server_type",
    type=click.Choice(["none", "nginx", "apache", "tomcat", "custom"], case_sensitive=False),
)
@click.option("--path", "log_path", default=None, help="Explicit access log path or wildcard")
@click.option("--base", "base_path", default=None, help="Server base directory, e.g. CATALINA_BASE for Tomcat")
@click.option("--config", "config_path", default=None, help="Path to config.toml")
def config_access_log(server_type, log_path, base_path, config_path):
    """Configure web access-log analysis using server presets."""
    target = _config_target(config_path)
    if not target.exists():
        raise click.ClickException(f"Config file does not exist: {target}")

    data = _load_toml_file(target)
    server = server_type.lower()
    if server == "none":
        _set_dotted_value(data, "website.log_config.log_monitor_enabled", False)
        _write_toml_file(target, data)
        click.echo(f"Disabled access log analysis in {target}")
        return

    access_log = _access_log_preset_path(server, log_path=log_path, base_path=base_path)
    _set_dotted_value(data, "website.log_config.log_monitor_enabled", True)
    _set_dotted_value(data, "website.log_config.access_log_path", access_log)
    _write_toml_file(target, data)
    click.echo(f"Enabled access log analysis for {server}.")
    click.echo(f"Set website.log_config.access_log_path = {access_log!r} in {target}")


@config.group("env")
def config_env():
    """Manage .env values."""


@config_env.command("set")
@click.argument("key")
@click.argument("value")
@click.option("--env", "env_path", default=None, help="Path to .env")
def config_env_set(key, value, env_path):
    """Set one environment variable in .env."""
    target = Path(env_path).expanduser().resolve() if env_path else _config_target().parent / ".env"
    _write_env_value(target, key, value)
    click.echo(f"Set {key} in {target}")


@config.command("validate")
@click.option("--config", "config_path", default=None, help="Path to config.toml")
def config_validate(config_path):
    """Validate config.toml, .env, paths, ports, and enabled integrations."""
    target = _config_target(config_path)
    errors, warnings = _validate_config_file(target)

    for warning in warnings:
        click.echo(f"Warning: {warning}")
    for error in errors:
        click.echo(f"Error: {error}", err=True)

    if errors:
        raise SystemExit(1)
    click.echo(f"Config OK: {target}")


@config.command("reload")
@click.option("--config", "config_path", default=None, help="Path to config.toml")
def config_reload(config_path):
    """Fully parse config without mutating a running service."""
    target = _config_target(config_path)
    errors, warnings = _validate_config_file(target)
    for warning in warnings:
        click.echo(f"Warning: {warning}")
    if errors:
        for error in errors:
            click.echo(f"Error: {error}", err=True)
        raise SystemExit(1)

    from anteumbra.infrastructure.config.provider import TomlConfigProvider

    try:
        provider = TomlConfigProvider(target)
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise click.ClickException(f"Config parse failed: {exc}") from exc
    click.echo(f"Config parsed successfully: {provider.path}")
    click.echo(f"Enabled websites: {len(provider.get_enabled_websites())}")
    click.echo(
        "The running Anteumbra service is unchanged; "
        "reload it in Web System or restart it."
    )


@config.command("wizard")
@click.option("--config", "config_path", default=None, help="Path to config.toml")
def config_wizard(config_path):
    """Interactive first-run configuration wizard."""
    target = _config_target(config_path)
    if not target.exists():
        click.echo(f"No config found at {target}; creating a template first.")
        _create_config_template(target, overwrite=True)

    data = _load_toml_file(target)

    current_site = str(_get_dotted_value(data, "website.path", "sites/default"))
    site_path = click.prompt("Website root path", default=current_site)
    resolved_site = Path(site_path)
    if not resolved_site.is_absolute():
        resolved_site = target.parent / resolved_site
    if not resolved_site.exists() and click.confirm(f"Create website directory {resolved_site}?", default=True):
        resolved_site.mkdir(parents=True, exist_ok=True)
    _set_dotted_value(data, "website.path", site_path)

    current_port = int(_get_dotted_value(data, "web_admin.port", DEFAULT_PORT))
    admin_port = click.prompt("Admin port", default=current_port, type=int)
    if not (1 <= admin_port <= 65535):
        raise click.ClickException("Admin port must be between 1 and 65535.")
    _set_dotted_value(data, "web_admin.port", admin_port)

    password = _secret_prompt("Admin password (leave empty to keep generated/current)")
    if password:
        from werkzeug.security import generate_password_hash

        _write_env_value(target.parent / ".env", "ANTEUMBRA_PASSWORD_HASH", generate_password_hash(password))

    log_enabled = bool(_get_dotted_value(data, "website.log_config.log_monitor_enabled", False))
    enable_logs = click.confirm("Enable access log analysis?", default=log_enabled)
    _set_dotted_value(data, "website.log_config.log_monitor_enabled", enable_logs)
    if enable_logs:
        current_log = str(_get_dotted_value(data, "website.log_config.access_log_path", ""))
        default_server = _infer_access_log_server(current_log) if current_log else "custom"
        server = click.prompt(
            "Access log server",
            default=default_server,
            type=click.Choice(["nginx", "apache", "tomcat", "custom"], case_sensitive=False),
        )
        if server.lower() == "tomcat":
            default_base = _infer_tomcat_base(current_log) or "."
            base_path = click.prompt("Tomcat/CATALINA_BASE directory", default=default_base)
            access_log = _access_log_preset_path("tomcat", base_path=base_path)
        elif server.lower() == "custom":
            access_log = click.prompt("Access log path", default=current_log or "logs/access.log")
        else:
            default_log = _access_log_preset_path(server)
            access_log = click.prompt("Access log path", default=current_log or default_log)
        _set_dotted_value(data, "website.log_config.access_log_path", access_log)

    waf_enabled = bool(_get_dotted_value(data, "waf_source.enabled", False))
    enable_waf = click.confirm("Enable WAF event polling?", default=waf_enabled)
    _set_dotted_value(data, "waf_source.enabled", enable_waf)
    if enable_waf:
        waf_type = click.prompt(
            "WAF type",
            default=str(_get_dotted_value(data, "waf_source.type", "mock")),
            type=click.Choice(
                ["mock", "http", "modsecurity", "cloudflare", "aws_waf", "syslog"],
                case_sensitive=False,
            ),
        )
        waf_url = click.prompt(
            "WAF URL",
            default=str(_get_dotted_value(data, "waf_source.url", "http://127.0.0.1:8081")),
        )
        _set_dotted_value(data, "waf_source.type", waf_type)
        _set_dotted_value(data, "waf_source.url", waf_url)
        waf_key = _secret_prompt("WAF API key (optional)")
        if waf_key:
            _write_env_value(target.parent / ".env", "ANTEUMBRA_WAF_API_KEY", waf_key)

    wechat_key = _secret_prompt("ServerChan/WeChat SendKey (optional)")
    if wechat_key:
        _write_env_value(target.parent / ".env", "ANTEUMBRA_WECHAT_API_KEY", wechat_key)
        _set_dotted_value(data, "notifier.enabled", True)
        _set_dotted_value(data, "notifier.wechat.enabled", True)

    _write_toml_file(target, data)
    click.echo(f"Config wizard wrote {target}")

    errors, warnings = _validate_config_file(target)
    for warning in warnings:
        click.echo(f"Warning: {warning}")
    if errors:
        for error in errors:
            click.echo(f"Error: {error}", err=True)
        raise SystemExit(1)
    click.echo("Config OK.")


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
    from datetime import datetime
    from anteumbra.infrastructure.config.install_registry import (
        get_install_info,
        register_install,
    )

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
                "data/siem", "logs", "rules", str(DEFAULT_SITE_DIR)]:
        (target / sub).mkdir(parents=True, exist_ok=True)

    # ── 提取 config.toml 模板 ─────────────────────
    config_dst = target / "config.toml"
    config_src = _find_config_template()
    pkg_dir = _package_dir()

    if config_src and config_src != config_dst:
        shutil.copy(config_src, config_dst)
        click.echo(f"Config template -> {config_dst}")
    elif not config_src:
        click.echo("Error: bundled config.toml template not found. Reinstall the anteumbra package.", err=True)

    # ── 复制 YARA 规则 ────────────────────────────
    if not config_src:
        raise SystemExit(1)

    if not config_dst.exists():
        click.echo(f"Error: failed to create {config_dst}", err=True)
        raise SystemExit(1)

    rules_src = pkg_dir / "rules"
    rules_dst = target / "rules"
    if rules_src.exists() and rules_src.is_dir():
        # 只复制 webshell 子目录（不复制整个 rules/ 包裹层）
        webshell_src = rules_src / "webshell"
        webshell_dst = rules_dst / "webshell"
        if webshell_src.exists() and not webshell_dst.exists():
            shutil.copytree(webshell_src, webshell_dst)
            yar_count = len(list(webshell_dst.glob("*.yar")))
            click.echo(f"YARA rules -> {webshell_dst} ({yar_count} files)")
        elif webshell_dst.exists():
            click.echo(f"YARA rules already exist at {webshell_dst} (skipped)")
    else:
        click.echo("Warning: YARA rules not found in package")

    # ── 生成 .env ─────────────────────────────────
    env_file = target / ".env"
    if not env_file.exists() or force:
        pwd = _write_generated_env(env_file)
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
    try:
        register_install(str(target), __version__)
    except OSError as exc:
        click.echo(
            "Warning: installation completed, but the user-level instance "
            f"registry could not be updated: {exc}",
            err=True,
        )

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
