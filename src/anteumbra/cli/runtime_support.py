"""Runtime discovery and process helpers shared by CLI command modules."""

from __future__ import annotations

import logging
from collections.abc import Callable
from pathlib import Path
from types import ModuleType
from urllib import error as urlerror

from anteumbra.infrastructure.process_identity import (
    ProcessIdentity,
    ProcessIdentityState,
)


def package_dir() -> Path:
    import anteumbra

    return Path(anteumbra.__file__).parent


def find_config_template(package_root: Path) -> Path | None:
    """Return the bundled config template for wheel and editable installs."""
    for candidate in [
        package_root / "config.toml",
        package_root.parent.parent / "config.toml",
    ]:
        if candidate.exists():
            return candidate
    return None


def ensure_default_site_dir(root: Path, default_site_dir: Path) -> Path:
    site_dir = root / default_site_dir
    site_dir.mkdir(parents=True, exist_ok=True)
    return site_dir


def find_project_root(os_module: ModuleType) -> Path:
    """Resolve the current runtime without crossing into another installation."""
    env_home = os_module.environ.get("ANTEUMBRA_HOME")
    if env_home:
        return Path(env_home).expanduser().resolve()

    cwd = Path.cwd().resolve()
    directory = cwd
    source_checkout = None
    for _ in range(6):
        has_pid = (directory / "data" / "anteumbra.pid").exists()
        has_runtime_file = (directory / "config.toml").exists() or has_pid
        if has_runtime_file:
            is_source_checkout = (directory / "pyproject.toml").is_file() and (
                directory / "src" / "anteumbra"
            ).is_dir()
            is_runtime_checkout = (directory / ".anteumbra_install").is_file() or has_pid
            if not is_source_checkout or is_runtime_checkout:
                return directory
            source_checkout = directory
        if directory.parent == directory:
            break
        directory = directory.parent

    try:
        from anteumbra.infrastructure.config.install_registry import get_install_info

        info = get_install_info()
        if info:
            registered = Path(info["install_path"])
            if registered.exists():
                return registered
    except Exception:
        logging.getLogger(__name__).debug(
            "Failed to discover the registered Anteumbra installation",
            exc_info=True,
        )

    return source_checkout or cwd


def service_ready(
    host: str,
    port: int,
    timeout: float,
    *,
    urlopen: Callable,
) -> bool:
    """Return whether the running service answers its public health endpoint."""
    connect_host = host
    if host in {"0.0.0.0", "::", "[::]"}:
        connect_host = "127.0.0.1"
    if ":" in connect_host and not connect_host.startswith("["):
        connect_host = f"[{connect_host}]"
    health_url = f"http://{connect_host}:{port}/api/v1/health"
    try:
        with urlopen(health_url, timeout=timeout) as response:
            return 200 <= response.status < 300
    except (OSError, ValueError, urlerror.URLError):
        return False


def wait_for_process_exit(
    identity: ProcessIdentity,
    root: Path,
    *,
    process_state: Callable[[ProcessIdentity, Path], ProcessIdentityState],
    time_module: ModuleType,
    timeout: float = 5.0,
    interval: float = 0.1,
) -> bool:
    """Wait until a process exits instead of trusting a kill command result."""
    deadline = time_module.monotonic() + timeout
    while time_module.monotonic() < deadline:
        state = process_state(identity, root)
        if state in {ProcessIdentityState.STOPPED, ProcessIdentityState.MISMATCH}:
            return True
        time_module.sleep(interval)
    return process_state(identity, root) in {
        ProcessIdentityState.STOPPED,
        ProcessIdentityState.MISMATCH,
    }


def resolve_bind_options(
    root: Path,
    host: str | None,
    port: int | None,
    *,
    load_toml_file: Callable[[Path], dict],
    default_host: str,
    default_port: int,
) -> tuple[str, int]:
    """Resolve bind address from CLI options, config, then defaults."""
    resolved_host = host
    resolved_port = port
    if resolved_host is not None and resolved_port is not None:
        return resolved_host, resolved_port

    config_path = root / "config.toml"
    if config_path.exists():
        try:
            config = load_toml_file(config_path)
            web_admin = config.get("web_admin", {})
            if isinstance(web_admin, dict):
                if resolved_host is None:
                    resolved_host = str(web_admin.get("host") or default_host)
                if resolved_port is None:
                    resolved_port = int(web_admin.get("port", default_port))
        except Exception as exc:
            import click

            click.echo(
                f"Warning: failed to read {config_path}; using default bind: {exc}",
                err=True,
            )

    return resolved_host or default_host, resolved_port or default_port
