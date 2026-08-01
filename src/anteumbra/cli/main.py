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
import os
import subprocess
import sys
import time
from pathlib import Path
from urllib import error as urlerror  # noqa: F401 - compatibility export
from urllib import request as urlrequest

import click

from anteumbra import __version__
from anteumbra.cli import (
    config_commands,
    config_support,
    install_commands,
    lifecycle_commands,
    runtime_support,
)
from anteumbra.infrastructure.process_identity import (
    ProcessIdentity,
    ProcessIdentityState,
    probe_process_identity,
    read_process_identity,
)

PID_FILE = Path("data/anteumbra.pid")
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8080
DEFAULT_SITE_DIR = Path("sites/default")


def _package_dir() -> Path:
    return runtime_support.package_dir()


def _find_config_template() -> Path | None:
    return runtime_support.find_config_template(_package_dir())


def _ensure_default_site_dir(root: Path) -> Path:
    return runtime_support.ensure_default_site_dir(root, DEFAULT_SITE_DIR)


def _find_project_root() -> Path:
    return runtime_support.find_project_root(os)


def _pid_path(root: Path | None = None) -> Path:
    return (root or _find_project_root()) / PID_FILE


def _read_runtime_identity(root: Path | None = None) -> ProcessIdentity | None:
    return read_process_identity(_pid_path(root))


def _process_state(
    identity: ProcessIdentity,
    root: Path | None = None,
) -> ProcessIdentityState:
    return probe_process_identity(identity, root or _find_project_root())


def _service_ready(host: str, port: int, timeout: float = 0.25) -> bool:
    return runtime_support.service_ready(
        host,
        port,
        timeout,
        urlopen=urlrequest.urlopen,
    )


def _wait_for_process_exit(
    identity: ProcessIdentity,
    root: Path,
    *,
    timeout: float = 5.0,
    interval: float = 0.1,
) -> bool:
    return runtime_support.wait_for_process_exit(
        identity,
        root,
        process_state=lambda current, current_root: _process_state(
            current, current_root
        ),
        time_module=time,
        timeout=timeout,
        interval=interval,
    )


def _get_python() -> str:
    return sys.executable


def _resolve_bind_options(
    root: Path,
    host: str | None,
    port: int | None,
) -> tuple[str, int]:
    return runtime_support.resolve_bind_options(
        root,
        host,
        port,
        load_toml_file=_load_toml_file,
        default_host=DEFAULT_HOST,
        default_port=DEFAULT_PORT,
    )

@click.group(
    invoke_without_command=True,
    context_settings={"help_option_names": ["-h", "--help"]},
    epilog=(
        "\b\nExamples:\n"
        "  anteumbra install E:\\Software\\Anteumbra\n"
        "  anteumbra --home E:\\Software\\Anteumbra config wizard\n"
        "  anteumbra --home E:\\Software\\Anteumbra start\n\n"
        "Run 'anteumbra COMMAND --help' for command-specific options."
    ),
)
@click.version_option(__version__, prog_name="anteumbra")
@click.option(
    "--home",
    type=click.Path(file_okay=False, path_type=Path, resolve_path=True),
    envvar="ANTEUMBRA_HOME",
    help="Runtime instance directory used by run, start, stop, status, and config.",
)
@click.pass_context
def cli(ctx, home):
    """Anteumbra - Lightweight Web Perimeter Security Platform.

    Install package code with pip (preferably in an isolated environment),
    then create one mutable runtime with `anteumbra install INSTANCE_DIR`.
    The runtime directory owns config.toml, .env, data, logs, rules, and
    quarantine state; it is separate from the Python package location.
    """
    if home is not None:
        os.environ["ANTEUMBRA_HOME"] = str(home)
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())
        root = _find_project_root()
        identity = _read_runtime_identity(root)
        state = _process_state(identity, root) if identity else None
        if identity and state is ProcessIdentityState.RUNNING:
            click.echo(f"\n  Status: RUNNING (PID {identity.pid})")
        elif identity and state is ProcessIdentityState.UNKNOWN:
            click.echo(
                f"\n  Status: UNKNOWN (cannot verify PID {identity.pid} ownership)"
            )
        elif identity is None and _pid_path(root).exists():
            click.echo("\n  Status: UNKNOWN (invalid PID identity file)")
        else:
            click.echo("\n  Status: STOPPED")


_lifecycle_commands = lifecycle_commands.register_lifecycle_commands(
    cli,
    lifecycle_commands.LifecycleCommandDependencies(
        version=__version__,
        find_project_root=lambda: _find_project_root(),
        pid_path=lambda root=None: _pid_path(root),
        read_runtime_identity=lambda root=None: _read_runtime_identity(root),
        process_state=lambda identity, root=None: _process_state(identity, root),
        service_ready=lambda host, port, timeout=0.25: _service_ready(host, port),
        wait_for_process_exit=lambda identity, root, **kwargs: _wait_for_process_exit(
            identity, root, **kwargs
        ),
        get_python=lambda: _get_python(),
        resolve_bind_options=lambda root, host, port: _resolve_bind_options(
            root, host, port
        ),
        os_module=os,
        subprocess_module=subprocess,
        sys_module=sys,
        time_module=time,
    ),
)
run = _lifecycle_commands['run']
start = _lifecycle_commands['start']
stop = _lifecycle_commands['stop']
status = _lifecycle_commands['status']


# ── Config management ──────────────────────────────

_load_toml_file = config_support.load_toml_file
_write_toml_file = config_support.write_toml_file
_load_toml_value = config_support.load_toml_value
_parse_config_value = config_support.parse_config_value
_path_to_config_string = config_support.path_to_config_string
_has_glob = config_support.has_glob
_glob_for_config_path = config_support.glob_for_config_path
_collapse_expanded_access_log_paths = config_support.collapse_expanded_access_log_paths
_normalize_config_set_value = config_support.normalize_config_set_value
_infer_access_log_server = config_support.infer_access_log_server
_infer_tomcat_base = config_support.infer_tomcat_base
_access_log_preset_path = config_support.access_log_preset_path
_set_dotted_value = config_support.set_dotted_value
_get_dotted_value = config_support.get_dotted_value
_write_env_value = config_support.write_env_value
_secret_prompt = config_support.secret_prompt
_generate_deployment_credentials = config_support.generate_deployment_credentials
_write_generated_env = config_support.write_generated_env
_validate_config_file = config_support.validate_config_file


def _config_target(config_path: str | None = None) -> Path:
    if config_path:
        return Path(config_path).expanduser().resolve()
    return (_find_project_root() / "config.toml").resolve()


def _create_config_template(
    target: Path,
    overwrite: bool | None = None,
) -> str | None:
    return config_support.create_config_template(
        target,
        find_config_template=_find_config_template,
        ensure_default_site_dir=_ensure_default_site_dir,
        package_dir=_package_dir,
        overwrite=overwrite,
    )

config = config_commands.register_config_commands(
    cli,
    config_target=lambda config_path=None: _config_target(config_path),
    create_config_template=lambda target, overwrite=None: _create_config_template(
        target, overwrite
    ),
    default_port=DEFAULT_PORT,
)
config_init = config.commands['init']
config_set = config.commands['set']
config_access_log = config.commands['access-log']
config_env = config.commands['env']
config_env_set = config_env.commands['set']
config_validate = config.commands['validate']
config_reload = config.commands['reload']
config_wizard = config.commands['wizard']


install = install_commands.register_install_command(
    cli,
    version=__version__,
    default_site_dir=DEFAULT_SITE_DIR,
    find_config_template=lambda: _find_config_template(),
    package_dir=lambda: _package_dir(),
    write_generated_env=lambda env_file: _write_generated_env(env_file),
    resolve_bind_options=lambda root, host, port: _resolve_bind_options(
        root, host, port
    ),
    load_toml_file=lambda path: _load_toml_file(path),
)


if __name__ == "__main__":
    cli()
