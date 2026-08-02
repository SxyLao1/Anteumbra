"""Click command for provisioning a mutable Anteumbra runtime instance."""

from __future__ import annotations

import json
import logging
import shutil
import sys
from collections.abc import Callable
from datetime import datetime
from pathlib import Path

import click


def register_install_command(
    root: click.Group,
    *,
    version: str,
    default_site_dir: Path,
    find_config_template: Callable[[], Path | None],
    package_dir: Callable[[], Path],
    write_generated_env: Callable[[Path], str],
    resolve_bind_options: Callable[[Path, str | None, int | None], tuple[str, int]],
    load_toml_file: Callable[[Path], dict],
) -> click.Command:
    """Register and return the deployment installation command."""

    @root.command()
    @click.argument("path", required=False, metavar="[INSTANCE_DIR]")
    @click.option(
        "--force",
        is_flag=True,
        help="Allow registration replacement or a non-empty target; preserve config and .env.",
    )
    def install(path, force):
        """Create a mutable runtime in INSTANCE_DIR.

        This command does not install Python package code. Install that first with
        `pip install anteumbra` inside an isolated environment. It then creates the
        runtime config, secrets, rules, data, logs, and quarantine directories and
        registers this as the single default instance for the current user.

        INSTANCE_DIR accepts an absolute or relative path and defaults to the
        current directory. Existing config.toml and .env files are always preserved;
        use `anteumbra config init --force` only when an intentional reset is needed.
        """
        from anteumbra.infrastructure.config.install_registry import (
            get_install_info,
            register_install,
        )

        target = Path(path).resolve() if path else Path.cwd().resolve()
        existing = get_install_info()
        if existing:
            existing_path = Path(existing["install_path"])
            if existing_path == target:
                if not force:
                    click.echo("Anteumbra is already installed at this location:")
                    click.echo(f"  {existing_path}")
                    click.echo(f"  Version: {existing.get('version', 'unknown')}")
                    click.echo(f"  Installed: {existing.get('installed_at', 'unknown')}")
                    click.echo("\nUse --force to reinstall.")
                    raise SystemExit(1)
                click.echo(f"Reinstalling at {target} (--force)...")
            elif not force:
                click.echo("Anteumbra is already installed on this machine:")
                click.echo(f"  {existing_path}")
                click.echo(f"  Version: {existing.get('version', 'unknown')}")
                click.echo(f"  Installed: {existing.get('installed_at', 'unknown')}")
                click.echo("\nOnly one instance per machine is supported.")
                click.echo("To move the installation, reinstall with --force at the new path.")
                click.echo("To reinstall at the existing path, run: anteumbra install --force")
                raise SystemExit(1)
            else:
                click.echo(f"Moving installation from {existing_path} to {target}...")

        if target.exists() and not (target / ".anteumbra_install").exists():
            existing_files = list(target.iterdir())
            if existing_files and not force:
                click.echo(f"Target directory {target} already exists and is not empty.")
                click.echo("It does not appear to be an Anteumbra installation.")
                if not click.confirm("Continue anyway?"):
                    click.echo("Aborted.")
                    return

        target.mkdir(parents=True, exist_ok=True)
        for subdirectory in [
            "data",
            "data/sessions",
            "data/quarantine",
            "data/threat_intel",
            "data/siem",
            "logs",
            "rules",
            str(default_site_dir),
        ]:
            (target / subdirectory).mkdir(parents=True, exist_ok=True)

        config_dst = target / "config.toml"
        config_src = find_config_template()
        pkg_dir = package_dir()

        if config_src and config_src != config_dst:
            if config_dst.exists():
                click.echo(f"Existing config preserved at {config_dst}")
            else:
                shutil.copy(config_src, config_dst)
                click.echo(f"Config template -> {config_dst}")
        elif not config_src:
            click.echo(
                "Error: bundled config.toml template not found. Reinstall the anteumbra package.",
                err=True,
            )

        if not config_src:
            raise SystemExit(1)
        if not config_dst.exists():
            click.echo(f"Error: failed to create {config_dst}", err=True)
            raise SystemExit(1)

        rules_src = pkg_dir / "rules"
        rules_dst = target / "rules"
        if rules_src.is_dir():
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

        env_file = target / ".env"
        if not env_file.exists():
            password = write_generated_env(env_file)
            click.echo(f".env written to {env_file}")
        else:
            click.echo(f"Existing .env preserved at {env_file}")
            password = None

        lock_data = {
            "version": version,
            "installed_at": datetime.now().isoformat(),
            "install_path": str(target),
            "python": sys.executable,
        }
        (target / ".anteumbra_install").write_text(
            "# Anteumbra installation marker — do not delete manually\n"
            f"# {json.dumps(lock_data)}\n",
            encoding="utf-8",
        )

        try:
            register_install(str(target), version)
        except OSError as exc:
            click.echo(
                "Warning: installation completed, but the user-level instance "
                f"registry could not be updated: {exc}",
                err=True,
            )

        admin_host, admin_port = resolve_bind_options(target, None, None)
        display_host = "127.0.0.1" if admin_host in {"0.0.0.0", "::", "[::]"} else admin_host
        if ":" in display_host and not display_host.startswith("["):
            display_host = f"[{display_host}]"
        username = "admin"
        try:
            summary_config = load_toml_file(config_dst)
            web_admin = summary_config.get("web_admin", {})
            if isinstance(web_admin, dict):
                username = str(web_admin.get("username") or username).strip() or username
        except (OSError, TypeError, ValueError):
            logging.getLogger(__name__).debug(
                "Failed to resolve the configured admin username for install summary",
                exc_info=True,
            )
        quoted_target = f'"{target}"'
        click.echo(f"\n{'=' * 60}")
        click.echo(f"  Anteumbra v{version} installed successfully!")
        click.echo(f"  Location: {target}")
        click.echo(f"  Admin:    http://{display_host}:{admin_port}/admin")
        click.echo(f"  Username: {username}")
        if password:
            click.echo(f"  Password: {password}")
        else:
            click.echo("  Password: unchanged (use the Config command below to reset)")
        click.echo(f"\n  Start:    anteumbra --home {quoted_target} start")
        click.echo(f"  Status:   anteumbra --home {quoted_target} status")
        click.echo(f"  Config:   anteumbra --home {quoted_target} config wizard")
        click.echo(f"{'=' * 60}\n")

    return install
