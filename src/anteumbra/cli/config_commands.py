"""Click commands for inspecting and modifying runtime configuration."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import click

from anteumbra.cli import config_support


def register_config_commands(
    root: click.Group,
    *,
    config_target: Callable[[str | None], Path],
    create_config_template: Callable[[Path, bool | None], str | None],
    default_port: int,
) -> click.Group:
    """Register the config command tree and return its Click group."""

    @root.group(
        invoke_without_command=True,
        epilog=(
            "\b\nExamples:\n"
            "  anteumbra config init\n"
            "  anteumbra config wizard\n"
            "  anteumbra config set web_admin.port 8080\n"
            "  anteumbra config validate"
        ),
    )
    @click.pass_context
    def config(ctx):
        """Inspect or modify runtime configuration.

        Running this group without a subcommand only displays help and never
        creates or overwrites files. Use `config init` for explicit initialization.
        """
        if ctx.invoked_subcommand is None:
            click.echo(ctx.get_help())

    @config.command("init")
    @click.option("--output", "-o", default=None, help="Output path (default: ./config.toml)")
    @click.option(
        "--force",
        is_flag=True,
        help="Replace existing config.toml and .env without prompting.",
    )
    def config_init(output, force):
        """Create config.toml, .env, default site directory, and bundled rules.

        Existing config and secrets are preserved unless you confirm replacement
        interactively or pass --force.
        """
        target = Path(output).expanduser().resolve() if output else config_target(None)
        create_config_template(target, True if force else None)

    @config.command("set")
    @click.argument("key")
    @click.argument("value", nargs=-1, required=True)
    @click.option("--config", "config_path", default=None, help="Path to config.toml")
    @click.option(
        "--allow-site-id-change",
        is_flag=True,
        help="Acknowledge that changing website.id creates a new site identity.",
    )
    def config_set(key, value, config_path, allow_site_id_change):
        """Set a dotted config key, for example website.path or web_admin.port."""
        target = config_target(config_path)
        if not target.exists():
            raise click.ClickException(f"Config file does not exist: {target}")

        data = config_support.load_toml_file(target)
        raw_value, note = config_support.normalize_config_set_value(key, value)
        parsed = config_support.parse_config_value(raw_value)
        site_id_changed = False
        if allow_site_id_change and key != "website.id":
            raise click.ClickException(
                "--allow-site-id-change is only valid with website.id."
            )
        if key == "website.id":
            from anteumbra.domain.site import SiteIdentity

            site_name = str(config_support.get_dotted_value(data, "website.name", parsed)).strip()
            try:
                requested = SiteIdentity.from_values(str(parsed), site_name or str(parsed))
            except ValueError as exc:
                raise click.ClickException(f"Invalid website.id: {exc}") from exc
            if requested.site_id == "legacy":
                raise click.ClickException(
                    "website.id 'legacy' is reserved for unassigned records."
                )
            current_raw = config_support.get_dotted_value(data, key)
            if current_raw is None or not str(current_raw).strip():
                current_raw = config_support.get_dotted_value(data, "website.site_id")
            if current_raw is not None and str(current_raw).strip():
                current = SiteIdentity.from_values(
                    str(current_raw),
                    site_name or str(current_raw),
                )
                site_id_changed = current.site_id != requested.site_id
            if site_id_changed and not allow_site_id_change:
                raise click.ClickException(
                    "website.id is a stable ownership key. Rename website.name instead, "
                    "or pass --allow-site-id-change to create a new site identity."
                )
            parsed = requested.site_id
        config_support.set_dotted_value(data, key, parsed)
        if key == "website.id" and isinstance(data.get("website"), dict):
            data["website"].pop("site_id", None)
        config_support.write_toml_file(target, data)
        if note:
            click.echo(f"Note: {note}")
        if site_id_changed:
            click.echo(
                "Warning: website.id changed; existing records keep the previous site ID."
            )
        click.echo(f"Set {key} = {parsed!r} in {target}")

    @config.command("access-log")
    @click.argument(
        "server_type",
        type=click.Choice(
            ["none", "nginx", "apache", "tomcat", "custom"],
            case_sensitive=False,
        ),
    )
    @click.option("--path", "log_path", default=None, help="Explicit access log path or wildcard")
    @click.option(
        "--base",
        "base_path",
        default=None,
        help="Server base directory, e.g. CATALINA_BASE for Tomcat",
    )
    @click.option("--config", "config_path", default=None, help="Path to config.toml")
    def config_access_log(server_type, log_path, base_path, config_path):
        """Configure web access-log analysis using server presets."""
        target = config_target(config_path)
        if not target.exists():
            raise click.ClickException(f"Config file does not exist: {target}")

        data = config_support.load_toml_file(target)
        server = server_type.lower()
        if server == "none":
            config_support.set_dotted_value(
                data, "website.log_config.log_monitor_enabled", False
            )
            config_support.write_toml_file(target, data)
            click.echo(f"Disabled access log analysis in {target}")
            return

        access_log = config_support.access_log_preset_path(
            server, log_path=log_path, base_path=base_path
        )
        config_support.set_dotted_value(
            data, "website.log_config.log_monitor_enabled", True
        )
        config_support.set_dotted_value(
            data, "website.log_config.access_log_path", access_log
        )
        config_support.write_toml_file(target, data)
        click.echo(f"Enabled access log analysis for {server}.")
        click.echo(
            f"Set website.log_config.access_log_path = {access_log!r} in {target}"
        )

    @config.group("env")
    def config_env():
        """Manage .env values."""

    @config_env.command("set")
    @click.argument("key")
    @click.argument("value")
    @click.option("--env", "env_path", default=None, help="Path to .env")
    def config_env_set(key, value, env_path):
        """Set one environment variable in .env."""
        target = (
            Path(env_path).expanduser().resolve()
            if env_path
            else config_target(None).parent / ".env"
        )
        config_support.write_env_value(target, key, value)
        click.echo(f"Set {key} in {target}")

    @config.command("validate")
    @click.option("--config", "config_path", default=None, help="Path to config.toml")
    def config_validate(config_path):
        """Validate config.toml, .env, paths, ports, and enabled integrations."""
        target = config_target(config_path)
        errors, warnings = config_support.validate_config_file(target)

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
        target = config_target(config_path)
        errors, warnings = config_support.validate_config_file(target)
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
        target = config_target(config_path)
        if not target.exists():
            click.echo(f"No config found at {target}; creating a template first.")
            create_config_template(target, True)

        data = config_support.load_toml_file(target)

        current_site = str(
            config_support.get_dotted_value(data, "website.path", "sites/default")
        )
        site_path = click.prompt("Website root path", default=current_site)
        resolved_site = Path(site_path)
        if not resolved_site.is_absolute():
            resolved_site = target.parent / resolved_site
        if not resolved_site.exists() and click.confirm(
            f"Create website directory {resolved_site}?", default=True
        ):
            resolved_site.mkdir(parents=True, exist_ok=True)
        config_support.set_dotted_value(data, "website.path", site_path)

        current_port = int(
            config_support.get_dotted_value(data, "web_admin.port", default_port)
        )
        admin_port = click.prompt("Admin port", default=current_port, type=int)
        if not (1 <= admin_port <= 65535):
            raise click.ClickException("Admin port must be between 1 and 65535.")
        config_support.set_dotted_value(data, "web_admin.port", admin_port)

        password = config_support.secret_prompt(
            "Admin password (leave empty to keep generated/current)"
        )
        if password:
            from werkzeug.security import generate_password_hash

            config_support.write_env_value(
                target.parent / ".env",
                "ANTEUMBRA_PASSWORD_HASH",
                generate_password_hash(password),
            )

        log_enabled = bool(
            config_support.get_dotted_value(
                data, "website.log_config.log_monitor_enabled", False
            )
        )
        enable_logs = click.confirm("Enable access log analysis?", default=log_enabled)
        config_support.set_dotted_value(
            data, "website.log_config.log_monitor_enabled", enable_logs
        )
        if enable_logs:
            current_log = str(
                config_support.get_dotted_value(
                    data, "website.log_config.access_log_path", ""
                )
            )
            default_server = (
                config_support.infer_access_log_server(current_log)
                if current_log
                else "custom"
            )
            server = click.prompt(
                "Access log server",
                default=default_server,
                type=click.Choice(
                    ["nginx", "apache", "tomcat", "custom"],
                    case_sensitive=False,
                ),
            )
            if server.lower() == "tomcat":
                default_base = config_support.infer_tomcat_base(current_log) or "."
                base_path = click.prompt(
                    "Tomcat/CATALINA_BASE directory", default=default_base
                )
                access_log = config_support.access_log_preset_path(
                    "tomcat", base_path=base_path
                )
            elif server.lower() == "custom":
                access_log = click.prompt(
                    "Access log path", default=current_log or "logs/access.log"
                )
            else:
                default_log = config_support.access_log_preset_path(server)
                access_log = click.prompt(
                    "Access log path", default=current_log or default_log
                )
            config_support.set_dotted_value(
                data, "website.log_config.access_log_path", access_log
            )

        waf_enabled = bool(
            config_support.get_dotted_value(data, "waf_source.enabled", False)
        )
        enable_waf = click.confirm("Enable WAF event polling?", default=waf_enabled)
        config_support.set_dotted_value(data, "waf_source.enabled", enable_waf)
        if enable_waf:
            waf_type = click.prompt(
                "WAF type",
                default=str(
                    config_support.get_dotted_value(data, "waf_source.type", "mock")
                ),
                type=click.Choice(
                    ["mock", "http", "modsecurity", "cloudflare", "aws_waf", "syslog"],
                    case_sensitive=False,
                ),
            )
            waf_url = click.prompt(
                "WAF URL",
                default=str(
                    config_support.get_dotted_value(
                        data, "waf_source.url", "http://127.0.0.1:8081"
                    )
                ),
            )
            config_support.set_dotted_value(data, "waf_source.type", waf_type)
            config_support.set_dotted_value(data, "waf_source.url", waf_url)
            waf_key = config_support.secret_prompt("WAF API key (optional)")
            if waf_key:
                config_support.write_env_value(
                    target.parent / ".env", "ANTEUMBRA_WAF_API_KEY", waf_key
                )

        wechat_key = config_support.secret_prompt(
            "ServerChan/WeChat SendKey (optional)"
        )
        if wechat_key:
            config_support.write_env_value(
                target.parent / ".env", "ANTEUMBRA_WECHAT_API_KEY", wechat_key
            )
            config_support.set_dotted_value(data, "notifier.enabled", True)
            config_support.set_dotted_value(data, "notifier.wechat.enabled", True)

        config_support.write_toml_file(target, data)
        click.echo(f"Config wizard wrote {target}")

        errors, warnings = config_support.validate_config_file(target)
        for warning in warnings:
            click.echo(f"Warning: {warning}")
        if errors:
            for error in errors:
                click.echo(f"Error: {error}", err=True)
            raise SystemExit(1)
        click.echo("Config OK.")

    return config
