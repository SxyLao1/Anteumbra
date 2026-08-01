"""Configuration parsing, validation, and provisioning helpers for the CLI."""

from __future__ import annotations

import glob
import os
import posixpath
import re
import shutil
import sys
from collections.abc import Callable
from pathlib import Path

import click


def load_toml_file(path: Path) -> dict:
    """Load a TOML file without install-registry fallbacks."""
    if sys.version_info >= (3, 11):
        import tomllib
    else:
        import tomli as tomllib

    with path.open("rb") as stream:
        return tomllib.load(stream)


def write_toml_file(path: Path, data: dict) -> None:
    import tomli_w

    path.write_text(tomli_w.dumps(data), encoding="utf-8")


def load_toml_value(value: str):
    if sys.version_info >= (3, 11):
        import tomllib
    else:
        import tomli as tomllib

    return tomllib.loads(f"value = {value}")["value"]


def parse_config_value(raw: str):
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
        return load_toml_value(value)
    except Exception:
        return raw


def path_to_config_string(path: Path) -> str:
    """Write paths with forward slashes so TOML examples work across shells."""
    return path.as_posix()


def has_glob(pattern: str) -> bool:
    return any(ch in pattern for ch in "*?[")


def glob_for_config_path(pattern: str, config_path: Path) -> list[str]:
    glob_path = Path(pattern)
    if not glob_path.is_absolute():
        glob_path = config_path.parent / glob_path
    return glob.glob(str(glob_path), recursive="**" in pattern)


def collapse_expanded_access_log_paths(values: tuple[str, ...]) -> str | None:
    """Recover a wildcard when PowerShell expands an access-log glob."""
    if len(values) < 2:
        return None

    paths = [Path(value) for value in values]
    parent = paths[0].parent
    if any(path.parent != parent for path in paths):
        return None

    names = [path.name for path in paths]
    if all(re.match(r"^localhost_access_log\..+\.txt$", name) for name in names):
        return path_to_config_string(parent / "localhost_access_log.*.txt")

    prefix = os.path.commonprefix(names)
    suffix = os.path.commonprefix([name[::-1] for name in names])[::-1]
    if not prefix and not suffix:
        return None

    shortest = min(len(name) for name in names)
    if len(prefix) + len(suffix) >= shortest:
        suffix = suffix[: max(0, shortest - len(prefix) - 1)]

    return path_to_config_string(parent / f"{prefix}*{suffix}")


def normalize_config_set_value(key: str, values: tuple[str, ...]) -> tuple[str, str | None]:
    if not values:
        raise click.ClickException("Config value cannot be empty.")
    if len(values) == 1:
        return values[0], None

    if key == "website.log_config.access_log_path":
        collapsed = collapse_expanded_access_log_paths(values)
        if collapsed:
            return (
                collapsed,
                "Multiple paths were received; treating them as an expanded shell wildcard.",
            )

    raise click.ClickException(
        "Received multiple values. Quote the value, or use `anteumbra config access-log` for web access logs."
    )


def infer_access_log_server(access_log_path: str) -> str:
    lower = access_log_path.lower()
    if "localhost_access_log" in lower or "tomcat" in lower:
        return "tomcat"
    if "nginx" in lower:
        return "nginx"
    if "apache" in lower or "httpd" in lower:
        return "apache"
    return "custom"


def infer_tomcat_base(access_log_path: str) -> str | None:
    if not access_log_path:
        return None
    path = Path(access_log_path)
    if path.name.lower().startswith("localhost_access_log") and path.parent.name.lower() == "logs":
        return path_to_config_string(path.parent.parent)
    return None


def access_log_preset_path(
    server_type: str,
    log_path: str | None = None,
    base_path: str | None = None,
) -> str:
    server = server_type.lower()
    if log_path:
        return log_path
    if server == "nginx":
        return "/var/log/nginx/access.log"
    if server == "apache":
        return "/var/log/apache2/access.log"
    if server == "tomcat":
        if base_path:
            return path_to_config_string(Path(base_path) / "logs" / "localhost_access_log.*.txt")
        return posixpath.join("logs", "localhost_access_log.*.txt")
    if server == "custom":
        raise click.ClickException("Custom access-log setup requires --path or wizard input.")
    raise click.ClickException(f"Unsupported access-log server type: {server_type}")


def set_dotted_value(data: dict, dotted_key: str, value) -> None:
    parts = [part for part in dotted_key.split(".") if part]
    if not parts:
        raise click.ClickException("Config key cannot be empty.")
    node = data
    for part in parts[:-1]:
        child = node.setdefault(part, {})
        if not isinstance(child, dict):
            raise click.ClickException(f"Cannot set {dotted_key}: {part} is not a table.")
        node = child
    node[parts[-1]] = value


def get_dotted_value(data: dict, dotted_key: str, default=None):
    node = data
    for part in dotted_key.split("."):
        if not isinstance(node, dict) or part not in node:
            return default
        node = node[part]
    return node


def write_env_value(env_path: Path, key: str, value: str) -> None:
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


def secret_prompt(text: str, default: str = "") -> str:
    """Prompt for a secret, without blocking piped/non-interactive input."""
    return click.prompt(
        text,
        default=default,
        show_default=False,
        hide_input=sys.stdin.isatty(),
    )


def generate_deployment_credentials() -> tuple[str, str, str]:
    """Return a plaintext admin password, its hash, and a session secret."""
    import secrets
    import string

    from werkzeug.security import generate_password_hash

    password = "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(16))
    return password, generate_password_hash(password), secrets.token_urlsafe(48)


def write_generated_env(env_file: Path) -> str:
    """Create a complete deployment .env and return the admin password."""
    password, password_hash, secret_key = generate_deployment_credentials()
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


def create_config_template(
    target: Path,
    *,
    find_config_template: Callable[[], Path | None],
    ensure_default_site_dir: Callable[[Path], Path],
    package_dir: Callable[[], Path],
    overwrite: bool | None = None,
) -> str | None:
    """Generate config.toml, .env, default site dir, and bundled rules."""
    template = find_config_template()
    target.parent.mkdir(parents=True, exist_ok=True)

    if not template:
        click.echo(
            "No bundled config.toml template found. Reinstall the anteumbra package.", err=True
        )
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
    site_dir = ensure_default_site_dir(target.parent)
    click.echo(f"Default website directory ready at {site_dir}")

    env_file = target.parent / ".env"
    if (
        not env_file.exists()
        or overwrite is True
        or click.confirm(f"{env_file} already exists. Overwrite?")
    ):
        password = write_generated_env(env_file)
        click.echo(f".env written to {env_file}")
        click.echo("  Admin username: admin")
        click.echo(f"  Admin password: {password}")
        click.echo("  (fill in email/WeChat fields to enable notifications)")
    else:
        password = None

    rules_src = None
    for candidate in [template.parent / "rules", package_dir() / "rules"]:
        if candidate.is_dir():
            rules_src = candidate
            break

    rules_dst = target.parent / "rules"
    if rules_src and not rules_dst.exists():
        shutil.copytree(rules_src, rules_dst)
        click.echo(f"YARA rules copied to {rules_dst}")
    elif rules_src and rules_dst.exists():
        click.echo(f"YARA rules already exist at {rules_dst} (skipped)")
    else:
        click.echo("Warning: YARA rules source not found; rules will be unavailable until added")
        click.echo("  You can manually copy rules/ from the Anteumbra repository")

    click.echo("Edit config.toml to configure websites, WAF, notifications, etc.")
    return password


def validate_config_file(config_path: Path) -> tuple[list[str], list[str]]:
    from ipaddress import ip_network

    from anteumbra.application.runtime_health_service import assess_runtime_capabilities
    from anteumbra.domain.site import SiteIdentity
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
    elif isinstance(raw_websites, list) and all(isinstance(item, dict) for item in raw_websites):
        websites = raw_websites
    else:
        errors.append("[website] must be a table or an array of tables.")
        websites = []

    enabled_websites = 0
    site_ids: set[str] = set()
    for index, website in enumerate(websites, start=1):
        label = "[website]" if len(websites) == 1 else f"[[website]] #{index}"
        site_name = str(website.get("name", "")).strip()
        valid_site_name = not (
            not site_name or site_name in {".", ".."} or "/" in site_name or "\\" in site_name
        )
        if not valid_site_name:
            errors.append(f"{label}.name is required and must not contain path separators.")

        raw_site_id = website.get("id")
        if raw_site_id is None or not str(raw_site_id).strip():
            raw_site_id = website.get("site_id")
        explicit_site_id = raw_site_id is not None and bool(str(raw_site_id).strip())
        try:
            identity = SiteIdentity.from_values(
                str(raw_site_id) if explicit_site_id else None,
                site_name if valid_site_name else str(raw_site_id or "site"),
            )
        except ValueError as exc:
            errors.append(f"{label}.id is invalid: {exc}")
        else:
            if not explicit_site_id:
                warnings.append(
                    f"{label}.id is missing; it is currently derived as "
                    f"{identity.site_id!r} from name. Add an explicit stable ID "
                    "before renaming the site."
                )
            if identity.site_id == "legacy":
                errors.append(f"{label}.id 'legacy' is reserved for unassigned records.")
            elif identity.site_id in site_ids:
                errors.append(f"Duplicate website.id: {identity.site_id}")
            else:
                site_ids.add(identity.site_id)

        if not website.get("enabled", True):
            continue
        enabled_websites += 1

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
            elif has_glob(access_log):
                if not glob_for_config_path(access_log, config_path):
                    errors.append(f"Access log wildcard has no matches ({label}): {access_log}")
            else:
                log_path = Path(access_log)
                if not log_path.is_absolute():
                    log_path = config_path.parent / log_path
                if not log_path.exists():
                    errors.append(f"Access log path does not exist ({label}): {log_path.resolve()}")

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
        "auto",
        "true",
        "false",
        "yes",
        "no",
        "on",
        "off",
        "1",
        "0",
    }:
        errors.append("[web_admin].session_cookie_secure must be true, false, or 'auto'.")
    if web_admin.get("trusted_proxy_ips") and secure_cookie is False:
        warnings.append(
            "Trusted proxy is configured while session_cookie_secure=false; HTTPS session cookies are not protected."
        )

    security = cfg.get("security", {})
    secret = security.get("secret_key", "") if isinstance(security, dict) else ""
    if not secret or secret in {"change_this_to_a_random_32_char_string", "YOUR_SECRET_KEY_HERE"}:
        warnings.append("ANTEUMBRA_SECRET_KEY is not customized.")

    waf_source = cfg.get("waf_source", {})
    if isinstance(waf_source, dict) and waf_source.get("enabled"):
        if not str(waf_source.get("url", "")).strip():
            errors.append("WAF source is enabled but [waf_source].url is empty.")

    warnings.extend(warning["message"] for warning in assess_runtime_capabilities(cfg)["warnings"])
    return errors, warnings
