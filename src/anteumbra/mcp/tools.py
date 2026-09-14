"""The MCP tool surface: one declared spec per tool, one implementation per tool.

Two rules shape this module:

* **The declaration is testable.** :data:`READ_ONLY_TOOLS` and
  :data:`WRITE_TOOLS` name every tool, its parameters, and whether it mutates.
  A test asserts that the declared parameters match the handler's real
  signature, so the advertised schema cannot drift from the behaviour.
* **Mutating tools exist only under ``--allow-write``.** They are not built at
  all in read-only mode, so they cannot appear in a client's tool list.
"""

from __future__ import annotations

import os
import re
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib import request as urlrequest

import psutil

from anteumbra.mcp import discovery
from anteumbra.mcp.instance import Instance

# ── declarations ─────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class ToolParameter:
    """One declared tool parameter."""

    name: str
    type: str
    required: bool = False
    description: str = ""


@dataclass(frozen=True, slots=True)
class ToolSpec:
    """Everything a client is told about one tool before calling it."""

    name: str
    summary: str
    parameters: tuple[ToolParameter, ...] = ()
    write: bool = False


@dataclass(frozen=True, slots=True)
class BoundTool:
    """A declared spec paired with its implementation for one instance."""

    spec: ToolSpec
    function: Callable[..., dict[str, Any]]

    @property
    def name(self) -> str:
        return self.spec.name


READ_ONLY_TOOLS: tuple[ToolSpec, ...] = (
    ToolSpec(
        name="get_status",
        summary=(
            "Report whether Anteumbra is running for this instance, its version, admin URL, "
            "uptime, health endpoint and how many sites are monitored. Call this first."
        ),
    ),
    ToolSpec(
        name="list_sites",
        summary=(
            "List every configured site with its stable id, name, path, port, enabled flag, "
            "whether the port is reachable, and whether the site serves JSP files."
        ),
        parameters=(
            ToolParameter("include_disabled", "boolean", False, "Include sites with enabled=false."),
            ToolParameter("probe_ports", "boolean", False, "TCP-connect each port to test it."),
        ),
    ),
    ToolSpec(
        name="get_config",
        summary=(
            "Return the effective configuration with every password, token, hash and key "
            "replaced by ***REDACTED***. Optionally limit the result to one section."
        ),
        parameters=(
            ToolParameter("section", "string", False, "Dotted prefix, e.g. 'notifier' or 'web_admin'."),
        ),
    ),
    ToolSpec(
        name="validate_config",
        summary=(
            "Run Anteumbra's own config validation and return exactly what "
            "`anteumbra config validate` prints, plus structured errors and warnings."
        ),
    ),
    ToolSpec(
        name="list_detections",
        summary=(
            "List detection records from the registry, newest first, filtered by site and status. "
            "Status is one of active, quarantined, missing, false_positive, deleted, all."
        ),
        parameters=(
            ToolParameter("site_id", "string", False, "Restrict to one site id."),
            ToolParameter("status", "string", False, "active (default), quarantined, missing, false_positive, deleted, all."),
            ToolParameter("limit", "integer", False, "Maximum rows, 1-500 (default 50)."),
            ToolParameter("offset", "integer", False, "Rows to skip for paging."),
            ToolParameter("include_false_positive", "boolean", False, "Include reviewed false positives."),
        ),
    ),
    ToolSpec(
        name="list_quarantine",
        summary=(
            "List quarantined files with their quarantine id, original path, rule and status. "
            "File contents are never returned."
        ),
        parameters=(
            ToolParameter("site_id", "string", False, "Restrict to one site id."),
            ToolParameter("status", "string", False, "quarantined, restored or deleted."),
            ToolParameter("limit", "integer", False, "Maximum rows, 1-500 (default 50)."),
            ToolParameter("offset", "integer", False, "Rows to skip for paging."),
        ),
    ),
    ToolSpec(
        name="list_sites_summary",
        summary=(
            "Per-site overview for a report: site identity, monitoring state, detection counts "
            "by status, quarantine counts and the newest detection time."
        ),
    ),
    ToolSpec(
        name="list_listening_ports",
        summary=(
            "List local TCP listening ports with the owning process name, from the operating "
            "system's connection table. Read-only and bounded."
        ),
        parameters=(
            ToolParameter("max_results", "integer", False, "Maximum rows (default 200)."),
        ),
    ),
    ToolSpec(
        name="discover_web_services",
        summary=(
            "List listening ports that look like web services, with the owning process and, when "
            "the OS states it, the document root. Use this to propose what to monitor. "
            "Set probe_http=true only with the user's consent: it sends a request the site's "
            "access log will record."
        ),
        parameters=(
            ToolParameter("max_results", "integer", False, "Maximum candidates (default 25)."),
            ToolParameter("probe_http", "boolean", False, "Send one HEAD request per candidate (default false)."),
            ToolParameter("include_runtimes", "boolean", False, "Include generic java/python/node listeners."),
        ),
    ),
)


WRITE_TOOLS: tuple[ToolSpec, ...] = (
    ToolSpec(
        name="add_site",
        summary=(
            "Add one monitored site to config.toml, then revalidate. Requires --allow-write. "
            "Ask the user for the path and port first: a wrong path is a validation error."
        ),
        parameters=(
            ToolParameter("name", "string", True, "Human-readable site name; must not contain path separators."),
            ToolParameter("path", "string", True, "Absolute path of the web root to watch."),
            ToolParameter("port", "integer", True, "TCP port the site is served on."),
            ToolParameter("site_id", "string", False, "Stable lowercase id; derived from name when omitted."),
            ToolParameter("enabled", "boolean", False, "Monitor this site now (default true)."),
            ToolParameter("log_monitor_enabled", "boolean", False, "Also analyse the web access log."),
            ToolParameter("access_log_path", "string", False, "Access log file or wildcard, e.g. logs/access.log."),
            ToolParameter("create_directory", "boolean", False, "Create the directory when it does not exist."),
        ),
        write=True,
    ),
    ToolSpec(
        name="update_site",
        summary=(
            "Change one field of an existing site, matched by stable id, then revalidate. "
            "The id itself cannot be changed. Requires --allow-write."
        ),
        parameters=(
            ToolParameter("site_id", "string", True, "Stable id of the site to update."),
            ToolParameter("name", "string", False, "New display name."),
            ToolParameter("path", "string", False, "New web root path."),
            ToolParameter("port", "integer", False, "New port."),
            ToolParameter("enabled", "boolean", False, "Enable or disable the site."),
            ToolParameter("log_monitor_enabled", "boolean", False, "Enable or disable access log analysis."),
            ToolParameter("access_log_path", "string", False, "Access log file or wildcard."),
        ),
        write=True,
    ),
    ToolSpec(
        name="disable_site",
        summary=(
            "Stop monitoring one site by setting enabled=false, keeping its id and history, "
            "then revalidate. Requires --allow-write."
        ),
        parameters=(
            ToolParameter("site_id", "string", True, "Stable id of the site to disable."),
        ),
        write=True,
    ),
    ToolSpec(
        name="set_config_value",
        summary=(
            "Set one dotted config key exactly as `anteumbra config set` does, then revalidate. "
            "Requires --allow-write. Never use this for secrets; use set_env_value."
        ),
        parameters=(
            ToolParameter("key", "string", True, "Dotted key, e.g. notifier.enabled or website.port."),
            ToolParameter("value", "string", True, "Value parsed like the CLI: true/false, integer, float, TOML literal, else string."),
        ),
        write=True,
    ),
    ToolSpec(
        name="set_env_value",
        summary=(
            "Write one secret to the instance .env file (never config.toml), then revalidate. "
            "Requires --allow-write. The value is never echoed back. Changing .env needs a restart."
        ),
        parameters=(
            ToolParameter("key", "string", True, "ANTEUMBRA_* or CLOUDFLARE_* variable name."),
            ToolParameter("value", "string", True, "The secret the user pasted, e.g. a mail authorization code."),
        ),
        write=True,
    ),
    ToolSpec(
        name="run_memory_shell_probe",
        summary=(
            "Deploy Anteumbra's own JSP probe into one site to enumerate memory-resident servlet "
            "components, then delete it. Requires --allow-write AND a stopped instance, because a "
            "running monitor would report Anteumbra's own probe as a new file."
        ),
        parameters=(
            ToolParameter("site_id", "string", True, "Stable id of the site to probe."),
        ),
        write=True,
    ),
)


# ── shared helpers ───────────────────────────────────────────

JSP_SUFFIXES = (".jsp", ".jspx", ".jspf", ".jsw", ".jsv")
_JSP_SCAN_BUDGET = 400
_JSP_SCAN_DEPTH = 4
MAX_ROWS = 500
DEFAULT_ROWS = 50

DETECTION_STATUSES = ("active", "quarantined", "missing", "false_positive", "deleted", "all")

ENV_KEY_PATTERN = re.compile(r"^(?:ANTEUMBRA|CLOUDFLARE)_[A-Z0-9_]+$")
KNOWN_ENV_KEYS = (
    "ANTEUMBRA_PASSWORD_HASH",
    "ANTEUMBRA_SECRET_KEY",
    "ANTEUMBRA_EMAIL_USERNAME",
    "ANTEUMBRA_EMAIL_PASSWORD",
    "ANTEUMBRA_EMAIL_FROM",
    "ANTEUMBRA_EMAIL_TO",
    "ANTEUMBRA_WECHAT_API_KEY",
    "ANTEUMBRA_WAF_API_KEY",
    "CLOUDFLARE_API_TOKEN",
)


class ToolError(RuntimeError):
    """A tool call that cannot be served, reported to the client as an error."""


def _bounded(value: int, default: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return max(0, min(parsed, maximum))


def scan_for_jsp(root: Path) -> tuple[bool | None, str]:
    """Return whether a bounded scan of ``root`` finds a JSP file, and the evidence."""
    if not root.is_dir():
        return None, f"site path does not exist: {root}"
    budget = _JSP_SCAN_BUDGET
    queue: list[tuple[Path, int]] = [(root, 0)]
    seen = 0
    while queue and budget > 0:
        directory, depth = queue.pop(0)
        try:
            entries = list(os.scandir(directory))
        except OSError:
            continue
        for entry in entries:
            budget -= 1
            seen += 1
            if budget <= 0:
                break
            try:
                if entry.is_dir(follow_symlinks=False):
                    if depth + 1 < _JSP_SCAN_DEPTH:
                        queue.append((Path(entry.path), depth + 1))
                    continue
            except OSError:
                continue
            if Path(entry.name).suffix.lower() in JSP_SUFFIXES:
                return True, f"found {entry.name} under the site root"
    if budget <= 0:
        return False, f"no JSP among the first {seen} entries; the scan was truncated"
    return False, f"no JSP file among {seen} entries under the site root"


def deployment_context(root: Path) -> str:
    """Describe whether the site root looks like a deployed servlet context."""
    if not root.is_dir():
        return "unknown"
    if (root / "WEB-INF" / "web.xml").is_file():
        return "site root is a deployed context (WEB-INF/web.xml)"
    try:
        contexts = [
            entry.name
            for entry in sorted(root.iterdir())
            if entry.is_dir() and (entry / "WEB-INF" / "web.xml").is_file()
        ]
    except OSError:
        return "unknown"
    if len(contexts) == 1:
        return f"single deployed context '{contexts[0]}'"
    if contexts:
        return f"{len(contexts)} deployed contexts: {', '.join(contexts[:5])}"
    return "no deployed servlet context found"


def site_rows(
    instance: Instance,
    config: dict[str, Any],
    *,
    include_disabled: bool,
    probe_ports: bool,
) -> list[dict[str, Any]]:
    """Build the per-site view shared by ``list_sites`` and ``list_sites_summary``."""
    from anteumbra.infrastructure.utils.platform_utils import check_port_reachable

    rows: list[dict[str, Any]] = []
    for website in instance.websites(config):
        enabled = bool(getattr(website, "enabled", False))
        if not enabled and not include_disabled:
            continue
        root = Path(str(getattr(website, "path", "")))
        port = int(getattr(website, "port", 0) or 0)
        jsp, evidence = scan_for_jsp(root) if enabled else (None, "site is disabled")
        log_config = getattr(website, "log_config", None) or {}
        rows.append(
            {
                "site_id": str(getattr(website, "site_id", "")),
                "name": str(getattr(website, "name", "")),
                "path": str(root),
                "port": port,
                "enabled": enabled,
                "serves_jsp": jsp,
                "serves_jsp_evidence": evidence,
                "deployment_context": deployment_context(root) if enabled else "unknown",
                "log_monitor_enabled": bool(
                    log_config.get("log_monitor_enabled") if isinstance(log_config, dict) else False
                ),
                "reachable": (
                    check_port_reachable("127.0.0.1", port, timeout=1) if (probe_ports and port) else None
                ),
            }
        )
    return rows


def detection_status(record: dict[str, Any]) -> str:
    """Derive the operator-facing status of one registry record."""
    if record.get("quarantine_id"):
        return "quarantined"
    if record.get("deleted_at") and not record.get("missing_at"):
        return "deleted"
    if not record.get("file_exists", True) or record.get("missing_at"):
        return "missing"
    if record.get("marked_false_positive"):
        return "false_positive"
    return "active"


def detection_view(record: dict[str, Any]) -> dict[str, Any]:
    """Trim one registry record to the fields an agent should reason about."""
    return {
        "site_id": record.get("site_id"),
        "site_name": record.get("site_name"),
        "file_path": record.get("file_path"),
        "status": detection_status(record),
        "detected_at": record.get("detected_at"),
        "features": list(record.get("features") or []),
        "detection_source": record.get("detection_source"),
        "first_seen_ip": record.get("first_seen_ip"),
        "communication_count": record.get("communication_count", 0),
        "alerted": bool(record.get("alerted", False)),
        "file_exists": bool(record.get("file_exists", True)),
        "missing_at": record.get("missing_at"),
        "quarantine_id": record.get("quarantine_id"),
        "marked_false_positive": bool(record.get("marked_false_positive", False)),
        "content_hash": record.get("content_hash", ""),
    }


def site_resolver(instance: Instance) -> Callable[[str], tuple[str, str]]:
    """Return a memoized path-to-site resolver for one tool call."""
    provider = instance.config_provider()
    cache: dict[str, tuple[str, str]] = {}

    def resolve(file_path: str) -> tuple[str, str]:
        if file_path not in cache:
            identity = None
            if provider is not None:
                try:
                    identity = provider.resolve_site_identity(file_path)
                except Exception:  # noqa: BLE001 - an unresolvable path is not fatal
                    identity = None
            cache[file_path] = (identity.site_id, identity.site_name) if identity else ("", "")
        return cache[file_path]

    return resolve


def quarantine_view(
    resolve: Callable[[str], tuple[str, str]], record: dict[str, Any]
) -> dict[str, Any]:
    """Trim one quarantine record; path resolution never reads file content."""
    site_id = str(record.get("site_id") or "")
    site_name = str(record.get("site_name") or "")
    if not site_id:
        site_id, site_name = resolve(str(record.get("original_path") or ""))
    return {
        "quarantine_id": record.get("quarantine_id"),
        "site_id": site_id or None,
        "site_name": site_name or None,
        "original_path": record.get("original_path"),
        "quarantine_path": record.get("quarantine_path"),
        "rule_name": record.get("rule_name"),
        "features": list(record.get("features") or []),
        "file_size": record.get("file_size", 0),
        "status": record.get("status", "quarantined"),
        "quarantine_time": record.get("quarantine_time") or record.get("created_at"),
    }


def runtime_state(instance: Instance) -> dict[str, Any]:
    """Describe the runtime process owning this instance, without changing it."""
    from anteumbra.infrastructure.process_identity import (
        ProcessIdentityState,
        probe_process_identity,
        read_process_identity,
    )

    identity = read_process_identity(instance.pid_path)
    if identity is None:
        return {
            "running": False,
            "state": "stopped" if not instance.pid_path.exists() else "unknown",
            "pid": None,
            "uptime_seconds": None,
            "memory_mb": None,
        }
    state = probe_process_identity(identity, instance.root)
    running = state is ProcessIdentityState.RUNNING
    uptime: float | None = None
    memory: float | None = None
    if running:
        try:
            process = psutil.Process(identity.pid)
            uptime = round(time.time() - process.create_time(), 1)
            memory = round(process.memory_info().rss / 1024 / 1024, 1)
        except Exception:  # noqa: BLE001 - optional process statistics
            pass
    return {
        "running": running,
        "state": state.value,
        "pid": identity.pid,
        "uptime_seconds": uptime,
        "memory_mb": memory,
    }


def admin_url(config: dict[str, Any]) -> str:
    """Return the local admin URL for this instance."""
    web_admin = config.get("web_admin", {})
    if not isinstance(web_admin, dict):
        web_admin = {}
    host = str(web_admin.get("host") or "127.0.0.1")
    if host in {"0.0.0.0", "::", "[::]"}:
        host = "127.0.0.1"
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    port = int(web_admin.get("port", 8080) or 8080)
    return f"http://{host}:{port}/admin"


def memory_shell_state(
    instance: Instance, config: dict[str, Any], *, allow_write: bool | None = None
) -> dict[str, Any]:
    """Report whether the memory-shell probe tool may be exposed, and why not."""
    write_mode = instance.allow_write if allow_write is None else bool(allow_write)
    plugins = config.get("plugins", {})
    section = plugins.get("memory_shell_probe", {}) if isinstance(plugins, dict) else {}
    if not isinstance(section, dict):
        section = {}
    enabled = section.get("enabled", True)
    if isinstance(enabled, str):
        enabled = enabled.strip().lower() in {"1", "true", "yes", "on"}
    if not enabled:
        return {"available": False, "reason": "plugins.memory_shell_probe.enabled is false"}
    if not write_mode:
        return {"available": False, "reason": "server started read-only (no --allow-write)"}
    if runtime_state(instance)["running"]:
        return {
            "available": False,
            "reason": (
                "the instance is running: a live monitor would report Anteumbra's own probe as a "
                "new file. Use the /admin/memory-shell page of the running instance instead."
            ),
        }
    return {"available": True, "reason": ""}


# ── site mutation helper ─────────────────────────────────────


def _website_entries(data: dict[str, Any]) -> tuple[list[dict[str, Any]], bool]:
    """Return the ``website`` entries and whether the source used ``[[website]]``."""
    raw = data.get("website")
    if isinstance(raw, list):
        return [dict(item) for item in raw if isinstance(item, dict)], True
    if isinstance(raw, dict):
        return [dict(raw)], False
    return [], False


def _store_website_entries(
    data: dict[str, Any], entries: list[dict[str, Any]], was_list: bool
) -> None:
    data["website"] = entries if (was_list or len(entries) > 1) else entries[0]


def _site_index_by_id(entries: list[dict[str, Any]], site_id: str) -> int | None:
    for index, entry in enumerate(entries):
        current = str(entry.get("id") or entry.get("site_id") or "").strip().lower()
        if current == site_id:
            return index
        if not current:
            from anteumbra.domain.site import derive_site_id

            if derive_site_id(str(entry.get("name") or "")) == site_id:
                return index
    return None


def _normalize_site_fields(entry: dict[str, Any], *, create_directory: bool) -> list[str]:
    """Validate and normalize one site entry; returns advisory notes."""
    notes: list[str] = []
    if create_directory:
        root = Path(str(entry.get("path") or "")).expanduser()
        if str(entry.get("path") or "").strip() and not root.is_dir():
            root.mkdir(parents=True, exist_ok=True)
            notes.append(f"created directory {root}")
    elif str(entry.get("path") or "").strip():
        root = Path(str(entry["path"])).expanduser()
        if not root.is_dir():
            notes.append(
                f"{root} does not exist yet; validation will fail until it does. "
                "Pass create_directory=true to create it."
            )
    return notes


def _mutate_config(instance: Instance, mutate: Callable[[dict[str, Any]], list[str]]) -> dict[str, Any]:
    """Apply one edit through the CLI's TOML helpers, write, and revalidate."""
    from anteumbra.cli import config_support

    if not instance.has_config:
        raise ToolError(
            f"No config.toml at {instance.config_path}. Create the runtime first with "
            f'`anteumbra install "{instance.root}"` and configure it with '
            f'`anteumbra --home "{instance.root}" config wizard`.'
        )

    notes: list[str] = []
    try:
        data = config_support.load_toml_file(instance.config_path)
    except Exception as exc:  # noqa: BLE001 - surfaced as a tool error
        raise ToolError(f"Cannot parse {instance.config_path}: {exc}") from exc

    notes.extend(mutate(data))
    try:
        config_support.write_toml_file(instance.config_path, data)
    except Exception as exc:  # noqa: BLE001 - surfaced as a tool error
        raise ToolError(f"Cannot write {instance.config_path}: {exc}") from exc

    instance.forget_secrets()
    validation = instance.validate()
    return {
        "written": True,
        "valid": validation["valid"],
        "config_path": validation["config_path"],
        "validation": validation,
        "errors": validation["errors"],
        "warnings": validation["warnings"],
        "notes": notes,
    }


# ── tool implementations ─────────────────────────────────────


def build_tools(instance: Instance, *, allow_write: bool = False) -> tuple[BoundTool, ...]:
    """Build the tool set for one instance, honouring the write gate."""

    # ── read-only ────────────────────────────────────────────
    def get_status() -> dict[str, Any]:
        """Report whether Anteumbra is running, its version, admin URL and sites."""
        from anteumbra import __version__

        config, config_error = instance.load_config()
        state = runtime_state(instance)
        rows = site_rows(instance, config, include_disabled=True, probe_ports=False)
        enabled = [row for row in rows if row["enabled"]]
        health: dict[str, Any] = {"url": None, "reachable": None}
        if config:
            from anteumbra.cli import runtime_support

            web_admin = config.get("web_admin", {})
            host = str((web_admin or {}).get("host") or "127.0.0.1")
            port = int((web_admin or {}).get("port", 8080) or 8080)
            health["url"] = f"http://{host}:{port}/api/v1/health"
            health["reachable"] = runtime_support.service_ready(
                host, port, 0.5, urlopen=urlrequest.urlopen
            )
        return instance.redact(
            {
                "instance_root": str(instance.root),
                "config_path": str(instance.config_path),
                "config_exists": instance.has_config,
                "config_error": config_error,
                "version": __version__,
                "admin_url": admin_url(config) if config else None,
                "data_dir": str(instance.data_dir(config)),
                "log_dir": str(instance.log_dir(config)),
                "pid_path": str(instance.pid_path),
                "runtime": state,
                "health": health,
                "monitored_sites": {
                    "enabled": len(enabled),
                    "configured": len(rows),
                    "site_ids": [row["site_id"] for row in enabled],
                },
                "memory_shell_probe_tool": memory_shell_state(instance, config),
                "allow_write": instance.allow_write,
            }
        )

    def list_sites(include_disabled: bool = True, probe_ports: bool = True) -> dict[str, Any]:
        """List configured sites with identity, path, port, reachability and JSP support."""
        config, config_error = instance.load_config()
        rows = site_rows(
            instance,
            config,
            include_disabled=bool(include_disabled),
            probe_ports=bool(probe_ports),
        )
        return instance.redact(
            {
                "config_path": str(instance.config_path),
                "config_error": config_error,
                "sites": rows,
                "count": len(rows),
            }
        )

    def get_config(section: str | None = None) -> dict[str, Any]:
        """Return the effective configuration with all credentials redacted."""
        config, config_error = instance.load_config()
        if config_error:
            raise ToolError(config_error)
        selected: Any = config
        if section:
            from anteumbra.cli import config_support

            selected = config_support.get_dotted_value(config, section, None)
            if selected is None:
                raise ToolError(
                    f"No such configuration section: {section!r}. Call get_config without a "
                    "section to see the available keys."
                )
        return instance.redact(
            {
                "config_path": str(instance.config_path),
                "section": section,
                "config": instance.redacted_config(selected),
            }
        )

    def validate_config() -> dict[str, Any]:
        """Run Anteumbra's config validation and return what the CLI prints."""
        return instance.redact(instance.validate())

    def list_detections(
        site_id: str | None = None,
        status: str = "active",
        limit: int = DEFAULT_ROWS,
        offset: int = 0,
        include_false_positive: bool = False,
    ) -> dict[str, Any]:
        """List detection records filtered by site and status, newest first."""
        from anteumbra.domain.registry_records import project_records

        wanted = (status or "active").strip().lower()
        if wanted not in DETECTION_STATUSES:
            raise ToolError(
                f"Unknown status {status!r}. Use one of: {', '.join(DETECTION_STATUSES)}."
            )
        config, _ = instance.load_config()
        read = instance.registry_records(config)
        rows = project_records(
            read["records"],
            include_deleted=wanted in {"all", "deleted", "missing", "quarantined"},
            include_false_positive=bool(include_false_positive) or wanted in {"all", "false_positive"},
            site_id=str(site_id).strip().lower() if site_id else None,
        )
        views = [detection_view(row) for row in rows]
        if wanted != "all":
            views = [view for view in views if view["status"] == wanted]
        page = _bounded(limit, DEFAULT_ROWS, MAX_ROWS)
        start = _bounded(offset, 0, 1_000_000)
        return instance.redact(
            {
                "source": read["source"],
                "note": read["note"],
                "site_id": site_id,
                "status": wanted,
                "total_matching": len(views),
                "detections": views[start : start + page],
            }
        )

    def list_quarantine(
        site_id: str | None = None,
        status: str | None = None,
        limit: int = DEFAULT_ROWS,
        offset: int = 0,
    ) -> dict[str, Any]:
        """List quarantine records without ever returning file content."""
        config, _ = instance.load_config()
        read = instance.quarantine_records(config)
        wanted = str(status).strip().lower() if status else None
        if wanted and wanted not in {"quarantined", "restored", "deleted"}:
            raise ToolError("Unknown status. Use quarantined, restored or deleted.")
        wanted_site = str(site_id).strip().lower() if site_id else None
        resolve = site_resolver(instance)
        views = [
            quarantine_view(resolve, record)
            for record in sorted(
                read["records"],
                key=lambda item: str(item.get("quarantine_time") or item.get("created_at") or ""),
                reverse=True,
            )
        ]
        if wanted:
            views = [view for view in views if view["status"] == wanted]
        if wanted_site:
            views = [view for view in views if (view["site_id"] or "") == wanted_site]
        page = _bounded(limit, DEFAULT_ROWS, MAX_ROWS)
        start = _bounded(offset, 0, 1_000_000)
        return instance.redact(
            {
                "source": read["source"],
                "note": read["note"],
                "site_id": site_id,
                "status": wanted,
                "total_matching": len(views),
                "quarantine": views[start : start + page],
            }
        )

    def list_sites_summary() -> dict[str, Any]:
        """Summarize each site for a report: monitoring state and detection counts."""
        from anteumbra.domain.registry_records import project_records

        config, config_error = instance.load_config()
        rows = site_rows(instance, config, include_disabled=True, probe_ports=True)
        records = project_records(
            instance.registry_records(config)["records"],
            include_deleted=True,
            include_false_positive=True,
            site_id=None,
        )
        quarantine = instance.quarantine_records(config)["records"]
        resolve = site_resolver(instance)
        empty_bucket = {
            "detections": 0,
            "active": 0,
            "quarantined": 0,
            "missing": 0,
            "false_positive": 0,
            "last_detection_at": None,
            "quarantine_records": 0,
            "quarantined_files": 0,
        }
        by_site: dict[str, dict[str, Any]] = {}
        for record in records:
            key = str(record.get("site_id") or "legacy")
            bucket = by_site.setdefault(key, dict(empty_bucket))
            bucket["detections"] += 1
            status = detection_status(record)
            bucket[status] = bucket.get(status, 0) + 1
            detected_at = str(record.get("detected_at") or "")
            if detected_at and (
                bucket["last_detection_at"] is None or detected_at > bucket["last_detection_at"]
            ):
                bucket["last_detection_at"] = detected_at
        for record in quarantine:
            key = str(record.get("site_id") or "")
            if not key:
                key = resolve(str(record.get("original_path") or ""))[0] or "legacy"
            bucket = by_site.setdefault(key, dict(empty_bucket))
            bucket["quarantine_records"] += 1
            if record.get("status", "quarantined") == "quarantined":
                bucket["quarantined_files"] += 1

        summaries = []
        for row in rows:
            merged = {**empty_bucket, **by_site.get(row["site_id"], {})}
            summaries.append({**row, **merged, "watched": bool(row["enabled"])})
        orphaned = sorted(set(by_site) - {row["site_id"] for row in rows})
        return instance.redact(
            {
                "config_path": str(instance.config_path),
                "config_error": config_error,
                "sites": summaries,
                "totals": {
                    "sites_configured": len(rows),
                    "sites_enabled": sum(1 for row in rows if row["enabled"]),
                    "detections": sum(item["detections"] for item in summaries),
                    "active": sum(item["active"] for item in summaries),
                    "quarantined_files": sum(item["quarantined_files"] for item in summaries),
                },
                "records_without_a_configured_site": orphaned,
            }
        )

    def list_listening_ports(max_results: int = 200) -> dict[str, Any]:
        """List local TCP listening ports and their owning processes."""
        return instance.redact(
            discovery.list_listening_ports(max_results=_bounded(max_results, 200, 1000))
        )

    def discover_web_services(
        max_results: int = 25,
        probe_http: bool = False,
        include_runtimes: bool = True,
    ) -> dict[str, Any]:
        """List listening ports that look like web services, with document roots when known."""
        return instance.redact(
            discovery.discover_web_services(
                max_results=_bounded(max_results, 25, 200),
                probe_http=bool(probe_http),
                include_runtimes=bool(include_runtimes),
            )
        )

    bound = [
        BoundTool(spec, function)
        for spec, function in (
            (READ_ONLY_TOOLS[0], get_status),
            (READ_ONLY_TOOLS[1], list_sites),
            (READ_ONLY_TOOLS[2], get_config),
            (READ_ONLY_TOOLS[3], validate_config),
            (READ_ONLY_TOOLS[4], list_detections),
            (READ_ONLY_TOOLS[5], list_quarantine),
            (READ_ONLY_TOOLS[6], list_sites_summary),
            (READ_ONLY_TOOLS[7], list_listening_ports),
            (READ_ONLY_TOOLS[8], discover_web_services),
        )
    ]

    if not allow_write:
        return tuple(bound)

    # ── mutating (only under --allow-write) ──────────────────

    def add_site(
        name: str,
        path: str,
        port: int,
        site_id: str | None = None,
        enabled: bool = True,
        log_monitor_enabled: bool = False,
        access_log_path: str | None = None,
        create_directory: bool = False,
    ) -> dict[str, Any]:
        """Add one monitored site to config.toml and revalidate."""
        from anteumbra.domain.site import SiteIdentity

        clean_name = str(name or "").strip()
        if not clean_name or clean_name in {".", ".."} or "/" in clean_name or "\\" in clean_name:
            raise ToolError("name must be non-empty and must not contain path separators.")
        clean_path = str(path or "").strip()
        if not clean_path:
            raise ToolError("path is required: give the absolute web root the site serves.")
        try:
            clean_port = int(port)
        except (TypeError, ValueError) as exc:
            raise ToolError("port must be an integer between 1 and 65535.") from exc
        if not 1 <= clean_port <= 65535:
            raise ToolError("port must be between 1 and 65535.")
        try:
            identity = SiteIdentity.from_values(
                str(site_id).strip() if site_id else None, clean_name
            )
        except ValueError as exc:
            raise ToolError(f"Invalid site_id: {exc}") from exc
        if identity.site_id == "legacy":
            raise ToolError("site_id 'legacy' is reserved for unassigned records.")

        entry: dict[str, Any] = {
            "name": clean_name,
            "id": identity.site_id,
            "path": clean_path,
            "port": clean_port,
            "enabled": bool(enabled),
        }
        if log_monitor_enabled:
            entry["log_config"] = {
                "log_monitor_enabled": True,
                "access_log_path": str(access_log_path or ""),
            }

        payload: dict[str, Any] = {}

        def mutate(data: dict[str, Any]) -> list[str]:
            entries, was_list = _website_entries(data)
            if _site_index_by_id(entries, identity.site_id) is not None:
                raise ToolError(
                    f"Site id {identity.site_id!r} already exists. Use update_site to change it."
                )
            notes = _normalize_site_fields(entry, create_directory=bool(create_directory))
            if access_log_path and not log_monitor_enabled:
                notes.append(
                    "access_log_path was ignored because log_monitor_enabled is false; "
                    "call update_site with log_monitor_enabled=true to enable it."
                )
            entries.append(entry)
            _store_website_entries(data, entries, was_list)
            payload["site"] = entry
            return notes

        result = _mutate_config(instance, mutate)
        return instance.redact({"site": payload.get("site"), **result})

    def update_site(
        site_id: str,
        name: str | None = None,
        path: str | None = None,
        port: int | None = None,
        enabled: bool | None = None,
        log_monitor_enabled: bool | None = None,
        access_log_path: str | None = None,
    ) -> dict[str, Any]:
        """Change fields of an existing site, matched by stable id, and revalidate."""
        wanted = str(site_id or "").strip().lower()
        if not wanted:
            raise ToolError("site_id is required.")
        if port is not None and not 1 <= int(port) <= 65535:
            raise ToolError("port must be between 1 and 65535.")

        payload: dict[str, Any] = {}

        def mutate(data: dict[str, Any]) -> list[str]:
            entries, was_list = _website_entries(data)
            index = _site_index_by_id(entries, wanted)
            if index is None:
                known = ", ".join(
                    str(entry.get("id") or entry.get("name")) for entry in entries
                ) or "none"
                raise ToolError(f"No site with id {wanted!r}. Configured sites: {known}.")
            entry = entries[index]
            if name is not None:
                clean = str(name).strip()
                if not clean or "/" in clean or "\\" in clean or clean in {".", ".."}:
                    raise ToolError("name must be non-empty and must not contain path separators.")
                entry["name"] = clean
            if path is not None:
                clean_path = str(path).strip()
                if not clean_path:
                    raise ToolError("path must not be empty.")
                entry["path"] = clean_path
            if port is not None:
                entry["port"] = int(port)
            if enabled is not None:
                entry["enabled"] = bool(enabled)
            if log_monitor_enabled is not None:
                log_config = entry.get("log_config")
                if not isinstance(log_config, dict):
                    log_config = {}
                log_config["log_monitor_enabled"] = bool(log_monitor_enabled)
                entry["log_config"] = log_config
            if access_log_path is not None:
                log_config = entry.get("log_config")
                if not isinstance(log_config, dict):
                    log_config = {}
                log_config["access_log_path"] = str(access_log_path)
                entry["log_config"] = log_config
            entries[index] = entry
            _store_website_entries(data, entries, was_list)
            payload["site"] = entry
            return _normalize_site_fields(entry, create_directory=False)

        result = _mutate_config(instance, mutate)
        return instance.redact({"site": payload.get("site"), **result})

    def disable_site(site_id: str) -> dict[str, Any]:
        """Stop monitoring one site by setting enabled=false, then revalidate."""
        wanted = str(site_id or "").strip().lower()
        if not wanted:
            raise ToolError("site_id is required.")

        payload: dict[str, Any] = {}

        def mutate(data: dict[str, Any]) -> list[str]:
            entries, was_list = _website_entries(data)
            index = _site_index_by_id(entries, wanted)
            if index is None:
                raise ToolError(f"No site with id {wanted!r}.")
            entries[index]["enabled"] = False
            _store_website_entries(data, entries, was_list)
            payload["site"] = entries[index]
            if not any(bool(entry.get("enabled", True)) for entry in entries):
                return [
                    "No site is enabled now; `anteumbra config validate` fails while every site "
                    "is disabled. Re-enable one before restarting the service."
                ]
            return [f"site {wanted!r} is now disabled; it keeps its id, records and history."]

        result = _mutate_config(instance, mutate)
        return instance.redact({"site": payload.get("site"), **result})

    def set_config_value(key: str, value: str) -> dict[str, Any]:
        """Set one dotted config key through `anteumbra config set`, then revalidate."""
        clean_key = str(key or "").strip()
        if not clean_key:
            raise ToolError("key is required, e.g. notifier.enabled.")
        result = instance.cli("config", "set", clean_key, str(value))
        validation = instance.validate()
        instance.forget_secrets()
        return instance.redact(
            {
                "ok": result.ok and validation["valid"],
                **result.as_dict(),
                "key": clean_key,
                "validation": validation,
                "errors": validation["errors"],
                "warnings": validation["warnings"],
            }
        )

    def set_env_value(key: str, value: str) -> dict[str, Any]:
        """Write one secret to the instance .env file, then revalidate."""
        clean_key = str(key or "").strip()
        if not ENV_KEY_PATTERN.fullmatch(clean_key):
            raise ToolError(
                "Only ANTEUMBRA_* and CLOUDFLARE_* variables may be written to .env. "
                f"Known keys: {', '.join(KNOWN_ENV_KEYS)}."
            )
        secret = str(value or "")
        if not secret:
            raise ToolError(
                "value is empty. Ask the user for the secret before calling this tool; "
                "never invent one."
            )
        result = instance.cli("config", "env", "set", clean_key, secret)
        instance.forget_secrets()
        validation = instance.validate()
        instance.forget_secrets()
        payload = result.as_dict()
        # The captured argv holds the secret; replace it rather than relying on
        # the redaction pass alone.
        payload["command"] = (
            f'anteumbra --home "{instance.root}" config env set {clean_key} ***'
        )
        return instance.redact(
            {
                "ok": result.ok and validation["valid"],
                **payload,
                "key": clean_key,
                "value_written": result.ok,
                "value_returned": False,
                "restart_required": result.ok,
                "validation": validation,
                "errors": validation["errors"],
                "warnings": validation["warnings"],
            }
        )

    def run_memory_shell_probe(site_id: str) -> dict[str, Any]:
        """Deploy Anteumbra's JSP probe into one site, read memory, and clean up."""
        wanted = str(site_id or "").strip().lower()
        if not wanted:
            raise ToolError("site_id is required.")
        config, config_error = instance.load_config()
        if config_error:
            raise ToolError(config_error)
        state = memory_shell_state(instance, config, allow_write=instance.allow_write)
        if not state["available"]:
            raise ToolError(f"The memory-shell probe is unavailable: {state['reason']}")
        provider = instance.config_provider()
        if provider is None:
            raise ToolError("The configuration could not be loaded, so the probe was not run.")

        from anteumbra.application.memory_shell_service import MemoryShellService
        from anteumbra.infrastructure.internal_artifacts import InMemoryInternalArtifactRegistry
        from anteumbra.infrastructure.memory_shell import MemoryShellProbeDeployer

        artifacts = InMemoryInternalArtifactRegistry()
        service = MemoryShellService(
            config_provider=provider,
            deployer=MemoryShellProbeDeployer(artifacts=artifacts),
            artifacts=artifacts,
        )
        outcome = service.run_probe(wanted, trigger="mcp", triggered_by="mcp")
        if outcome is None:
            raise ToolError("The probe did not run; check the instance log for details.")
        return instance.redact(
            {
                "memory_shell": outcome.as_dict(),
                "cleanup_required": bool(outcome.cleanup_error),
                "note": (
                    "The probe file was deployed into the site and removed again. A probe that "
                    "reports cleanup_error left a file behind: tell the user its path immediately."
                ),
            }
        )

    bound.extend(
        BoundTool(spec, function)
        for spec, function in (
            (WRITE_TOOLS[0], add_site),
            (WRITE_TOOLS[1], update_site),
            (WRITE_TOOLS[2], disable_site),
            (WRITE_TOOLS[3], set_config_value),
            (WRITE_TOOLS[4], set_env_value),
        )
    )
    if memory_shell_state(
        instance, instance.load_config()[0], allow_write=allow_write
    )["available"]:
        bound.append(BoundTool(WRITE_TOOLS[5], run_memory_shell_probe))
    return tuple(bound)


def call_tool(
    instance: Instance,
    name: str,
    arguments: dict[str, Any] | None = None,
    *,
    allow_write: bool = False,
) -> dict[str, Any]:
    """Invoke one tool in-process, the way a client would over the protocol."""
    tools = {tool.name: tool for tool in build_tools(instance, allow_write=allow_write)}
    tool = tools.get(str(name))
    if tool is None:
        available = ", ".join(sorted(tools)) or "none"
        raise ToolError(f"Unknown tool {name!r}. Available tools: {available}.")
    arguments = dict(arguments or {})
    declared = {parameter.name for parameter in tool.spec.parameters}
    unexpected = sorted(set(arguments) - declared)
    if unexpected:
        raise ToolError(
            f"Unexpected argument(s) for {name}: {', '.join(unexpected)}. "
            f"Accepted: {', '.join(sorted(declared)) or 'none'}."
        )
    missing = sorted(
        parameter.name
        for parameter in tool.spec.parameters
        if parameter.required and arguments.get(parameter.name) is None
    )
    if missing:
        raise ToolError(f"Missing required argument(s) for {name}: {', '.join(missing)}.")
    return tool.function(**arguments)


__all__ = [
    "BoundTool",
    "DETECTION_STATUSES",
    "READ_ONLY_TOOLS",
    "WRITE_TOOLS",
    "ToolError",
    "ToolParameter",
    "ToolSpec",
    "build_tools",
    "call_tool",
]
