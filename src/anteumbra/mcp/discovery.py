"""Find web services on the local machine, so an agent can propose what to watch.

Two bounded, read-only probes - no filesystem walk, no port sweep:

* the operating system's own connection table, via ``psutil`` (the dependency
  Anteumbra already uses), with a ``/proc/net/tcp`` fallback on Linux;
* for a candidate only, that process's name, command line and working
  directory, to name the document root when it can be derived.

Everything the platform genuinely cannot answer is reported as ``null`` with a
note rather than guessed at.
"""

from __future__ import annotations

import os
import socket
import sys
from pathlib import Path
from typing import Any
from urllib import error as urlerror
from urllib import request as urlrequest

import psutil

# Ports a web server listens on often enough to be worth promoting.
WEB_PORT_HINTS = frozenset(
    {
        80,
        81,
        88,
        443,
        591,
        3000,
        5000,
        7001,
        8000,
        8008,
        8080,
        8081,
        8088,
        8090,
        8180,
        8443,
        8888,
        9000,
        9080,
        9443,
        28080,
    }
)

# Process names that identify a web server on their own.
STRONG_PROCESS_HINTS = (
    "apache",
    "caddy",
    "httpd",
    "http.sys",
    "iisexpress",
    "lighttpd",
    "nginx",
    "openresty",
    "php-fpm",
    "tomcat",
    "traefik",
    "w3wp",
    "gunicorn",
    "uwsgi",
    "waitress",
)

# Runtimes that often - but not always - serve HTTP.
RUNTIME_PROCESS_HINTS = ("java", "javaw", "node", "python", "python3", "dotnet", "ruby", "php")

_DOCUMENT_ROOT_CANDIDATES = (
    "webapps",
    "www",
    "wwwroot",
    "htdocs",
    "html",
    "public_html",
    "public",
    "sites",
    "site",
)

HTTP_PROBE_TIMEOUT = 1.5
_MAX_PROCESS_INSPECTIONS = 40


def _process_name(process: psutil.Process) -> str:
    try:
        return str(process.name() or "")
    except (psutil.Error, OSError):
        return ""


def _process_cmdline(process: psutil.Process) -> list[str]:
    try:
        return [str(item) for item in process.cmdline()]
    except (psutil.Error, OSError):
        return []


def _process_cwd(process: psutil.Process) -> str | None:
    try:
        return str(process.cwd())
    except (psutil.Error, OSError):
        return None


def _matches(process_name: str, hints: tuple[str, ...]) -> bool:
    lowered = process_name.lower()
    return any(hint in lowered for hint in hints)


def _listening_sockets() -> tuple[list[tuple[str, int, int | None, str]], str]:
    """Return ``(address, port, pid, family)`` rows plus a platform note."""
    rows: list[tuple[str, int, int | None, str]] = []
    kinds = {socket.AF_INET: "ipv4", socket.AF_INET6: "ipv6"}
    try:
        connections = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, psutil.Error, OSError) as exc:
        return _listening_sockets_from_proc(), (
            f"psutil could not read the connection table ({type(exc).__name__}); "
            "fell back to the kernel tables, so owning process names are unavailable."
        )

    for connection in connections:
        if connection.status != psutil.CONN_LISTEN:
            continue
        address = connection.laddr
        if not address:
            continue
        rows.append(
            (
                str(address.ip),
                int(address.port),
                connection.pid,
                kinds.get(connection.family, "inet"),
            )
        )
    return rows, ""


def _listening_sockets_from_proc() -> list[tuple[str, int, int | None, str]]:
    """Linux fallback: read listening sockets from ``/proc/net``."""
    rows: list[tuple[str, int, int | None, str]] = []
    if not sys.platform.startswith("linux"):
        return rows
    for name, family in (("/proc/net/tcp", "ipv4"), ("/proc/net/tcp6", "ipv6")):
        try:
            text = Path(name).read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        for line in text.splitlines()[1:]:
            fields = line.split()
            if len(fields) < 4 or fields[3] != "0A":
                continue
            try:
                port = int(fields[1].split(":")[1], 16)
            except (IndexError, ValueError):
                continue
            rows.append(("0.0.0.0", port, None, family))
    return rows


def _service_guess(port: int) -> str:
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return ""


def _port_summary(port: int) -> dict[str, Any]:
    """Describe one listening port without touching the owning process."""
    return {
        "port": port,
        "service_guess": _service_guess(port),
        "known_web_port": port in WEB_PORT_HINTS,
    }


def list_listening_ports(max_results: int = 200) -> dict[str, Any]:
    """Return the local listening TCP ports with their owning process."""
    rows, note = _listening_sockets()
    rows.sort(key=lambda row: (row[1], row[0]))

    ports: list[dict[str, Any]] = []
    seen: set[tuple[str, int]] = set()
    names: dict[int, str] = {}
    unresolved = 0
    truncated = False
    for address, port, pid, family in rows:
        key = (address, port)
        if key in seen:
            continue
        seen.add(key)
        if len(ports) >= max(0, max_results):
            truncated = True
            break
        entry = {"address": address, "family": family, **_port_summary(port)}
        entry["pid"] = pid
        if pid is None:
            entry["process_name"] = None
            unresolved += 1
        else:
            if pid not in names:
                try:
                    names[pid] = _process_name(psutil.Process(pid))
                except (psutil.Error, OSError):
                    names[pid] = ""
            entry["process_name"] = names[pid] or None
        ports.append(entry)

    if unresolved:
        extra = (
            f"{unresolved} listener(s) have no readable owning process; run the agent with "
            "permission to inspect other users' processes to identify them."
            if os.name != "nt"
            else f"{unresolved} listener(s) expose no owning process (Windows requires an "
            "elevated agent for system-owned listeners)."
        )
        note = f"{note} {extra}".strip()
    return {
        "platform": sys.platform,
        "ports": ports,
        "count": len(ports),
        "truncated": truncated,
        "note": note,
    }


def _document_root(
    process_name: str,
    cmdline: list[str],
    cwd: str | None,
) -> tuple[str | None, str]:
    """Derive a document root when the command line or working directory states it."""
    for argument in cmdline:
        for prefix in ("-Dcatalina.base=", "-Dcatalina.home="):
            if argument.startswith(prefix):
                base = Path(argument[len(prefix) :].strip().strip('"'))
                webapps = base / "webapps"
                target = webapps if webapps.is_dir() else base
                return str(target), f"from {prefix.rstrip('=')} on the process command line"
    if cwd:
        base = Path(cwd)
        for candidate in _DOCUMENT_ROOT_CANDIDATES:
            child = base / candidate
            if child.is_dir():
                return str(child), f"'{candidate}' below the process working directory"
        if base.is_dir():
            return str(base), "process working directory (not verified as a document root)"
    if _matches(process_name, ("w3wp", "http.sys")):
        return (
            None,
            "IIS sites are defined in applicationHost.config, not on disk here; "
            r"run `%windir%\system32\inetsrv\appcmd list sites` for the physical paths.",
        )
    return None, "could not determine the document root from the operating system"


def _http_probe(port: int, address: str) -> dict[str, Any]:
    """Send one bounded request to a candidate port and keep only headers."""
    host = "127.0.0.1" if address in {"0.0.0.0", "::", "*"} else address
    if ":" in host:
        host = f"[{host}]"
    url = f"http://{host}:{port}/"
    request = urlrequest.Request(url, method="HEAD")
    try:
        with urlrequest.urlopen(request, timeout=HTTP_PROBE_TIMEOUT) as response:
            return {
                "url": url,
                "status": int(response.status),
                "server": str(response.headers.get("Server") or ""),
                "reachable": True,
            }
    except urlerror.HTTPError as exc:
        return {
            "url": url,
            "status": int(exc.code),
            "server": str(exc.headers.get("Server") or "") if exc.headers else "",
            "reachable": True,
        }
    except (OSError, urlerror.URLError, ValueError) as exc:
        return {"url": url, "status": None, "server": "", "reachable": False, "error": str(exc)}


def discover_web_services(
    max_results: int = 25,
    probe_http: bool = False,
    include_runtimes: bool = True,
) -> dict[str, Any]:
    """Return listening ports that look like web services, with the owning process.

    ``probe_http`` is off by default: a request from the agent appears in the
    very access logs Anteumbra watches, so asking the user first is the right
    default.
    """
    listing = list_listening_ports(max_results=max_results)
    inspected = 0
    services: list[dict[str, Any]] = []

    for entry in listing["ports"]:
        port = int(entry["port"])
        pid = entry["pid"]
        process_name = str(entry.get("process_name") or "")
        strong = _matches(process_name, STRONG_PROCESS_HINTS)
        runtime = _matches(process_name, RUNTIME_PROCESS_HINTS)
        candidate = entry["known_web_port"] or strong or (include_runtimes and runtime)
        if not candidate:
            continue

        service: dict[str, Any] = {
            "port": port,
            "address": entry["address"],
            "pid": pid,
            "process_name": process_name or None,
            "service_guess": entry["service_guess"],
            "known_web_port": entry["known_web_port"],
            "confidence": "high" if (strong or entry["known_web_port"]) else "medium",
            "document_root": None,
            "document_root_note": "",
        }

        if pid is not None and inspected < _MAX_PROCESS_INSPECTIONS:
            inspected += 1
            try:
                process = psutil.Process(pid)
            except (psutil.Error, OSError):
                process = None
            if process is not None:
                if not process_name:
                    service["process_name"] = _process_name(process) or None
                cmdline = _process_cmdline(process)
                root, root_note = _document_root(
                    str(service["process_name"] or ""), cmdline, _process_cwd(process)
                )
                service["document_root"] = root
                service["document_root_note"] = root_note
        elif pid is not None:
            service["document_root_note"] = "process inspection limit reached"
        elif os.name == "nt":
            service["document_root_note"] = (
                "no owning process is visible; an elevated agent can identify the listener"
            )
        else:
            service["document_root_note"] = "no owning process is visible for this listener"

        if probe_http:
            service["http"] = _http_probe(port, entry["address"])
            if service["http"].get("reachable") and service["document_root"] is None:
                service["document_root_note"] = (
                    f"{service['document_root_note']}; the port answered HTTP with "
                    f"Server: {service['http'].get('server') or 'unknown'}"
                )
        services.append(service)

    services.sort(key=lambda item: item["port"])
    notes = [listing["note"]] if listing["note"] else []
    if probe_http:
        notes.append(
            "HTTP probing was enabled: each candidate received one HEAD request, which the "
            "site's own access log will record."
        )
    if not services:
        notes.append(
            "No listening port looked like a web service. Ask the user which web server and "
            "port serves the site rather than scanning further."
        )
    return {
        "platform": listing["platform"],
        "services": services,
        "count": len(services),
        "http_probe_enabled": bool(probe_http),
        "note": " ".join(notes).strip(),
    }


__all__ = ["discover_web_services", "list_listening_ports"]
