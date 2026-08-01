# -*- coding: utf-8 -*-
"""
v1.0.6: Monitor Blueprint — extracted from admin_bp.py
Routes: /stream_logs, /logs/*, /wal/*, /registry/*, /session/*, /sse/*, /config/*
"""

import base64
import hmac
import html
import logging
import queue
import re
import time

from flask import (
    Blueprint,
    Response,
    abort,
    current_app,
    request,
    session,
    stream_with_context,
)

from anteumbra.domain.site import SiteIdentity
from anteumbra.interfaces.web.auth import (
    get_admin_credentials,
    is_ip_allowed,
    require_auth,
)
from anteumbra.interfaces.web.log_history import (
    collect_log_history,
    render_log_history,
)
from anteumbra.interfaces.web.runtime import get_runtime

logger = logging.getLogger(__name__)


def _registry():
    """Return the Registry owned by the current Flask runtime."""
    return get_runtime().registry


monitor_bp = Blueprint("monitor", __name__, url_prefix="/admin")


# -- SSE Live Log Stream --


@monitor_bp.route("/stream_logs")
def stream_logs():
    """v1.7.6: SSE log stream with level filtering (config-driven, hot-reloadable)"""
    token = request.args.get("token")
    if not token:
        abort(403)

    client_ip = request.remote_addr
    runtime = get_runtime()
    sse = runtime.sse
    if sse is None:
        abort(503)

    config = runtime.config.get()
    web_admin_cfg = config.get("web_admin", {})
    limits = sse.get_limits()

    ip_client_count = sse.ip_client_count(client_ip)
    ip_connections = sse.ip_clients(client_ip)

    if ip_client_count >= limits["per_ip"]:
        for old_queue in ip_connections:
            sse.unregister_client(old_queue)
        logging.getLogger("monitor.admin_sse").info(
            f"[SSE] IP {client_ip} cleaned {len(ip_connections)} old connections"
        )
        ip_client_count = 0

    session_token = session.get("sse_token")
    if not session.get("authenticated") or not session_token:
        abort(403)
    if not hmac.compare_digest(str(token), str(session_token)):
        abort(403)

    try:
        decoded = base64.b64decode(token).decode("utf-8")
        username, random_part = decoded.split(":", 1)
        expected_username, password_hash, allowed_ips = get_admin_credentials()
        if username != expected_username or not is_ip_allowed(client_ip, allowed_ips):
            abort(403)
    except Exception:
        abort(403)

    logger = current_app.logger
    requested_site = request.args.get("site_id") or request.args.get("site")
    try:
        websites = runtime.config.get_enabled_websites()
    except Exception:
        logger.warning("[SSE] Failed to resolve configured sites", exc_info=True)
        abort(503)
    if requested_site:
        requested_id = requested_site.strip().lower()
        websites = [
            site for site in websites if site.site_id == requested_id or site.name == requested_site
        ]
        if not websites:
            abort(404)
    if not websites:
        abort(503)
    log_files = [
        runtime.logging.get_site_log_path(SiteIdentity.from_values(site.site_id, site.name))
        for site in websites
    ]
    show_all_levels = request.args.get("levels", "") == "all"

    if not show_all_levels:
        try:
            config = runtime.config.get()
            web_admin_cfg = config.get("web_admin", {})
            allowed_levels = web_admin_cfg.get("sse_log_levels", ["INFO", "ERROR", "CRITICAL"])
            allowed_levels_set = set(level.upper() for level in allowed_levels)
            allowed_levels_set.discard("DEBUG")
        except Exception as e:
            logger.warning(f"[SSE] Failed to read log level config: {e}, using defaults")
            allowed_levels_set = {"INFO", "WARNING", "ERROR", "CRITICAL"}
    else:
        allowed_levels_set = None
        logger.info("[SSE][ANALYZER] Full log mode")

    def generate():
        client_queue = None
        handles = []
        try:
            client_queue = sse.register_client(client_ip)
            if not client_queue:
                yield "data: [SSE][ERROR] Client registration failed\n\n"
                return

            for log_file in log_files:
                log_file.parent.mkdir(parents=True, exist_ok=True)
                log_file.touch(exist_ok=True)
                handle = open(
                    log_file,
                    "r",
                    encoding="utf-8",
                    errors="ignore",
                    buffering=1,
                )
                handle.seek(0, 2)
                handles.append(handle)

            last_heartbeat = time.monotonic()
            while True:
                try:
                    signal = client_queue.get_nowait()
                    if signal is None:
                        return
                    if signal == "registry_update":
                        yield "data: [REGISTRY][UPDATE] Registry updated\n\n"
                        continue
                except queue.Empty:
                    pass
                except Exception:
                    break

                emitted = False
                for handle in handles:
                    line = handle.readline()
                    if not line:
                        continue
                    emitted = True
                    log_line = line.strip()
                    if allowed_levels_set is not None:
                        level_match = re.search(r"\] (\w+) -", log_line)
                        if level_match:
                            level = level_match.group(1).upper()
                            if level not in allowed_levels_set:
                                continue
                    if "[SSE]" in log_line:
                        continue
                    cleaned = log_line.replace("\n", " ").replace("\r", " ")
                    sse.persist_log_line(cleaned)
                    yield f"data: {cleaned}\n\n"

                now = time.monotonic()
                if now - last_heartbeat >= 15.0:
                    yield "data: [SSE][HEARTBEAT]\n\n"
                    last_heartbeat = now
                    emitted = True
                if not emitted:
                    time.sleep(0.1)

        except Exception as e:
            error_msg = str(e).replace("\n", " ")
            yield f"data: [SSE][ERROR] {error_msg}\n\n"
        finally:
            for handle in handles:
                try:
                    handle.close()
                except OSError:
                    logger.debug("Failed to close SSE log handle", exc_info=True)
            if client_queue:
                sse.unregister_client(client_queue)
                remaining = sse.connected_client_count()
                logger.debug(f"[SSE] client {client_ip} disconnected, {remaining} remaining")

    response = Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )
    return response


# -- Log History --


@monitor_bp.route("/logs/history")
@require_auth
def logs_history():
    """Return escaped runtime-owned history for LIVE LOG STREAM initialization."""
    try:
        lines = collect_log_history(
            get_runtime(),
            limit=1000,
            log=current_app.logger,
        )
        return render_log_history(
            lines,
            empty_message="[INFO] No log history found",
        )
    except Exception as e:
        current_app.logger.error(f"[LOGS_HISTORY] Read failed: {e}", exc_info=True)
        message = html.escape(str(e)[:50])
        return f'<div class="log-line error">[ERROR] Failed to load history: {message}</div>'


@monitor_bp.route("/logs/access-analysis")
@require_auth
def access_log_analysis():
    """Render a read-only access-log behavior analysis for the Log Analyzer modal."""

    def line(level: str, text: str) -> str:
        return f'<div class="log-line {level}">{html.escape(text)}</div>'

    parts = [line("info", "[ACCESS_ANALYSIS] Web access log analysis")]
    try:
        runtime = get_runtime()
        results = runtime.log_analysis.analyze(runtime.config.get_enabled_websites())
    except Exception as exc:
        current_app.logger.warning("[ACCESS_ANALYSIS] failed: %s", exc, exc_info=True)
        parts.append(line("error", f"[ACCESS_ANALYSIS][ERROR] {exc}"))
        return "".join(parts)

    if not results:
        parts.append(
            line("warn", "[ACCESS_ANALYSIS][DISABLED] No enabled websites are configured.")
        )
        return "".join(parts)

    for result in results:
        site = result["website"]
        status = result["status"]
        parts.append(line("info", f"[ACCESS_ANALYSIS][SITE] {site}"))
        if status == "disabled":
            parts.append(line("warn", f"[ACCESS_ANALYSIS][DISABLED] {site}"))
            continue
        if status in {"missing", "error"}:
            parts.append(
                line(
                    "error",
                    f"[ACCESS_ANALYSIS][{status.upper()}] {site}: {result['error']} "
                    f"path={result['configured_path']}",
                )
            )
            continue

        parts.append(line("info", f"[ACCESS_ANALYSIS][SOURCE] selected={result['selected_path']}"))
        stats = result["stats"]
        parts.append(
            line(
                "info",
                f"[ACCESS_ANALYSIS][SUMMARY] analyzed={stats.get('total_analyzed', 0)} alerts={stats.get('total_alerts', 0)} ips={stats.get('ips_tracked', 0)}",
            )
        )
        if not result["events"]:
            parts.append(
                line("info", "[ACCESS_ANALYSIS][CLEAN] No suspicious access-log behavior detected.")
            )
            continue
        for event in result["events"]:
            severity = str(event.get("severity", "medium")).upper()
            event_type = event.get("type", "unknown")
            ip = event.get("ip", "unknown")
            target = event.get("path") or event.get("user_agent") or event.get("tools") or ""
            detail = event.get("reason") or event.get("count") or event.get("unique_paths") or ""
            parts.append(
                line(
                    "warn",
                    f"[ACCESS_ANALYSIS][{severity}] {event_type} ip={ip} target={target} detail={detail}",
                )
            )

    return "".join(parts)


# Import route registrations after the shared Blueprint is initialized.
from anteumbra.interfaces.web.blueprints import (  # noqa: E402
    monitor_admin_routes as _monitor_admin_routes,  # noqa: F401
)
