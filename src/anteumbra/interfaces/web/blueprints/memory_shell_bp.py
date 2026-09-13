# -*- coding: utf-8 -*-
"""Admin surface for the memory-shell (内存马) probe.

A memory shell lives only inside the servlet container's memory, so the file
monitor can never see it.  The probe asks the container itself: Anteumbra drops
a short-lived JSP into a watched web root, reads back what is registered in
memory (filters / servlets / listeners) and removes the probe again.

This module owns the page, the panel fragment and the manual trigger.  The probe
service belongs to the runtime and may not be wired in at all, so every entry
point degrades to a readable state: a feature that is switched off, or a service
that answers with nonsense, must never become a traceback in the panel.
"""

from __future__ import annotations

import logging
from datetime import datetime

from flask import Blueprint, request
from flask_babel import gettext as _
from markupsafe import escape as html_escape

from anteumbra.interfaces.web.auth import require_auth
from anteumbra.interfaces.web.pages import render_page
from anteumbra.interfaces.web.runtime import get_runtime

logger = logging.getLogger(__name__)

memory_shell_bp = Blueprint("memory_shell", __name__, url_prefix="/admin")

PAGE_TEMPLATE = "admin/memory_shell.html"
PANEL_TEMPLATE = "admin/panels/memory_shell_panel.html"

# A probe run finishes in seconds; ten runs are enough history to show the
# failures and the cleanup state without turning the panel into a log viewer.
RECENT_RUN_LIMIT = 10


# ── helpers ────────────────────────────────────────────────


def _service():
    """Return the probe service, or None while the plugin is not wired in."""
    try:
        runtime = get_runtime()
    except Exception:  # pragma: no cover - a runtime is always attached in practice
        logger.debug("runtime unavailable for the memory-shell surface", exc_info=True)
        return None
    return getattr(runtime, "memory_shell", None)


def _as_mapping(value) -> dict:
    """Coerce a snapshot field to a mapping without trusting its type."""
    return value if isinstance(value, dict) else {}


def _as_sequence(value) -> list:
    """Coerce a snapshot field to a list without trusting its type."""
    return list(value) if isinstance(value, (list, tuple)) else []


def _as_count(value, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _as_number(value, default=0):
    """Render a numeric config value without a trailing .0 when it is integral."""
    try:
        number = float(value)
    except (TypeError, ValueError):
        return default
    return int(number) if number.is_integer() else round(number, 1)


def _format_time(value) -> str:
    """Render an epoch timestamp the way the other admin tables do."""
    try:
        return datetime.fromtimestamp(float(value)).strftime("%Y-%m-%d %H:%M:%S")
    except (TypeError, ValueError, OSError, OverflowError):
        return ""


def _counts_summary(counts) -> str:
    """One readable line for a kind->count map, e.g. ``filter 3 · servlet 2``."""
    counts = _as_mapping(counts)
    parts = [f"{kind} {_as_count(counts.get(kind), 0)}" for kind in sorted(counts)]
    return " · ".join(parts)


def _entry_views(entries):
    """Split the probe entries into suspect rows plus a collapsed clean count."""
    suspects = []
    clean = 0
    for entry in _as_sequence(entries):
        if not isinstance(entry, dict):
            continue
        if not entry.get("suspect"):
            clean += 1
            continue
        suspects.append(
            {
                "kind": str(entry.get("kind") or ""),
                "name": str(entry.get("name") or ""),
                "urls": [str(item) for item in _as_sequence(entry.get("urls"))],
                "class_name": str(entry.get("class_name") or ""),
                "class_loader": str(entry.get("class_loader") or ""),
                "resource": str(entry.get("resource") or ""),
                "code_source": str(entry.get("code_source") or ""),
                "reasons": [str(item) for item in _as_sequence(entry.get("reasons"))],
                "on_disk": bool(entry.get("on_disk")),
            }
        )
    return suspects, clean


def _outcome_view(outcome) -> dict:
    """Flatten one probe outcome into the shape the panel template reads."""
    outcome = _as_mapping(outcome)
    report = _as_mapping(outcome.get("report"))
    suspects, clean = _entry_views(report.get("entries"))
    return {
        "site_id": str(outcome.get("site_id") or ""),
        "site_name": str(outcome.get("site_name") or outcome.get("site_id") or ""),
        "finished_at": _format_time(outcome.get("finished_at")),
        "duration_ms": _as_count(outcome.get("duration_ms"), 0),
        "ok": bool(outcome.get("ok")),
        "failure": str(outcome.get("failure") or ""),
        # A cleanup that did not happen is the one state an operator must not
        # miss, so it is carried separately from the run failure.
        "cleanup_ok": outcome.get("cleanup_ok") is not False,
        "cleanup_error": str(outcome.get("cleanup_error") or ""),
        "trigger": str(outcome.get("trigger") or ""),
        "triggered_by": str(outcome.get("triggered_by") or ""),
        "suspect_count": _as_count(outcome.get("suspect_count"), len(suspects)),
        "url": str(report.get("url") or ""),
        "container": ", ".join(str(item) for item in _as_sequence(report.get("container"))),
        "context_path": str(report.get("context_path") or ""),
        "probe_version": str(report.get("probe_version") or ""),
        "report_error": str(report.get("error") or ""),
        "entry_summary": _counts_summary(report.get("counts")),
        "entries_total": len(_as_sequence(report.get("entries"))),
        "clean_count": clean,
        "suspects": suspects,
    }


def _site_views(snapshot) -> list:
    """Merge the configured sites with the latest outcome known for each one."""
    latest = _as_mapping(snapshot.get("latest"))
    running = {str(item) for item in _as_sequence(snapshot.get("running"))}
    views = []
    for site in _as_sequence(snapshot.get("sites")):
        if not isinstance(site, dict):
            continue
        site_id = str(site.get("site_id") or "")
        outcome = _outcome_view(latest.get(site_id)) if site_id in latest else None
        views.append(
            {
                "site_id": site_id,
                "name": str(site.get("name") or site_id),
                "root": str(site.get("root") or ""),
                "base_url": str(site.get("base_url") or ""),
                "port": site.get("port"),
                "cooldown_remaining": _as_number(site.get("cooldown_remaining"), 0),
                "running": site_id in running,
                "last_run": outcome["finished_at"] if outcome else "",
                "suspect_count": outcome["suspect_count"] if outcome else 0,
                "entry_summary": outcome["entry_summary"] if outcome else "",
                "failure": outcome["failure"] if outcome else "",
                "cleanup_error": outcome["cleanup_error"] if outcome else "",
            }
        )
    return views


def _load_snapshot(service):
    """Return ``(snapshot, error_message)``; never raises."""
    try:
        snapshot = service.snapshot()
    except Exception as exc:  # noqa: BLE001 - the panel reports, it does not crash
        logger.error("memory-shell snapshot failed: %s", exc, exc_info=True)
        return None, _("The memory-shell probe service did not answer: %(error)s", error=exc)
    if not isinstance(snapshot, dict):
        return None, _("The memory-shell probe service returned no usable state.")
    return snapshot, ""


def _panel_context(service, *, error: str = "", triggered_site: str | None = None) -> dict:
    """Build the panel context for any service state: missing, broken or ready."""
    context = {
        "available": service is not None,
        "state": "unavailable" if service is None else "ready",
        "unavailable_reason": "",
        "error": error,
        "enabled": False,
        "auto_probe": False,
        "cooldown_seconds": 0,
        "http_timeout_seconds": 0,
        "trigger_extensions": [],
        "runs": 0,
        "failures": 0,
        "running": [],
        "polling": False,
        "sites": [],
        "recent_runs": [],
        "findings": [],
    }
    if service is None:
        context["unavailable_reason"] = _(
            "The memory-shell probe service is not attached to this runtime. "
            "Enable the memory_shell_probe plugin in config.toml and restart Anteumbra."
        )
        return context

    snapshot, snapshot_error = _load_snapshot(service)
    if snapshot is None:
        context["state"] = "error"
        context["error"] = error or snapshot_error
        return context

    recent_runs = []
    for outcome in _as_sequence(snapshot.get("history"))[:RECENT_RUN_LIMIT]:
        view = _outcome_view(outcome)
        if not view["site_id"] and not view["site_name"]:
            continue
        recent_runs.append(view)

    running = [str(item) for item in _as_sequence(snapshot.get("running"))]
    context.update(
        {
            "state": "error" if error else "ready",
            "enabled": bool(snapshot.get("enabled")),
            "auto_probe": bool(snapshot.get("auto_probe")),
            "cooldown_seconds": _as_number(snapshot.get("cooldown_seconds"), 0),
            "http_timeout_seconds": _as_number(snapshot.get("http_timeout_seconds"), 0),
            "trigger_extensions": [
                str(item) for item in _as_sequence(snapshot.get("trigger_extensions"))
            ],
            "runs": _as_count(snapshot.get("runs"), 0),
            "failures": _as_count(snapshot.get("failures"), 0),
            "running": running,
            "sites": _site_views(snapshot),
            "recent_runs": recent_runs,
            "findings": [view for view in recent_runs if view["suspects"]],
            # A probe that was just started may not have reached the service's
            # own "running" set yet, so the freshly triggered panel polls too.
            "polling": bool(running) or triggered_site is not None,
        }
    )
    return context


def _panel_response(context: dict):
    """Render the panel, falling back to a readable fragment on a broken render."""
    try:
        return render_page(PANEL_TEMPLATE, **context)
    except Exception as exc:  # noqa: BLE001 - an HTMX panel must never 500 silently
        logger.error("memory-shell panel render failed: %s", exc, exc_info=True)
        message = _("The memory-shell panel failed to render: %(error)s", error=exc)
        return (
            '<div class="memory-shell-panel" data-memory-shell-state="error" '
            'style="color:#ff4444;font-size:11px;">%s</div>' % html_escape(message)
        )


# ── routes ─────────────────────────────────────────────────


@memory_shell_bp.route("/memory-shell", methods=["GET"])
@require_auth
def memory_shell_page():
    """Memory-shell page: the panel loads itself and polls while probing."""
    return render_page(PAGE_TEMPLATE)


@memory_shell_bp.route("/memory-shell/panel", methods=["GET"])
@require_auth
def memory_shell_panel():
    """Panel fragment: status row, per-site rows, findings and recent runs."""
    return _panel_response(_panel_context(_service()))


@memory_shell_bp.route("/memory-shell/probe", methods=["POST"])
@require_auth
def memory_shell_probe():
    """Start one manual probe in the background and re-render the panel.

    A probe can take up to the configured HTTP timeout, so the request returns
    as soon as the worker thread is started; the panel polls itself until the
    site leaves the service's ``running`` set.  Every rejection stays a 200
    panel — HTMX does not swap error responses, and a silent no-op is exactly
    what an operator pressing "probe" must not get.
    """
    site_id = str(request.values.get("site_id") or "").strip()
    service = _service()
    if service is None:
        return _panel_response(
            _panel_context(None, error=_("The memory-shell probe service is not available."))
        )
    if not site_id:
        return _panel_response(
            _panel_context(service, error=_("No site was selected for the probe."))
        )

    snapshot, snapshot_error = _load_snapshot(service)
    if snapshot is None:
        return _panel_response(_panel_context(service, error=snapshot_error))

    known_sites = {
        str(site.get("site_id") or "")
        for site in _as_sequence(snapshot.get("sites"))
        if isinstance(site, dict)
    }
    if site_id not in known_sites:
        logger.warning("[MEMORY-SHELL] probe refused for unknown site: %s", site_id)
        return _panel_response(
            _panel_context(service, error=_("Unknown site: %(site_id)s", site_id=site_id))
        )

    try:
        service.run_probe(site_id, trigger="manual", triggered_by="admin", background=True)
    except Exception as exc:  # noqa: BLE001 - report the failure in the panel
        logger.error("memory-shell probe start failed for %s: %s", site_id, exc, exc_info=True)
        return _panel_response(
            _panel_context(
                service,
                error=_("The probe could not be started: %(error)s", error=exc),
            )
        )

    logger.info("[MEMORY-SHELL] manual probe started for site %s by admin", site_id)
    return _panel_response(_panel_context(service, triggered_site=site_id))
