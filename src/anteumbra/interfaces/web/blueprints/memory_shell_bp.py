# -*- coding: utf-8 -*-
"""Admin surface for the memory-shell (内存马) probe: detection, forensics, remediation.

A memory shell lives only inside the servlet container's memory, so the file
monitor can never see it.  The probe asks the container itself: Anteumbra drops
a short-lived JSP into a watched web root, reads back what is registered in
memory (filters / servlets / listeners) and removes the probe again.

Three tabs share that one probe:

* ``/admin/memory-shell``            detection (检测): the read-only report;
* ``/admin/memory-shell/forensics``  forensics (取证): stored artifacts per
  component, their manifests and their files;
* the 处置 (remediation) flow, which lives in a dialog on both pages and always
  asks the server first whether a forensics artifact exists for the component.

This module owns the pages, the fragments and the actions.  The probe service
belongs to the runtime and may not be wired in at all, so every entry point
degrades to a readable state: a feature that is switched off, or a service that
answers with nonsense, must never become a traceback in the panel.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from urllib.parse import urlencode

from flask import Blueprint, make_response, request, send_file
from flask_babel import gettext as _
from markupsafe import escape as html_escape

from anteumbra.interfaces.web.auth import require_auth
from anteumbra.interfaces.web.pages import render_page
from anteumbra.interfaces.web.runtime import get_runtime

logger = logging.getLogger(__name__)

memory_shell_bp = Blueprint("memory_shell", __name__, url_prefix="/admin")

PAGE_TEMPLATE = "admin/memory_shell.html"
PANEL_TEMPLATE = "admin/panels/memory_shell_panel.html"
FORENSICS_PAGE_TEMPLATE = "admin/memory_shell_forensics.html"
FORENSICS_PANEL_TEMPLATE = "admin/memory_shell_forensics_panel.html"
FORENSICS_MANIFEST_TEMPLATE = "admin/memory_shell_forensics_manifest.html"
DIALOG_TEMPLATE = "admin/memory_shell_forensics_dialog.html"

# A probe run finishes in seconds; ten runs are enough history to show the
# failures and the cleanup state without turning the panel into a log viewer.
RECENT_RUN_LIMIT = 10
# Forensics artifacts are few (one per investigated component) but a site that
# is under attack can accumulate dozens; the list stays bounded.
FORENSICS_RUN_LIMIT = 100

TRUE_VALUES = {"1", "true", "yes", "on"}


def _as_bool(value) -> bool:
    if isinstance(value, bool):
        return value
    return str(value or "").strip().lower() in TRUE_VALUES


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


# ── forensics helpers ──────────────────────────────────────


def _human_bytes(value) -> str:
    try:
        size = float(value)
    except (TypeError, ValueError):
        return "0 B"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{int(size)} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


def _run_files(run: dict) -> list:
    """Normalise the indexed file list, keeping the hash provenance visible."""
    files = []
    for item in _as_sequence(run.get("files")):
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "")
        files.append(
            {
                "name": name,
                "bytes": _as_count(item.get("bytes"), 0),
                "size": _human_bytes(item.get("bytes")),
                "sha256": str(item.get("sha256") or ""),
                "sha256_source": str(item.get("sha256_source") or ""),
                "sha256_note": str(item.get("sha256_note") or ""),
                "download_url": f"/admin/memory-shell/forensics/download/"
                f"{run.get('artifact_id', '')}/{name}",
            }
        )
    return files


def _remediation_view(run: dict) -> dict:
    """The newest remediation attempt recorded for this artifact, if any."""
    history = _as_sequence(run.get("remediations"))
    if not history or not isinstance(history[0], dict):
        return {}
    entry = history[0]
    return {
        "result": str(entry.get("result") or ""),
        "removed": bool(entry.get("removed")),
        "reason": str(entry.get("reason") or ""),
        "operator": str(entry.get("operator") or ""),
        "at": _format_time(entry.get("remediated_at")),
        "count": len(history),
    }


def _run_view(run: dict) -> dict:
    """Flatten one indexed forensics run into the shape the template reads."""
    heap = _as_mapping(run.get("heap"))
    remediation = _remediation_view(run)
    artifact_id = str(run.get("artifact_id") or "")
    files = _run_files(run)
    return {
        "artifact_id": artifact_id,
        "site_id": str(run.get("site_id") or ""),
        "site_name": str(run.get("site_name") or run.get("site_id") or ""),
        "created_at": _format_time(run.get("created_at")),
        "created_at_iso": str(run.get("created_at_iso") or ""),
        "trigger": str(run.get("trigger") or ""),
        "triggered_by": str(run.get("triggered_by") or ""),
        "kind": str(run.get("kind") or ""),
        "name": str(run.get("name") or ""),
        "component": f"{run.get('kind', '')}:{run.get('name', '')}",
        "class_name": str(run.get("class_name") or ""),
        "on_disk": bool(run.get("on_disk")),
        "class_bytes_available": bool(run.get("class_bytes_available")),
        "class_bytes_file": str(run.get("class_bytes_file") or ""),
        "class_bytes_unavailable_reason": str(run.get("class_bytes_unavailable_reason") or ""),
        "heap_ok": bool(heap.get("path")) and _as_count(heap.get("bytes"), 0) > 0,
        "heap_path": str(heap.get("path") or ""),
        "heap_size": _human_bytes(heap.get("bytes")) if heap else "",
        "heap_bytes": _as_count(heap.get("bytes"), 0),
        "heap_sha256": str(heap.get("sha256") or ""),
        "heap_error": str(run.get("heap_error") or ""),
        "report_error": str(run.get("report_error") or ""),
        "bytes": _as_count(run.get("bytes"), 0),
        "size": _human_bytes(run.get("bytes")),
        "files": files,
        "file_count": len(files),
        "remediated": bool(remediation.get("removed")),
        "remediation": remediation,
        "manifest_url": f"/admin/memory-shell/forensics/manifest/{artifact_id}",
        "download_url": files[0]["download_url"] if files else "",
        "remediate_confirm_url": (
            "/admin/memory-shell/remediate/confirm?site_id=%s&kind=%s&name=%s&expect_class=%s"
            % (
                str(run.get("site_id") or ""),
                str(run.get("kind") or ""),
                str(run.get("name") or ""),
                str(run.get("class_name") or ""),
            )
        ),
    }


def _forensics_context(service, *, error: str = "", component=None, triggered_site=None) -> dict:
    """Build the forensics panel context for any service state."""
    context = {
        "available": service is not None,
        "state": "unavailable" if service is None else "ready",
        "error": error,
        "unavailable_reason": "",
        "store_error": "",
        "enabled": False,
        "heap_dump_enabled": False,
        "history": 0,
        "max_dump_mb": 0,
        "timeout_seconds": 0,
        "root": "",
        "running": [],
        "polling": False,
        "runs": [],
        "total_bytes": "0 B",
        "sites": [],
        "component": component or {},
        "triggered_site": triggered_site or "",
    }
    if service is None:
        context["unavailable_reason"] = _(
            "The memory-shell probe service is not attached to this runtime. "
            "Enable the memory_shell_probe plugin in config.toml and restart Anteumbra."
        )
        return context

    try:
        snapshot = service.forensics_snapshot()
    except Exception as exc:  # noqa: BLE001 - the panel reports, it does not crash
        logger.error("forensics snapshot failed: %s", exc, exc_info=True)
        context["state"] = "error"
        context["error"] = error or _(
            "The forensics store did not answer: %(error)s", error=exc
        )
        return context
    if not isinstance(snapshot, dict):
        context["state"] = "error"
        context["error"] = error or _("The forensics store returned no usable state.")
        return context

    runs = []
    for run in _as_sequence(snapshot.get("runs"))[:FORENSICS_RUN_LIMIT]:
        if isinstance(run, dict):
            runs.append(_run_view(run))

    site_id = ""
    if isinstance(component, dict):
        site_id = str(component.get("site_id") or "")

    context.update(
        {
            "state": "error" if error else "ready",
            "available": bool(snapshot.get("available")),
            "store_error": str(snapshot.get("store_error") or ""),
            "enabled": bool(snapshot.get("enabled")),
            "heap_dump_enabled": bool(snapshot.get("heap_dump_enabled")),
            "history": _as_count(snapshot.get("history"), 0),
            "max_dump_mb": _as_count(snapshot.get("max_dump_mb"), 0),
            "timeout_seconds": _as_number(snapshot.get("timeout_seconds"), 0),
            "root": str(snapshot.get("root") or ""),
            "running": [str(item) for item in _as_sequence(snapshot.get("running"))],
            "runs": runs,
            "total_bytes": _human_bytes(sum(run["bytes"] for run in runs)),
            "sites": [
                dict(site) for site in _as_sequence(snapshot.get("sites")) if isinstance(site, dict)
            ],
            "polling": bool(snapshot.get("running")) or bool(triggered_site),
            "component_site": site_id,
        }
    )
    if not context["available"] and not context["error"]:
        context["error"] = _(
            "The forensics store is not available: %(reason)s",
            reason=context["store_error"] or _("unknown reason"),
        )
    return context


def _forensics_response(context: dict):
    try:
        return render_page(FORENSICS_PANEL_TEMPLATE, **context)
    except Exception as exc:  # noqa: BLE001 - an HTMX panel must never 500 silently
        logger.error("forensics panel render failed: %s", exc, exc_info=True)
        message = _("The forensics panel failed to render: %(error)s", error=exc)
        return (
            '<div class="memory-shell-forensics-panel" data-forensics-state="error" '
            'style="color:#ff4444;font-size:11px;">%s</div>' % html_escape(message)
        )


def _dialog_response(**context):
    """Render the 处置 dialog; a broken render must still answer HTMX."""
    try:
        return render_page(DIALOG_TEMPLATE, **context)
    except Exception as exc:  # noqa: BLE001 - the dialog is the last step before a removal
        logger.error("memory-shell remediation dialog render failed: %s", exc, exc_info=True)
        message = _("The remediation dialog failed to render: %(error)s", error=exc)
        return (
            '<div class="modal-overlay active" data-remediate-dialog="error">'
            '<div class="modal-box"><div class="modal-body" style="color:#ff4444;">%s</div>'
            "</div></div>" % html_escape(message)
        )


def _remediation_event_response(html: str, *, refresh: bool = True):
    """Wrap a dialog response so the panels know to re-read their state."""
    response = make_response(html)
    if refresh:
        response.headers["HX-Trigger"] = "memory-shell-refresh"
    return response


def _component_from_request() -> dict:
    return {
        "site_id": str(request.values.get("site_id") or "").strip(),
        "kind": str(request.values.get("kind") or "").strip(),
        "name": str(request.values.get("name") or "").strip(),
        "expect_class": str(request.values.get("expect_class") or "").strip(),
        "force": _as_bool(request.values.get("force")),
    }


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


# ── forensics (取证) routes ────────────────────────────────


@memory_shell_bp.route("/memory-shell/forensics", methods=["GET"])
@require_auth
def memory_shell_forensics_page():
    """Forensics page: stored artifacts for the components the probe flagged."""
    return render_page(FORENSICS_PAGE_TEMPLATE)


@memory_shell_bp.route("/memory-shell/forensics/panel", methods=["GET"])
@require_auth
def memory_shell_forensics_panel():
    """Forensics panel fragment: state row, run form, artifact table."""
    service = _service()
    component = _component_from_request()
    return _forensics_response(_forensics_context(service, component=component))


@memory_shell_bp.route("/memory-shell/forensics/manifest/<artifact_id>", methods=["GET"])
@require_auth
def memory_shell_forensics_manifest(artifact_id: str):
    """The stored manifest of one artifact, rendered for the detail pane."""
    service = _service()
    manifest = None
    if service is not None:
        try:
            manifest = service.forensics_manifest(artifact_id)
        except Exception as exc:  # noqa: BLE001 - report, never 500 the pane
            logger.error("manifest read failed for %s: %s", artifact_id, exc, exc_info=True)
    if manifest is None:
        manifest = {}
    try:
        return render_page(
            FORENSICS_MANIFEST_TEMPLATE,
            available=manifest != {},
            artifact_id=artifact_id,
            manifest=manifest,
            methods=[str(item) for item in _as_sequence(manifest.get("methods"))],
            fields=[str(item) for item in _as_sequence(manifest.get("fields"))],
            container=[str(item) for item in _as_sequence(manifest.get("container"))],
            jvm_arguments=[str(item) for item in _as_sequence(manifest.get("jvm_input_arguments"))],
            heap=_as_mapping(manifest.get("heap")),
            json_text=json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True)
            if manifest
            else "",
        )
    except Exception as exc:  # noqa: BLE001
        logger.error("manifest render failed for %s: %s", artifact_id, exc, exc_info=True)
        return (
            '<div class="memory-shell-manifest" data-manifest-state="error" '
            'style="color:#ff4444;font-size:11px;">%s</div>'
            % html_escape(_("The manifest could not be rendered: %(error)s", error=exc))
        )


@memory_shell_bp.route(
    "/memory-shell/forensics/download/<artifact_id>/<path:filename>", methods=["GET"]
)
@require_auth
def memory_shell_forensics_download(artifact_id: str, filename: str):
    """Download one indexed artifact file. Only indexed files are served."""
    service = _service()
    path = None
    if service is not None and "/" not in filename and "\\" not in filename:
        try:
            path = service.forensics_file_path(artifact_id, filename)
        except Exception as exc:  # noqa: BLE001
            logger.error("forensics download failed for %s: %s", artifact_id, exc, exc_info=True)
    if path is None:
        logger.warning(
            "[MEMORY-SHELL] refused forensics download of %s/%s: not an indexed artifact",
            artifact_id,
            filename,
        )
        return (_("No such forensics artifact file."), 404)
    return send_file(path, as_attachment=True, download_name=filename)


@memory_shell_bp.route("/memory-shell/forensics/run", methods=["POST"])
@require_auth
def memory_shell_forensics_run():
    """Start one forensics run in the background and re-render the panel.

    A heap dump can take minutes, so the request returns as soon as the worker
    is started and the panel polls itself until the site leaves the running set.
    """
    component = _component_from_request()
    site_id = component["site_id"]
    service = _service()
    if service is None:
        return _forensics_response(
            _forensics_context(
                None, error=_("The memory-shell probe service is not available.")
            )
        )
    if not site_id:
        return _forensics_response(
            _forensics_context(service, error=_("No site was selected for forensics."))
        )
    if not component["kind"] or not component["name"]:
        return _forensics_response(
            _forensics_context(
                service,
                error=_(
                    "Select a component in the detection tab (or open forensics from a "
                    "finding) before running forensics."
                ),
                component=component,
            )
        )

    try:
        service.run_forensics(
            site_id,
            component["kind"],
            component["name"],
            trigger="manual",
            triggered_by="admin",
            background=True,
            heap_live=_as_bool(request.values.get("heap_live")),
        )
    except Exception as exc:  # noqa: BLE001 - report the failure in the panel
        logger.error("forensics run failed for %s: %s", site_id, exc, exc_info=True)
        return _forensics_response(
            _forensics_context(
                service,
                error=_("Forensics could not be started: %(error)s", error=exc),
                component=component,
            )
        )

    logger.info(
        "[MEMORY-SHELL] forensics started for %s on site %s by admin",
        f"{component['kind']}:{component['name']}",
        site_id,
    )
    return _forensics_response(
        _forensics_context(service, component=component, triggered_site=site_id)
    )


# ── remediation (处置) routes ──────────────────────────────


def _forensics_exists(service, component: dict) -> bool:
    """True when a forensics artifact exists for exactly this component."""
    if service is None:
        return False
    try:
        snapshot = service.forensics_snapshot()
    except Exception:  # noqa: BLE001 - an unreadable store means "no artifact known"
        return False
    for run in _as_sequence(snapshot.get("runs")):
        if not isinstance(run, dict):
            continue
        if (
            str(run.get("site_id") or "") == component["site_id"]
            and str(run.get("kind") or "") == component["kind"]
            and str(run.get("name") or "") == component["name"]
        ):
            return True
    return False


@memory_shell_bp.route("/memory-shell/remediate/confirm", methods=["GET"])
@require_auth
def memory_shell_remediate_confirm():
    """The 处置 confirmation contract, decided by the server.

    With a forensics artifact: a plain confirmation. Without one: the three
    button warning (立即处置 / 前往取证 / 取消), because removing a component
    without evidence is a decision the operator has to make explicitly.
    """
    component = _component_from_request()
    service = _service()
    has_forensics = _forensics_exists(service, component) if service is not None else False
    forensics_tab = _forensics_tab_url(component)
    return _dialog_response(
        mode="confirm" if has_forensics else "no-forensics",
        component=component,
        has_forensics=has_forensics,
        forensics_tab=forensics_tab,
        result="",
        reason="",
        detail="",
        after_count=None,
    )


def _forensics_tab_url(component: dict) -> str:
    """Where 前往取证 sends the operator: the forensics tab, component prefilled."""
    query = urlencode(
        {
            "site_id": component.get("site_id", ""),
            "kind": component.get("kind", ""),
            "name": component.get("name", ""),
        }
    )
    return f"/admin/memory-shell/forensics?{query}"


@memory_shell_bp.route("/memory-shell/remediate", methods=["POST"])
@require_auth
def memory_shell_remediate():
    """Remove one component, or refuse with a reason the operator can read.

    Every response is a dialog fragment at HTTP 200: htmx does not swap error
    responses, and "nothing happened, here is why" is exactly what an operator
    pressing 处置 must see.  ``acknowledge_no_forensics`` is the flag the warning
    dialog's 立即处置 button sends; without it a component that has no forensics
    gets the same warning back instead of being removed.
    """
    component = _component_from_request()
    acknowledge = _as_bool(request.values.get("acknowledge_no_forensics"))
    force = _as_bool(request.values.get("force"))
    service = _service()

    if service is None:
        return _remediation_event_response(
            _dialog_response(
                mode="error",
                component=component,
                has_forensics=False,
                forensics_tab=_forensics_tab_url(component),
                result="failed",
                reason=_("The memory-shell probe service is not available."),
                detail="",
                after_count=None,
            ),
            refresh=False,
        )

    for field_name, message in (
        ("site_id", _("No site was selected for remediation.")),
        ("kind", _("No component kind was selected for remediation.")),
        ("name", _("No component was selected for remediation.")),
    ):
        if not component[field_name]:
            return _remediation_event_response(
                _dialog_response(
                    mode="error",
                    component=component,
                    has_forensics=False,
                    forensics_tab=_forensics_tab_url(component),
                    result="refused",
                    reason=message,
                    detail="",
                    after_count=None,
                ),
                refresh=False,
            )

    has_forensics = _forensics_exists(service, component)

    try:
        outcome = service.remediate(
            component["site_id"],
            component["kind"],
            component["name"],
            acknowledge_no_forensics=acknowledge,
            force=force,
            expect_class=component["expect_class"],
            trigger="manual",
            triggered_by="admin",
        )
    except Exception as exc:  # noqa: BLE001 - a failed removal is reported, never raised
        logger.error(
            "remediation raised for %s:%s: %s", component["kind"], component["name"], exc,
            exc_info=True,
        )
        return _remediation_event_response(
            _dialog_response(
                mode="error",
                component=component,
                has_forensics=has_forensics,
                forensics_tab=_forensics_tab_url(component),
                result="failed",
                reason=_("The remediation request failed: %(error)s", error=exc),
                detail="",
                after_count=None,
            )
        )

    view = _as_mapping(outcome)
    reason = str(view.get("reason") or "")
    # A refusal because there is no evidence is answered with the same three
    # button warning, so the operator can still choose 立即处置 explicitly.
    if view.get("refused") and reason.startswith("forensics_required") and not acknowledge:
        return _remediation_event_response(
            _dialog_response(
                mode="no-forensics",
                component=component,
                has_forensics=False,
                forensics_tab=_forensics_tab_url(component),
                result="refused",
                reason="",
                detail="",
                after_count=None,
            )
        )

    if view.get("failure"):
        result = "failed"
    elif view.get("refused"):
        result = "refused"
    elif view.get("removed"):
        result = "removed"
    else:
        result = "not-removed"

    detail = ""
    after_component = _as_mapping(view.get("after_component"))
    if result == "removed":
        logger.warning(
            "[MEMORY-SHELL] admin removed %s:%s on site %s (class %s)",
            component["kind"],
            component["name"],
            component["site_id"],
            component["expect_class"],
        )
        detail = str(view.get("class_name") or component["expect_class"])
    elif after_component:
        detail = _(
            "The component is still registered: %(class_name)s",
            class_name=after_component.get("class_name", ""),
        )

    return _remediation_event_response(
        _dialog_response(
            mode="result",
            component=component,
            has_forensics=has_forensics,
            forensics_tab=_forensics_tab_url(component),
            result=result,
            reason=reason,
            detail=detail,
            after_count=_as_count(view.get("after_count"), 0),
        )
    )
