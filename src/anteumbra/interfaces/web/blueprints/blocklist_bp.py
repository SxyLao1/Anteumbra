"""Authenticated IP blocking and site-qualified audit ledger routes."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from flask import Blueprint, Response, current_app, jsonify, render_template, request

from anteumbra.domain.blocking import canonical_ip
from anteumbra.domain.site import SiteIdentity
from anteumbra.interfaces.web.auth import require_auth
from anteumbra.interfaces.web.runtime import get_runtime


blocklist_bp = Blueprint("blocklist", __name__, url_prefix="/admin")


def _blocking_services():
    runtime = get_runtime()
    if runtime.ip_blocker is None or runtime.block_ledger is None:
        raise RuntimeError("IP blocking services are not configured")
    return runtime.ip_blocker, runtime.block_ledger


def _site_identity(site_id: object = None) -> SiteIdentity:
    normalized = str(site_id or "").strip().lower()
    if not normalized or normalized == "legacy":
        return SiteIdentity.legacy()
    website = get_runtime().config.get_website(normalized)
    if website is None:
        raise ValueError(f"unknown site_id: {normalized}")
    return SiteIdentity.from_values(website.site_id, website.name)


def _site_filter() -> str | None:
    raw = request.args.get("site_id")
    return _site_identity(raw).site_id if raw else None


def _payload() -> Mapping[str, Any]:
    data = request.get_json(silent=True)
    if not isinstance(data, Mapping):
        raise ValueError("request body must be a JSON object")
    return data


def _validated_ips(data: Mapping[str, Any]) -> tuple[str, ...]:
    raw = data.get("ips")
    if isinstance(raw, (str, bytes)) or not isinstance(raw, list) or not raw:
        raise ValueError("ips must be a non-empty array")
    return tuple(dict.fromkeys(canonical_ip(str(item)) for item in raw))


def _device_filter(data: Mapping[str, Any]) -> tuple[str, ...] | None:
    raw = data.get("devices")
    if raw in (None, []):
        return None
    if not isinstance(raw, list) or not all(isinstance(item, str) for item in raw):
        raise ValueError("devices must be an array of names")
    return tuple(dict.fromkeys(raw))


def _result_payload(results) -> list[dict[str, object]]:
    return [
        {
            "device": item.device_name,
            "ip": item.ip,
            "success": item.success,
            "message": item.message,
        }
        for item in results
    ]


def _block(data: Mapping[str, Any]) -> tuple[dict[str, object], int]:
    blocker, ledger = _blocking_services()
    ips = _validated_ips(data)
    site = _site_identity(data.get("site_id"))
    profile_id = str(data.get("profile_id") or "")
    reason = str(data.get("reason") or "").strip()
    source = str(data.get("source") or "manual")
    risk_score = 0.0

    if profile_id and not reason:
        graph = get_runtime().threat_graph
        profile = (
            graph.query_profile(profile_id, site_id=site.site_id)
            if graph is not None
            else None
        )
        if profile is not None:
            tool = profile.tool_signature or "Unknown tool"
            risk_score = float(profile.risk_score)
            reason = f"Profile {profile_id[:8]} - {tool} / risk {round(risk_score * 100)}%"
            if risk_score >= 0.7:
                source = "auto"
    reason = reason or "Manual block from Anteumbra"

    results = blocker.block(
        ips,
        reason=reason,
        site=site,
        profile_id=profile_id,
        risk_score=risk_score,
        device_names=_device_filter(data),
    )
    ledger_errors: list[dict[str, str]] = []
    for ip in ips:
        ip_results = [item for item in results if item.ip == ip]
        try:
            ledger.add_entry(
                ip,
                site=site,
                source=source,
                reason=reason,
                profile_id=profile_id,
                blocked_by="admin",
                broadcast_results=_result_payload(ip_results),
            )
        except Exception as exc:
            current_app.logger.exception("Block ledger write failed for site=%s ip=%s", site.site_id, ip)
            ledger_errors.append({"ip": ip, "error": str(exc)})

    success_count = sum(item.success for item in results)
    all_succeeded = bool(results) and success_count == len(results)
    success = success_count > 0 and not ledger_errors
    if success_count == 0:
        status_code = 502
    elif ledger_errors or not all_succeeded:
        status_code = 207
    else:
        status_code = 200
    message = f"Blocked {success_count}/{len(results)} device operations"
    if ledger_errors:
        message += f"; {len(ledger_errors)} audit writes failed"
    return {
        "success": success,
        "message": message,
        "site_id": site.site_id,
        "results": _result_payload(results),
        "ledger_errors": ledger_errors,
    }, status_code


def _unblock(data: Mapping[str, Any]) -> tuple[dict[str, object], int]:
    blocker, ledger = _blocking_services()
    ips = _validated_ips(data)
    site = _site_identity(data.get("site_id"))
    results = blocker.unblock(ips, device_names=_device_filter(data))
    ledger_errors: list[dict[str, str]] = []
    for ip in ips:
        if not any(item.success and item.ip == ip for item in results):
            continue
        try:
            ledger.mark_unblocked(ip, site_id=site.site_id, unblocked_by="admin")
        except Exception as exc:
            current_app.logger.exception(
                "Block ledger unblock update failed for site=%s ip=%s",
                site.site_id,
                ip,
            )
            ledger_errors.append({"ip": ip, "error": str(exc)})

    success_count = sum(item.success for item in results)
    all_succeeded = bool(results) and success_count == len(results)
    success = success_count > 0 and not ledger_errors
    if success_count == 0:
        status_code = 502
    elif ledger_errors or not all_succeeded:
        status_code = 207
    else:
        status_code = 200
    return {
        "success": success,
        "message": f"Unblocked {success_count}/{len(results)} device operations",
        "site_id": site.site_id,
        "results": _result_payload(results),
        "ledger_errors": ledger_errors,
    }, status_code


def _command_response(command, context: str):
    try:
        payload, status = command(_payload())
        return jsonify(payload), status
    except ValueError as exc:
        return jsonify({"success": False, "message": str(exc)}), 400
    except RuntimeError as exc:
        current_app.logger.warning("%s unavailable: %s", context, exc)
        return jsonify({"success": False, "message": str(exc)}), 503
    except Exception:
        current_app.logger.exception("%s failed", context)
        return jsonify({"success": False, "message": "Internal blocking service error"}), 500


@blocklist_bp.route("/api/v1/blocklist/add", methods=["POST"])
@require_auth
def blocklist_add():
    return _command_response(_block, "Blocklist add")


@blocklist_bp.route("/blocklist/block", methods=["POST"])
@require_auth
def blocklist_manual_block():
    return _command_response(_block, "Manual block")


@blocklist_bp.route("/api/v1/blocklist/remove", methods=["POST"])
@require_auth
def blocklist_remove():
    return _command_response(_unblock, "Blocklist remove")


@blocklist_bp.route("/blocklist/unblock", methods=["POST"])
@require_auth
def blocklist_manual_unblock():
    return _command_response(_unblock, "Manual unblock")


@blocklist_bp.route("/api/v1/blocklist", methods=["GET"])
@require_auth
def blocklist_get():
    blocker, _ = _blocking_services()
    return jsonify(
        {
            "blocklist": blocker.get_blocklist(),
            "history": blocker.get_history(limit=20),
            "enabled": blocker.enabled,
            "auto_block_enabled": blocker.auto_block_enabled,
            "device_count": blocker.device_count,
        }
    )


@blocklist_bp.route("/block/status")
@require_auth
def block_status():
    blocker, _ = _blocking_services()
    return jsonify(
        {
            "enabled": blocker.enabled,
            "auto_block_enabled": blocker.auto_block_enabled,
            "auto_block_min_score": blocker.auto_block_min_score,
            "device_count": blocker.device_count,
            "devices": list(blocker.device_names),
            "retry_queue": blocker.get_retry_queue_status(),
            "history": blocker.get_history(limit=20),
            "blocklist": blocker.get_blocklist(),
        }
    )


@blocklist_bp.route("/blocklist")
@require_auth
def blocklist_page():
    return render_template("admin/blocklist.html")


@blocklist_bp.route("/blocklist/data")
@require_auth
def blocklist_data():
    _, ledger = _blocking_services()
    source = request.args.get("source", "all")
    search = request.args.get("q", "")
    status = request.args.get("status")
    page = max(1, request.args.get("page", 1, type=int))
    per_page = 30
    site_id = _site_filter()
    entries, total = ledger.get_entries(
        limit=per_page,
        offset=(page - 1) * per_page,
        source_filter=source,
        search=search,
        status=status,
        site_id=site_id,
    )
    return jsonify(
        {
            "entries": entries,
            "stats": ledger.get_stats(site_id=site_id),
            "page": page,
            "total_pages": max(1, (total + per_page - 1) // per_page),
            "total": total,
        }
    )


@blocklist_bp.route("/blocklist/notes", methods=["POST"])
@require_auth
def blocklist_update_notes():
    try:
        data = _payload()
        ip = str(data.get("ip") or "")
        if not ip:
            raise ValueError("ip is required")
        site = _site_identity(data.get("site_id"))
        _, ledger = _blocking_services()
        updated = ledger.update_notes(
            ip,
            str(data.get("notes") or ""),
            site_id=site.site_id,
        )
        return jsonify({"success": updated}), (200 if updated else 404)
    except ValueError as exc:
        return jsonify({"success": False, "message": str(exc)}), 400


@blocklist_bp.route("/blocklist/devices")
@require_auth
def blocklist_devices():
    blocker, _ = _blocking_services()
    return jsonify({"devices": blocker.device_status()})


@blocklist_bp.route("/blocklist/export")
@require_auth
def blocklist_export():
    fmt = request.args.get("format", "json").lower()
    if fmt not in {"json", "csv"}:
        return jsonify({"success": False, "message": "format must be json or csv"}), 400
    _, ledger = _blocking_services()
    data = ledger.export_ledger(fmt, site_id=_site_filter())
    mime = "text/csv" if fmt == "csv" else "application/json"
    return Response(
        data,
        mimetype=mime,
        headers={"Content-Disposition": f"attachment;filename=block_ledger.{fmt}"},
    )
