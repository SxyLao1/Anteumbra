# -*- coding: utf-8 -*-
"""
v1.9.0: Records Blueprint — 检测记录 + 审计日志 + 文件查看器

从 admin_bp.py 拆分。
路由前缀: /admin/records/*, /admin/search, /admin/remove/*,
         /admin/mark_false_positive/*, /admin/audit, /admin/file/*
"""

import json
import logging
from pathlib import Path
from urllib.parse import unquote

from flask import Blueprint, abort, current_app, jsonify, render_template, request
from markupsafe import escape as html_escape

from anteumbra.application.path_service import normalize_path, path_to_key
from anteumbra.application.site_read_model import site_fields, site_names
from anteumbra.application.text_encoding import decode_source_bytes
from anteumbra.interfaces.web.auth import require_auth
from anteumbra.interfaces.web.blueprints._shared import (
    verify_file_in_quarantine,
    verify_file_in_registry,
)
from anteumbra.interfaces.web.pages import active_site_id, render_page, site_context
from anteumbra.interfaces.web.runtime import get_runtime

logger = logging.getLogger(__name__)


def _registry():
    """Return the Registry owned by the current Flask runtime."""
    return get_runtime().registry


# ── Blueprint ──────────────────────────────────────────────

records_bp = Blueprint("records", __name__, url_prefix="/admin")


# ── Helper ─────────────────────────────────────────────────


def _deserialize_list(value):
    """v2.0 fix: SQLite stores list fields as JSON strings.
    Deserialize them back to Python lists so templates can iterate properly.
    """
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            if isinstance(parsed, list):
                return parsed
        except (json.JSONDecodeError, TypeError):
            pass
    return [str(value)] if value else []


def _configured_site_names() -> dict:
    """Return ``site_id -> name`` for records whose stored name is missing."""
    try:
        return site_names(get_runtime().config.get_enabled_websites())
    except Exception:
        logger.debug("configured site names are unavailable", exc_info=True)
        return {}


def _enhance_records(raw_records):
    """将 Registry 原始记录增强为前端可用的字典列表

    Each row keeps its **own** site identity: the list may be showing every
    site, and a record's site is what identifies it — never the active filter.
    """
    names_by_id = _configured_site_names()
    enhanced = []
    for r in raw_records:
        try:
            display_name = normalize_path(r.get("file_path", "")).name
        except Exception:
            display_name = Path(r.get("file_path", "")).name
        entry = {
            "file_exists": r.get("file_exists", False),
            "alerted": r.get("alerted", False),
            "marked_false_positive": r.get("marked_false_positive", False),
            "display_name": display_name,
            "detected_at": r.get("detected_at", "")[:16] if r.get("detected_at") else "N/A",
            "features": _deserialize_list(r.get("features")),
            "communication_count": r.get("communication_count", 0),
            "file_path": r.get("file_path", ""),
            "deleted_at": r.get("deleted_at", ""),
            "missing_reason": r.get("missing_reason", ""),
            "content_hash": r.get("content_hash", ""),
            "quarantine_id": r.get("quarantine_id", ""),
        }
        entry.update(site_fields(r, names_by_id=names_by_id))
        enhanced.append(entry)
    return enhanced


def _requested_site_id():
    """Return the site this request acts within, or ``None`` for every site.

    The URL wins (``?site=`` and the legacy ``?site_id=``), then the scope the
    operator chose earlier.  Mutations post the same parameter, so an action
    taken from an aggregate list still resolves the record it belongs to.
    """
    value = request.values.get("site") or request.values.get("site_id")
    if value:
        return str(value).strip().lower()
    return active_site_id()


def _find_record(file_path, *, site_id=None):
    """Resolve one record without allowing an ambiguous cross-site mutation."""
    target = path_to_key(file_path)
    matches = [
        record
        for record in _registry().get_all(
            include_deleted=True,
            include_false_positive=True,
            site_id=site_id,
        )
        if record.get("file_path") == target
    ]
    if len(matches) > 1:
        logger.warning(
            "[RECORDS] refusing ambiguous record operation for %s; site_id is required",
            target,
        )
        return None
    return matches[0] if matches else None


# ── Records List ───────────────────────────────────────────


@records_bp.route("/records", methods=["GET"])
@require_auth
def get_records():
    """检测记录列表（支持强制刷新、分页、审计模式）"""
    try:
        force_reload = request.args.get("force", "false").lower() == "true"
        # One ledger, filtered by status: the audit view is no longer a separate
        # tab, so "all" is the default and includes reviewed false positives and
        # soft-deleted entries.  audit=true stays supported for old links.
        status_filter = str(request.args.get("status", "") or "").lower()
        if not status_filter:
            status_filter = (
                "all" if request.args.get("audit", "false").lower() in ("true", "1") else "all"
            )
        if status_filter not in ("all", "active", "false_positive", "deleted"):
            status_filter = "all"
        include_reviewed = status_filter in ("all", "false_positive", "deleted")
        audit_mode = status_filter in ("all", "deleted")
        site_id = _requested_site_id()

        page_str = request.args.get("page", "1")
        try:
            page = max(1, int(page_str))
        except (ValueError, TypeError):
            current_app.logger.warning(f"[RECORDS] 无效page参数: '{page_str}'，使用默认值1")
            page = 1

        config = get_runtime().config.get()
        per_page = config.get("web_admin", {}).get("items_per_page", 20)

        if force_reload:
            _registry().reload()
            current_app.logger.info("[RECORDS] 强制刷新：已清除内存缓存")

        all_records = _registry().get_all(
            include_deleted=audit_mode,
            include_false_positive=include_reviewed,
            site_id=site_id,
        )

        # v2.0 fix: Always exclude quarantined items (they have their own Quarantine page)
        all_records = [r for r in all_records if not r.get("quarantine_id")]

        if status_filter == "false_positive":
            all_records = [r for r in all_records if r.get("marked_false_positive")]
        elif status_filter == "deleted":
            all_records = [
                r for r in all_records if r.get("deleted_at") and not r.get("file_exists")
            ]
        elif status_filter == "active":
            all_records = [
                r
                for r in all_records
                if not r.get("marked_false_positive") and r.get("file_exists")
            ]

        total = len(all_records)
        total_pages = max(1, (total + per_page - 1) // per_page)
        page = min(page, total_pages)
        start = (page - 1) * per_page
        end = start + per_page
        paginated = all_records[start:end]
        enhanced = _enhance_records(paginated)
        all_paths = [r.get("file_path", "") for r in all_records if r.get("file_path")]

        compact = request.args.get("compact") == "1"
        if request.headers.get("HX-Request") or request.headers.get("Sec-Fetch-Dest") == "document":
            return render_page(
                "admin/records_table.html",
                records=enhanced,
                page=page,
                total_pages=total_pages,
                total=total,
                per_page=per_page,
                audit_mode=audit_mode,
                status_filter=status_filter,
                compact=compact,
                all_paths=all_paths,
            )
        else:
            return jsonify(
                {
                    "records": enhanced,
                    "pagination": {
                        "page": page,
                        "total_pages": total_pages,
                        "total": total,
                        "per_page": per_page,
                    },
                    "audit_mode": audit_mode,
                    "status": status_filter,
                    "site_id": site_id,
                }
            )
    except Exception as e:
        current_app.logger.error(f"[RECORDS] 致命错误: {e}", exc_info=True)
        return render_template("admin/error.html", error=str(e)), 500


@records_bp.route("/records/quarantine", methods=["POST"])
@require_auth
def manual_quarantine():
    """手动隔离 — 从Records列表一键隔离"""
    try:
        file_path = request.form.get("file_path", "")
        if not file_path:
            return jsonify({"error": "缺少 file_path 参数"}), 400

        record = _find_record(file_path, site_id=_requested_site_id())

        if not record:
            return jsonify({"error": "文件不在检测记录中"}), 404
        if record.get("quarantine_id"):
            return jsonify({"error": "文件已被隔离", "quarantine_id": record["quarantine_id"]}), 409

        features = record.get("features", [])
        rule_name = features[0] if features else "manual_quarantine"
        result = get_runtime().quarantine.quarantine_file(
            file_path=str(file_path),
            rule_name=rule_name,
            features=features,
            original_path=str(file_path),
            site_id=record.get("site_id"),
            site_name=record.get("site_name"),
        )

        if result is None:
            return jsonify({"error": "隔离失败，文件可能已被删除或移动"}), 500

        current_app.logger.info(f"[RECORDS] 手动隔离成功: {file_path} -> {result['quarantine_id']}")
        return jsonify(
            {
                "success": True,
                "quarantine_id": result["quarantine_id"],
                "message": f"已隔离: {result['quarantine_id']}",
            }
        )
    except Exception as e:
        current_app.logger.error(f"[RECORDS] 手动隔离失败: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@records_bp.route("/records/batch", methods=["POST"])
@require_auth
def records_batch():
    """批量操作：隔离/误报/删除"""
    try:
        action = request.form.get("action", "")
        file_paths = request.form.getlist("file_paths[]")
        if not file_paths:
            return jsonify({"error": "missing file_paths"}), 400

        results = {"success": 0, "failed": 0, "skipped": 0, "errors": []}
        site_id = _requested_site_id()
        if action == "quarantine":
            for fp in file_paths:
                try:
                    record = _find_record(fp, site_id=site_id)
                    if not record or record.get("quarantine_id"):
                        results["skipped"] += 1
                        continue
                    features = record.get("features", [])
                    rule = features[0] if features else "batch"
                    qr = get_runtime().quarantine.quarantine_file(
                        str(fp),
                        rule,
                        features,
                        str(fp),
                        record.get("site_id"),
                        record.get("site_name"),
                    )
                    if qr:
                        results["success"] += 1
                    else:
                        results["failed"] += 1
                        results["errors"].append(
                            {
                                "file_path": fp,
                                "error": "source file is missing or could not be moved",
                            }
                        )
                except Exception as exc:
                    results["failed"] += 1
                    results["errors"].append({"file_path": fp, "error": str(exc)})
                    current_app.logger.error(
                        "[RECORDS] batch quarantine failed for %s: %s",
                        fp,
                        exc,
                        exc_info=True,
                    )
        elif action == "false_positive":
            # v1.1.0: Use public mark_false_positive() API (was inline load→mutate→save)
            for fp in file_paths:
                try:
                    record = _find_record(fp, site_id=site_id)
                    if _registry().mark_false_positive(
                        fp, "", record.get("site_id") if record else None
                    ):
                        results["success"] += 1
                    else:
                        results["skipped"] += 1
                except Exception as exc:
                    results["failed"] += 1
                    results["errors"].append({"file_path": fp, "error": str(exc)})
                    current_app.logger.error(
                        "[RECORDS] batch false-positive failed for %s: %s",
                        fp,
                        exc,
                        exc_info=True,
                    )
        elif action == "unmark_false_positive":
            # Undo a review: the record returns to the active threat set.
            for fp in file_paths:
                try:
                    record = _find_record(fp, site_id=site_id)
                    if _registry().unmark_false_positive(
                        fp, record.get("site_id") if record else None
                    ):
                        results["success"] += 1
                    else:
                        results["skipped"] += 1
                except Exception as exc:
                    results["failed"] += 1
                    results["errors"].append({"file_path": fp, "error": str(exc)})
                    current_app.logger.error(
                        "[RECORDS] batch unmark-false-positive failed for %s: %s",
                        fp,
                        exc,
                        exc_info=True,
                    )
        elif action == "delete":
            # v1.1.0: Use public soft_delete_record() API (was inline load→mutate→save)
            for fp in file_paths:
                try:
                    record = _find_record(fp, site_id=site_id)
                    if _registry().soft_delete_record(
                        fp, record.get("site_id") if record else None
                    ):
                        results["success"] += 1
                    else:
                        results["skipped"] += 1
                except Exception as exc:
                    results["failed"] += 1
                    results["errors"].append({"file_path": fp, "error": str(exc)})
                    current_app.logger.error(
                        "[RECORDS] batch delete failed for %s: %s",
                        fp,
                        exc,
                        exc_info=True,
                    )
        else:
            return jsonify({"error": "unknown action"}), 400

        # v2.0 fix: Trigger stats refresh in dashboard via HTMX header
        resp = jsonify(results)
        resp.headers["HX-Trigger"] = "anteumbra:statsRefresh"
        return resp, 207 if results["failed"] else 200
    except Exception as e:
        current_app.logger.error(f"[RECORDS] batch error: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


# ── Record Detail ──────────────────────────────────────────


@records_bp.route("/records/detail", methods=["GET"])
@require_auth
def get_record_detail():
    """获取单个检测记录的完整详情"""
    try:
        file_path = request.args.get("file_path", "")
        if not file_path:
            return jsonify({"error": "缺少 file_path 参数"}), 400

        site_id = _requested_site_id()
        record = _find_record(file_path, site_id=site_id)
        if not record:
            return jsonify({"error": "记录不存在"}), 404

        try:
            file_path_obj = normalize_path(file_path)
            display_name = file_path_obj.name
            file_size = file_path_obj.stat().st_size if file_path_obj.exists() else 0
        except Exception:
            display_name = Path(file_path).name
            file_size = 0

        quarantine_records = get_runtime().quarantine.list_records(
            status=None, site_id=record.get("site_id")
        )
        quarantine_info = None
        for q in quarantine_records:
            if q.get("original_path", "") == file_path:
                quarantine_info = q
                break

        linked_profiles = []
        try:
            tg = get_runtime().threat_graph
            for profile in tg.find_profiles_for_file(
                file_path,
                site_id=record.get("site_id"),
            ):
                linked_profiles.append(
                    {
                        "profile_id": profile.profile_id,
                        "risk_score": round(profile.risk_score, 2),
                        "ip_count": len(profile.ip_pool),
                        "tool_signature": profile.tool_signature or "N/A",
                    }
                )
        except Exception:
            logger.debug("Failed to load linked threat profiles for record detail", exc_info=True)

        site = site_fields(record, names_by_id=_configured_site_names())
        detail = {
            "file_path": file_path,
            "display_name": display_name,
            "detected_at": record.get("detected_at", "N/A"),
            "features": record.get("features", []),
            "rule_name": record.get("features", ["未知"])[0] if record.get("features") else "未知",
            "file_exists": record.get("file_exists", False),
            "file_size": file_size,
            "communication_count": record.get("communication_count", 0),
            "first_seen_ip": record.get("first_seen_ip", "N/A"),
            "alerted": record.get("alerted", False),
            "marked_false_positive": record.get("marked_false_positive", False),
            "site_id": record.get("site_id", "legacy"),
            "site_name": record.get("site_name", "Legacy / unassigned"),
            "site_unassigned": site["site_unassigned"],
            "site_label": "" if site["site_unassigned"] else site["site_name"],
            "deleted_at": record.get("deleted_at", "N/A"),
            "missing_reason": record.get("missing_reason", ""),
            "missing_at": record.get("missing_at", ""),
            "content_hash": record.get("content_hash", ""),
            "quarantine_info": quarantine_info,
            "linked_profiles": linked_profiles,
        }

        if request.headers.get("HX-Request"):
            return render_template("admin/record_detail.html", record=detail, **site_context())
        else:
            return jsonify(detail)
    except Exception as e:
        current_app.logger.error(f"[RECORDS] detail error: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


# ── Search ─────────────────────────────────────────────────


@records_bp.route("/search")
@require_auth
def search():
    """HTMX 搜索端点"""
    query = request.args.get("q", "").lower()
    records = _registry().get_all(include_deleted=True, site_id=_requested_site_id())
    filtered = [
        r
        for r in records
        if query in str(r.get("file_path", "")).lower()
        or query in str(r.get("features", [])).lower()
    ]
    enhanced = _enhance_records(filtered)
    compact = request.args.get("compact") == "1"
    return render_template(
        "admin/records_table.html",
        records=enhanced,
        page=1,
        total_pages=1,
        total=len(enhanced),
        per_page=len(enhanced),
        compact=compact,
        **site_context(),
    )


# ── Remove ─────────────────────────────────────────────────


@records_bp.route("/remove/<path:file_path>", methods=["POST"])
@require_auth
def remove_file(file_path):
    """物理删除记录"""
    try:
        page_str = request.args.get("page", "1")
        try:
            page = max(1, int(page_str))
        except (ValueError, TypeError):
            page = 1

        decoded_path = unquote(file_path)
        current_app.logger.warning(f"[RECORDS] 物理删除记录: {decoded_path}")
        normalized_path = normalize_path(decoded_path)
        target_key = path_to_key(normalized_path)
        site_id = _requested_site_id()
        success = _registry().remove(target_key, site_id=site_id)

        if not success:
            return jsonify({"status": "error", "message": "删除失败或记录不存在"}), 404

        get_runtime().sse.trigger_registry_update()

        filtered_records = _registry().get_all(
            include_deleted=False,
            include_false_positive=False,
            site_id=site_id,
        )
        enhanced = _enhance_records(filtered_records)

        config = get_runtime().config.get()
        per_page = config.get("web_admin", {}).get("items_per_page", 20)
        total = len(enhanced)
        total_pages = max(1, (total + per_page - 1) // per_page)
        page = min(page, total_pages)

        compact = request.args.get("compact") == "1"
        return render_template(
            "admin/records_table.html",
            records=enhanced,
            page=page,
            total_pages=total_pages,
            total=total,
            per_page=per_page,
            compact=compact,
            **site_context(),
        )
    except Exception as e:
        current_app.logger.error(f"[RECORDS] 物理删除失败: {e}", exc_info=True)
        return render_template("admin/error.html", error=str(e)), 500


# ── False Positive ─────────────────────────────────────────


def _records_table_response(status_filter: str = "all"):
    """Re-render the ledger for the current status filter after a review change."""
    status_filter = (
        status_filter if status_filter in ("all", "active", "false_positive", "deleted") else "all"
    )
    site_id = _requested_site_id()
    include_reviewed = status_filter in ("all", "false_positive", "deleted")
    records = _registry().get_all(
        include_deleted=status_filter in ("all", "deleted"),
        include_false_positive=include_reviewed,
        site_id=site_id,
    )
    records = [r for r in records if not r.get("quarantine_id")]
    if status_filter == "false_positive":
        records = [r for r in records if r.get("marked_false_positive")]
    elif status_filter == "deleted":
        records = [r for r in records if r.get("deleted_at") and not r.get("file_exists")]
    elif status_filter == "active":
        records = [
            r for r in records if not r.get("marked_false_positive") and r.get("file_exists")
        ]

    enhanced = _enhance_records(records)
    config = get_runtime().config.get()
    per_page = config.get("web_admin", {}).get("items_per_page", 20)
    total = len(enhanced)
    return render_template(
        "admin/records_table.html",
        records=enhanced,
        page=1,
        total_pages=max(1, (total + per_page - 1) // per_page),
        total=total,
        per_page=per_page,
        status_filter=status_filter,
        compact=request.args.get("compact") == "1",
        all_paths=[r.get("file_path", "") for r in enhanced if r.get("file_path")],
        **site_context(),
    )


@records_bp.route("/mark_false_positive/<path:file_path>", methods=["POST"])
@require_auth
def mark_false_positive_route(file_path):
    """标记为误报 — v2.0: 委托给 centralized suspicious_registry.mark_false_positive()"""
    try:
        decoded_path = unquote(file_path)
        normalized_path = normalize_path(decoded_path)

        site_id = _requested_site_id()
        ok = _registry().mark_false_positive(normalized_path, site_id=site_id)
        if not ok:
            return jsonify({"status": "error", "message": "记录不存在"}), 404

        get_runtime().sse.trigger_registry_update()
        return _records_table_response(str(request.args.get("status", "all")))
    except Exception as e:
        current_app.logger.error(f"[RECORDS] 误报标记失败: {e}", exc_info=True)
        return render_template("admin/error.html", error=str(e)), 500


@records_bp.route("/unmark_false_positive/<path:file_path>", methods=["POST"])
@require_auth
def unmark_false_positive_route(file_path):
    """取消误报 — return a reviewed false positive to the active set."""
    try:
        decoded_path = unquote(file_path)
        normalized_path = normalize_path(decoded_path)

        site_id = _requested_site_id()
        ok = _registry().unmark_false_positive(normalized_path, site_id=site_id)
        if not ok:
            return jsonify({"status": "error", "message": "记录不存在"}), 404

        get_runtime().sse.trigger_registry_update()
        return _records_table_response(str(request.args.get("status", "all")))
    except Exception as e:
        current_app.logger.error(f"[RECORDS] 取消误报失败: {e}", exc_info=True)
        return render_template("admin/error.html", error=str(e)), 500


@records_bp.route("/records/rearm_alert/<path:file_path>", methods=["POST"])
@require_auth
def rearm_alert_route(file_path):
    """重新告警 — re-arm alerting so the next detection of this file reports again.

    Repeat alerts are suppressed while the standing alert still covers the exact
    bytes on disk, so an operator who wants to be told again needs a way to say
    so without deleting the file or faking a false-positive review.
    """
    try:
        decoded_path = unquote(file_path)
        normalized_path = normalize_path(decoded_path)

        site_id = _requested_site_id()
        if not _registry().clear_alert_state(normalized_path, site_id=site_id):
            return jsonify({"status": "error", "message": "记录不存在"}), 404

        current_app.logger.info("[RECORDS] 重新告警: %s", normalized_path)
        get_runtime().sse.trigger_registry_update()
        return jsonify({"status": "ok"})
    except Exception as e:
        current_app.logger.error(f"[RECORDS] 重新告警失败: {e}", exc_info=True)
        return jsonify({"status": "error", "message": str(e)}), 500


# ── Audit Log ──────────────────────────────────────────────


@records_bp.route("/audit")
@require_auth
def audit_records():
    """审计日志 — 懒加载 HTMX 分页"""
    try:
        page = max(1, request.args.get("page", 1, type=int))
        config = get_runtime().config.get()
        per_page = config.get("web_admin", {}).get("items_per_page", 20)

        all_records = _registry().get_all(
            include_deleted=True,
            include_false_positive=True,
            site_id=_requested_site_id(),
        )
        total = len(all_records)
        total_pages = max(1, (total + per_page - 1) // per_page)
        page = min(page, total_pages)
        start = (page - 1) * per_page
        paginated = all_records[start : start + per_page]
        enhanced = _enhance_records(paginated)

        return render_template(
            "admin/records_table.html",
            records=enhanced,
            page=page,
            total_pages=total_pages,
            total=total,
            per_page=per_page,
            audit_mode=True,
            all_paths=[r.get("file_path", "") for r in all_records if r.get("file_path")],
            **site_context(),
        )
    except Exception as e:
        current_app.logger.error(f"[RECORDS] audit error: {e}", exc_info=True)
        return render_template("admin/error.html", error=str(e)), 500


# ── File Content Viewer ────────────────────────────────────


@records_bp.route("/file/content", methods=["GET"])
@require_auth
def view_file_content():
    """安全文件内容查看器（白名单 + HTML 转义）"""
    try:
        file_path = request.args.get("path", "")
        quarantine_id = request.args.get("qid", "")

        # 路径穿越基础检测
        if ".." in file_path or ".." in quarantine_id:
            abort(403)

        actual_path = None
        if quarantine_id:
            actual_path = verify_file_in_quarantine(quarantine_id)
        elif file_path:
            if verify_file_in_registry(file_path):
                actual_path = Path(file_path)
        else:
            return jsonify({"error": "缺少 path 或 qid 参数"}), 400

        if not actual_path or not actual_path.exists():
            return jsonify({"error": "文件不存在或无权访问"}), 404

        # 二次路径穿越确认
        resolved = actual_path.resolve()
        if ".." in str(resolved):
            abort(403)

        size = resolved.stat().st_size
        if size > 512 * 1024:
            return jsonify({"error": f"文件过大 ({size} bytes)，上限 512KB"}), 413

        content, encoding = decode_source_bytes(resolved.read_bytes())
        escaped = html_escape(content)

        return jsonify(
            {
                "path": str(actual_path),
                "size": size,
                "content": escaped,
                "lines": content.count("\n") + 1,
                "encoding": encoding,
            }
        )
    except Exception as e:
        current_app.logger.error(f"[RECORDS] file content error: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500
