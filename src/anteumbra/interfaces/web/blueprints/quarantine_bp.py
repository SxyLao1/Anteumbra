from datetime import datetime
# -*- coding: utf-8 -*-
"""
@Time: 2026-06-09
@Auth: SxyLao1
@File: quarantine_bp.py
@IDE: PyCharm
@Motto: HACK THE REAL

v1.7.9 新增：隔离管理后台蓝图
"""
from flask import Blueprint, render_template, request, jsonify, current_app

from anteumbra.application.quarantine_service import (
    get_quarantine_list, get_quarantine_detail, get_quarantine_stats,
    restore_file, delete_quarantine
)
from anteumbra.interfaces.web.auth import require_auth
from anteumbra.interfaces.web.runtime import get_runtime

quarantine_bp = Blueprint('quarantine', __name__, url_prefix='/admin')


def _requested_site_id():
    """Read an optional site boundary from either query or form input."""
    return request.values.get("site_id") or None


def _record_matches_site(record, site_id):
    """Avoid acting on a quarantine item outside the requested site boundary."""
    return not site_id or (
        record and record.get("site_id") == str(site_id).strip().lower()
    )


@quarantine_bp.route('/quarantine', methods=['GET'])
@require_auth
def quarantine_list():
    """隔离文件列表"""
    try:
        status = request.args.get('status', 'quarantined')
        site_id = request.args.get('site_id') or None
        page_str = request.args.get('page', '1')
        try:
            page = max(1, int(page_str))
        except (ValueError, TypeError):
            page = 1

        config = get_runtime().config.get()
        per_page = config.get("web_admin", {}).get("items_per_page", 20)

        all_records = get_quarantine_list(
            status=status if status != 'all' else None,
            site_id=site_id,
        )

        # v1.8.4: 搜索过滤
        q = request.args.get('q', '').lower()
        if q:
            all_records = [r for r in all_records
                if q in r.get('quarantine_id', '').lower()
                or q in r.get('original_path', '').lower()
                or q in r.get('quarantine_path', '').lower()
                or q in r.get('rule_name', '').lower()]

        total = len(all_records)
        total_pages = max(1, (total + per_page - 1) // per_page)
        page = min(page, total_pages)

        start = (page - 1) * per_page
        end = start + per_page
        paginated = all_records[start:end]

        stats = get_quarantine_stats(site_id=site_id)

        all_qids = [r.get('quarantine_id', '') for r in all_records if r.get('quarantine_id')]

        compact = request.args.get('compact') == '1'
        if request.headers.get('HX-Request'):
            return render_template(
                'admin/quarantine_list.html',
                records=paginated,
                stats=stats,
                page=page,
                total_pages=total_pages,
                total=total,
                per_page=per_page,
                current_status=status,
                compact=compact,
                all_qids=all_qids,
            )
        else:
            return render_template(
                'admin/quarantine.html',
                records=paginated,
                stats=stats,
                page=page,
                total_pages=total_pages,
                total=total,
                per_page=per_page,
                current_status=status
            )

    except Exception as e:
        current_app.logger.error(f"[QUARANTINE][LIST] 错误: {e}", exc_info=True)
        return render_template('admin/error.html', error=str(e)), 500


@quarantine_bp.route('/quarantine/detail', methods=['GET'])
@require_auth
def quarantine_detail():
    """隔离详情"""
    try:
        qid = request.args.get('qid', '')
        if not qid:
            return jsonify({"error": "缺少 qid 参数"}), 400

        record = get_quarantine_detail(qid)
        if not record or not _record_matches_site(record, _requested_site_id()):
            return jsonify({"error": "记录不存在"}), 404

        if request.headers.get('HX-Request'):
            return render_template('admin/quarantine_detail.html', record=record)
        else:
            return jsonify(record)

    except Exception as e:
        current_app.logger.error(f"[QUARANTINE][DETAIL] 错误: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


def _render_quarantine_list(status=None, site_id=None):
    """v1.7.9: 渲染隔离列表片段，供 restore/delete 后刷新用"""
    config = get_runtime().config.get()
    per_page = config.get("web_admin", {}).get("items_per_page", 20)
    all_records = get_quarantine_list(status=status, site_id=site_id)
    total = len(all_records)
    total_pages = max(1, (total + per_page - 1) // per_page)
    paginated = all_records[:per_page]
    stats = get_quarantine_stats(site_id=site_id)
    return render_template('admin/quarantine_list.html',
        records=paginated, stats=stats, page=1, total_pages=total_pages,
        total=total, per_page=per_page, current_status=status or 'all')


@quarantine_bp.route('/quarantine/restore', methods=['POST'])
@require_auth
def quarantine_restore():
    """恢复隔离文件 — v1.7.9: 返回刷新后的列表HTML"""
    try:
        qid = request.form.get('qid', '') or request.args.get('qid', '')
        if not qid:
            return jsonify({"error": "缺少 qid 参数"}), 400

        site_id = _requested_site_id()
        record = get_quarantine_detail(qid)
        if not record or not _record_matches_site(record, site_id):
            return jsonify({"error": "记录不存在"}), 404

        restore_file(qid)
        # 返回刷新后的列表，保留当前筛选状态
        status = request.args.get('status', 'quarantined')
        return _render_quarantine_list(status=None, site_id=site_id)

    except Exception as e:
        current_app.logger.error(f"[QUARANTINE][RESTORE] 错误: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@quarantine_bp.route('/quarantine/delete', methods=['POST'])
@require_auth
def quarantine_delete():
    """永久删除隔离文件 — v1.7.9: 返回刷新后的列表HTML"""
    try:
        qid = request.form.get('qid', '') or request.args.get('qid', '')
        if not qid:
            return jsonify({"error": "缺少 qid 参数"}), 400

        site_id = _requested_site_id()
        record = get_quarantine_detail(qid)
        if not record or not _record_matches_site(record, site_id):
            return jsonify({"error": "记录不存在"}), 404

        delete_quarantine(qid)
        return _render_quarantine_list(status=None, site_id=site_id)

    except Exception as e:
        current_app.logger.error(f"[QUARANTINE][DELETE] 错误: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@quarantine_bp.route('/quarantine/batch', methods=['POST'])
@require_auth
def quarantine_batch():
    """v1.9.0: 批量操作 — restore / delete"""
    try:
        action = request.form.get('action', '')
        qids = request.form.getlist('qids[]')
        if not qids:
            return jsonify({"error": "missing qids"}), 400

        results = {"success": 0, "failed": 0, "skipped": 0, "errors": []}
        site_id = _requested_site_id()

        for qid in qids:
            try:
                record = get_quarantine_detail(qid)
                if not record or not _record_matches_site(record, site_id):
                    results["skipped"] += 1
                    continue
                if action == 'restore':
                    if restore_file(qid):
                        results["success"] += 1
                    else:
                        results["failed"] += 1
                elif action == 'delete':
                    # v2.0 fix: delete_quarantine() returns None (void), always count success
                    delete_quarantine(qid)
                    results["success"] += 1
                else:
                    return jsonify({"error": "unknown action"}), 400
            except Exception as exc:
                results["failed"] += 1
                results["errors"].append({"quarantine_id": qid, "error": str(exc)})
                current_app.logger.error(
                    "[QUARANTINE][BATCH] %s failed for %s: %s",
                    action, qid, exc, exc_info=True,
                )

        # v2.0 fix: Trigger stats refresh in dashboard via HTMX header
        resp = jsonify(results)
        resp.headers['HX-Trigger'] = 'anteumbra:statsRefresh'
        return resp, 207 if results["failed"] else 200
    except Exception as e:
        current_app.logger.error(f"[QUARANTINE][BATCH] error: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500
