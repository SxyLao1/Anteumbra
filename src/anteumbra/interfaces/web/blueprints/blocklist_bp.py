# -*- coding: utf-8 -*-
"""
v1.9.0: Blocklist Blueprint — IP 封禁台账 + 封禁 API

从 admin_bp.py 拆分。
路由前缀: /admin/blocklist/*, /admin/api/v1/blocklist/*, /admin/block/*
"""
import logging

from flask import (
    Blueprint, render_template, request, jsonify,
    Response, current_app
)

from anteumbra.interfaces.web.auth import require_auth
from anteumbra.interfaces.web.runtime import get_runtime

logger = logging.getLogger(__name__)

# ── Blueprint ──────────────────────────────────────────────

blocklist_bp = Blueprint('blocklist', __name__, url_prefix='/admin')


# ── Blocklist API ──────────────────────────────────────────

@blocklist_bp.route('/api/v1/blocklist/add', methods=['POST'])
@require_auth
def blocklist_add():
    """封禁 IP — 自动写入 BlockLedger"""
    try:
        data = request.get_json()
        ips = data.get('ips', [])
        profile_id = data.get('profile_id', '')
        reason = data.get('reason', '') or 'Manual block from Anteumbra'
        source = data.get('source', 'manual')

        if not ips:
            return jsonify({"success": False, "message": "No IPs provided"}), 400

        if profile_id and not data.get('reason'):
            try:
                tg = get_runtime().threat_graph
                if tg is None:
                    raise RuntimeError("ThreatGraph is not configured")
                profile = tg.query_profile(profile_id)
                if profile:
                    tool = profile.tool_signature or 'Unknown tool'
                    risk = round(profile.risk_score * 100)
                    reason = f"Profile {profile_id[:8]} — {tool} / risk {risk}%"
                    if profile.risk_score >= 0.7:
                        source = "auto"
            except Exception:
                logger.debug("Failed to auto-generate block reason from threat profile", exc_info=True)

        from anteumbra.application.ip_blocker_service import get_ip_blocker
        blocker = get_ip_blocker()
        results = blocker.block(ips, reason=reason, profile_id=profile_id)
        success_count = sum(1 for r in results if r.success)

        for ip in ips:
            try:
                from anteumbra.application.block_ledger_service import add_entry
                add_entry(
                    ip=ip, source=source, reason=reason,
                    profile_id=profile_id, blocked_by="admin",
                    broadcast_results=[
                        {"device": r.device_name, "success": r.success, "message": r.message}
                        for r in results if r.ip == ip
                    ]
                )
            except Exception as le:
                current_app.logger.warning(f"[BLOCKLIST] ledger write failed for {ip}: {le}")

        return jsonify({
            "success": success_count > 0,
            "message": f"Blocked {success_count}/{len(results)} across {len(blocker.devices)} device(s)",
            "results": [{"device": r.device_name, "ip": r.ip, "success": r.success, "message": r.message} for r in results]
        })
    except Exception as e:
        current_app.logger.error(f"[BLOCKLIST] add failed: {e}", exc_info=True)
        return jsonify({"success": False, "message": str(e)}), 500


@blocklist_bp.route('/api/v1/blocklist/remove', methods=['POST'])
@require_auth
def blocklist_remove():
    """解封 IP"""
    try:
        data = request.get_json()
        ips = data.get('ips', [])
        if not ips:
            return jsonify({"success": False, "message": "No IPs provided"}), 400

        from anteumbra.application.ip_blocker_service import get_ip_blocker
        blocker = get_ip_blocker()
        results = blocker.unblock(ips)
        success_count = sum(1 for r in results if r.success)
        return jsonify({
            "success": success_count > 0,
            "message": f"Unblocked {success_count}/{len(results)}",
            "results": [{"device": r.device_name, "ip": r.ip, "success": r.success} for r in results]
        })
    except Exception as e:
        current_app.logger.error(f"[BLOCKLIST] remove failed: {e}", exc_info=True)
        return jsonify({"success": False, "message": str(e)}), 500


@blocklist_bp.route('/api/v1/blocklist', methods=['GET'])
@require_auth
def blocklist_get():
    """获取当前黑名单"""
    try:
        from anteumbra.application.ip_blocker_service import get_ip_blocker
        blocker = get_ip_blocker()
        return jsonify({
            "blocklist": blocker.get_blocklist(),
            "history": blocker.get_history(limit=20),
            "auto_block_enabled": blocker._auto_block_enabled,
            "device_count": len(blocker.devices),
        })
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


# ── Block Status ───────────────────────────────────────────

@blocklist_bp.route('/block/status')
@require_auth
def block_status():
    """封禁状态面板数据"""
    try:
        from anteumbra.application.ip_blocker_service import get_ip_blocker
        blocker = get_ip_blocker()
        return jsonify({
            "auto_block_enabled": blocker._auto_block_enabled,
            "auto_block_min_score": blocker._auto_block_min_score,
            "device_count": len(blocker.devices),
            "devices": [d.get_name() for d in blocker.devices],
            "retry_queue": blocker.get_retry_queue_status(),
            "history": blocker.get_history(limit=20),
            "blocklist": blocker.get_blocklist(),
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── Block Audit Ledger ─────────────────────────────────────

@blocklist_bp.route('/blocklist')
@require_auth
def blocklist_page():
    """封禁台账页面"""
    try:
        return render_template('admin/blocklist.html')
    except Exception as e:
        current_app.logger.error(f"[BLOCKLIST] page error: {e}", exc_info=True)
        return render_template('admin/error.html', error=str(e)), 500


@blocklist_bp.route('/blocklist/data')
@require_auth
def blocklist_data():
    """台账数据 JSON（分页 + 筛选）"""
    try:
        from anteumbra.application.block_ledger_service import get_entries, get_stats
        source = request.args.get('source', 'all')
        search = request.args.get('q', '')
        page = max(1, request.args.get('page', 1, type=int))
        per_page = 30
        offset = (page - 1) * per_page
        entries, total = get_entries(limit=per_page, offset=offset, source_filter=source, search=search)
        total_pages = max(1, (total + per_page - 1) // per_page)
        return jsonify({
            "entries": entries,
            "stats": get_stats(),
            "page": page,
            "total_pages": total_pages,
            "total": total,
        })
    except Exception as e:
        current_app.logger.error(f"[BLOCKLIST] data error: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@blocklist_bp.route('/blocklist/notes', methods=['POST'])
@require_auth
def blocklist_update_notes():
    """更新封禁备注"""
    try:
        data = request.get_json() or {}
        ip = data.get('ip', '')
        notes = data.get('notes', '')
        if not ip:
            return jsonify({"error": "missing ip"}), 400
        from anteumbra.application.block_ledger_service import update_notes
        ok = update_notes(ip, notes)
        return jsonify({"success": ok})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@blocklist_bp.route('/blocklist/devices')
@require_auth
def blocklist_devices():
    """获取可用封禁设备列表"""
    try:
        from anteumbra.application.ip_blocker_service import get_ip_blocker
        blocker = get_ip_blocker()
        devices = [{'name': d.get_name(), 'available': d.is_available()} for d in blocker.devices]
        return jsonify({'devices': devices})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@blocklist_bp.route('/blocklist/block', methods=['POST'])
@require_auth
def blocklist_manual_block():
    """手动封禁（从台账页）"""
    try:
        from anteumbra.application.ip_blocker_service import get_ip_blocker, BlockDecision
        from anteumbra.application.block_ledger_service import add_entry
        data = request.get_json() or {}
        ips = data.get('ips', [])
        reason = data.get('reason', 'Manual block')
        devices_filter = data.get('devices', [])
        if not ips:
            return jsonify({'success': False, 'message': 'No IPs'}), 400
        blocker = get_ip_blocker()
        if devices_filter:
            results = []
            for ip in ips:
                for dev in blocker.devices:
                    if dev.get_name() in devices_filter:
                        results.append(dev.block(BlockDecision(ip=ip, reason=reason)))
        else:
            results = blocker.block(ips, reason=reason)
        success = sum(1 for r in results if r.success)
        for ip in ips:
            add_entry(ip=ip, source='manual', reason=reason,
                      broadcast_results=[{'device': r.device_name, 'success': r.success} for r in results if r.ip == ip])
        return jsonify({'success': success > 0, 'message': f'Blocked {success}/{len(results)}',
                        'results': [{'device': r.device_name, 'ip': r.ip, 'success': r.success, 'message': r.message} for r in results]})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


@blocklist_bp.route('/blocklist/unblock', methods=['POST'])
@require_auth
def blocklist_manual_unblock():
    """手动解封（从台账页）"""
    try:
        from anteumbra.application.ip_blocker_service import get_ip_blocker
        data = request.get_json() or {}
        ips = data.get('ips', [])
        devices_filter = data.get('devices', [])
        if not ips:
            return jsonify({'success': False, 'message': 'No IPs'}), 400
        blocker = get_ip_blocker()
        if devices_filter:
            results = []
            for ip in ips:
                for dev in blocker.devices:
                    if dev.get_name() in devices_filter:
                        results.append(dev.unblock(ip))
        else:
            results = blocker.unblock(ips)
        success = sum(1 for r in results if r.success)
        return jsonify({'success': success > 0, 'message': f'Unblocked {success}/{len(results)}',
                        'results': [{'device': r.device_name, 'ip': r.ip, 'success': r.success, 'message': r.message} for r in results]})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


@blocklist_bp.route('/blocklist/export')
@require_auth
def blocklist_export():
    """导出台账"""
    fmt = request.args.get('format', 'json')
    from anteumbra.application.block_ledger_service import export_ledger
    data = export_ledger(fmt)
    if fmt == 'csv':
        return Response(data, mimetype='text/csv',
                       headers={'Content-Disposition': 'attachment;filename=block_ledger.csv'})
    return Response(data, mimetype='application/json',
                   headers={'Content-Disposition': 'attachment;filename=block_ledger.json'})
