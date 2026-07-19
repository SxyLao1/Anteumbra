# -*- coding: utf-8 -*-
"""
v1.9.0: Scanner Blueprint — 手动扫描器路由

从 admin_bp.py 拆分。
路由前缀: /admin/scanner/*
"""
import json as _json
import queue
import threading
import time
import uuid
from datetime import datetime
from pathlib import Path

from flask import (
    Blueprint, render_template, request, jsonify,
    Response, current_app, stream_with_context
)

from anteumbra.interfaces.web.auth import require_auth
from anteumbra.application.path_service import normalize_path
from anteumbra.interfaces.web.blueprints._shared import (
    save_scan_to_disk,
    load_scans_from_disk,
)
from anteumbra.interfaces.web.runtime import get_runtime

# ── Blueprint ──────────────────────────────────────────────

scanner_bp = Blueprint('scanner', __name__, url_prefix='/admin')

_SCAN_JOB_TTL = 3600



# ── Routes ─────────────────────────────────────────────────

@scanner_bp.route('/scanner')
@require_auth
def scanner_page():
    """主动扫描器页面"""
    try:
        config = get_runtime().config.get()
        websites = get_runtime().config.get_enabled_websites()
        default_site = next(iter(websites), None) if len(websites) == 1 else None
        default_dir = str(default_site.path) if default_site else ""

        default_extensions = config.get("paths", {}).get(
            "monitor_extensions", [".php", ".asp", ".aspx", ".jsp", ".jspx"]
        )
        exclude_dirs = (
            default_site.scan_options.exclude_dirs
            if default_site
            else ["cache", "logs", "temp", "data"]
        )
        return render_template('admin/scanner.html',
            default_dir=default_dir,
            default_extensions=default_extensions,
            exclude_dirs=exclude_dirs,
            sites=[
                {"site_id": site.site_id, "name": site.name, "path": str(site.path)}
                for site in websites
            ],
        )
    except Exception as e:
        current_app.logger.error(f"[SCANNER] page error: {e}", exc_info=True)
        return render_template('admin/error.html', error=str(e)), 500


def _request_data():
    if request.is_json:
        data = request.get_json(silent=True)
        if isinstance(data, dict):
            return data
    return request.form


def _is_true(value) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _complete_payload(result) -> dict:
    return {
        "event": "complete",
        "scan_id": result.scan_id,
        "site_id": getattr(result, "site_id", ""),
        "site_name": getattr(result, "site_name", ""),
        "total_files": result.total_files,
        "scanned_files": result.scanned_files,
        "new_findings": result.new_findings,
        "known_findings": result.known_findings,
        "clean": result.clean,
        "errors": result.errors,
        "duration": round(result.end_time - result.start_time, 1) if result.end_time else 0,
        "status": result.status,
        "error_message": getattr(result, "error_message", ""),
    }


def _parse_extensions(value) -> list[str] | None:
    if value is None:
        return None
    raw_items = value if isinstance(value, (list, tuple)) else str(value).split(",")
    extensions = []
    for item in raw_items:
        extension = str(item).strip().lower()
        if not extension:
            continue
        extensions.append(extension if extension.startswith(".") else f".{extension}")
    return extensions or None


def _run_scan_job(scan_id: str, runtime) -> None:
    state = runtime.scan_state
    job = state.get_job(scan_id)
    if not job:
        return

    target_dir = job["target_dir"]
    recursive = job["recursive"]
    extensions = job["extensions"]
    site_id = job["site_id"]
    site_name = job["site_name"]
    progress_queue = job["queue"]
    cancel_flag = job["cancel_flag"]
    scan_logger = runtime.logging.get_logger("scanner_sse")

    from anteumbra.application.scanner_service import ManualScanner

    try:
        scanner = ManualScanner(
            scan_logger,
            site_id=site_id,
            site_name=site_name,
            config_provider=runtime.config,
            scanner_service=runtime.scanner,
            metrics=runtime.metrics,
            registry=runtime.registry,
        )
        target = normalize_path(Path(target_dir))

        def progress_cb(result):
            try:
                progress_queue.put_nowait(('progress', {
                    'scanned': result.scanned_files,
                    'total': result.total_files,
                    'new_findings': result.new_findings,
                    'known_findings': result.known_findings,
                    'clean': result.clean,
                    'errors': result.errors,
                }))
            except queue.Full:
                pass

        def cancelled():
            return cancel_flag["cancelled"]

        result = scanner.scan_directory(
            target_dir=target,
            recursive=recursive,
            extensions=extensions,
            progress_callback=progress_cb,
            cancelled_check=cancelled,
            site_id=site_id,
            site_name=site_name,
        )
        state.update_job(
            scan_id,
            result=result,
            completed_at=time.time(),
        )
        state.put_result(result.scan_id, result)
        state.cleanup_results(_SCAN_JOB_TTL)
        save_scan_to_disk(result)
        progress_queue.put(('complete', result))
    except Exception as e:
        scan_logger.error("scanner failed: %s", e, exc_info=True)
        state.update_job(
            scan_id,
            error=str(e),
            completed_at=time.time(),
        )
        progress_queue.put(('error', str(e)))


@scanner_bp.route('/scanner/run', methods=['POST'])
@require_auth
def scanner_run():
    """Create a manual scanner job. Progress is streamed by /scanner/stream."""
    data = _request_data()
    target_dir = str(data.get('target_dir', '')).strip()
    recursive = _is_true(data.get('recursive', '1'))
    extensions = _parse_extensions(data.get('extensions'))
    requested_site_id = str(data.get('site_id', '')).strip() or None

    if not target_dir:
        return jsonify({"success": False, "error": "missing target_dir"}), 400

    runtime = get_runtime()
    try:
        identity = runtime.config.resolve_site_identity(
            target_dir, site_id=requested_site_id
        )
    except ValueError as exc:
        return jsonify({"success": False, "error": str(exc)}), 400

    runtime.scan_state.cleanup_jobs(_SCAN_JOB_TTL)
    scan_id = uuid.uuid4().hex
    job = {
        "scan_id": scan_id,
        "target_dir": target_dir,
        "recursive": recursive,
        "extensions": extensions,
        "site_id": identity.site_id,
        "site_name": identity.site_name,
        "queue": queue.Queue(),
        "cancel_flag": {"cancelled": False},
        "created_at": time.time(),
        "completed_at": None,
        "thread": None,
        "result": None,
        "error": None,
    }
    thread = threading.Thread(
        target=_run_scan_job,
        args=(scan_id, runtime),
        daemon=True,
        name=f"ManualScan-{scan_id[:8]}",
    )
    job["thread"] = thread
    runtime.scan_state.register_job(scan_id, job)
    thread.start()
    return jsonify({
        "success": True,
        "scan_id": scan_id,
        "site_id": identity.site_id,
        "stream_url": f"/admin/scanner/stream?scan_id={scan_id}",
    })


@scanner_bp.route('/scanner/stream')
@require_auth
def scanner_stream_sse():
    """SSE stream for an already-created scanner job."""
    scan_id = request.args.get('scan_id', '')
    job = get_runtime().scan_state.get_job(scan_id)

    if not job:
        def _err():
            yield f"data: {_json.dumps({'event': 'error', 'message': 'scan not found'})}\n\n"
        return Response(_err(), status=404, mimetype='text/event-stream')

    target_dir = job["target_dir"]
    recursive = job["recursive"]
    progress_queue = job["queue"]
    scan_thread = job["thread"]

    def _generate():
        try:
            t = normalize_path(Path(target_dir))
        except Exception:
            t = Path(target_dir)
        yield f"data: {_json.dumps({'event': 'init', 'target': str(t), 'recursive': recursive})}\n\n"

        findings_sent = set()
        while scan_thread.is_alive() or not progress_queue.empty():
            try:
                msg_type, payload = progress_queue.get(timeout=0.3)

                if msg_type == 'progress':
                    yield f"data: {_json.dumps({'event': 'progress', **payload})}\n\n"

                elif msg_type == 'complete':
                    result = payload
                    for finding in result.findings:
                        key = finding.get('file_path', '')
                        if key not in findings_sent:
                            findings_sent.add(key)
                            yield f"data: {_json.dumps({'event': 'finding', **finding})}\n\n"
                    yield f"data: {_json.dumps(_complete_payload(result))}\n\n"
                    return

                elif msg_type == 'error':
                    yield f"data: {_json.dumps({'event': 'error', 'message': str(payload)})}\n\n"
                    return

            except queue.Empty:
                continue

        while not progress_queue.empty():
            try:
                msg_type, payload = progress_queue.get_nowait()
                if msg_type == 'complete':
                    result = payload
                    for finding in result.findings:
                        key = finding.get('file_path', '')
                        if key not in findings_sent:
                            findings_sent.add(key)
                            yield f"data: {_json.dumps({'event': 'finding', **finding})}\n\n"
                    yield f"data: {_json.dumps(_complete_payload(result))}\n\n"
            except queue.Empty:
                break

    return Response(
        stream_with_context(_generate()),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no',
        }
    )


@scanner_bp.route('/scanner/cancel', methods=['POST'])
@require_auth
def scanner_cancel():
    """Cancel one active scanner job, or all active jobs if no scan_id is sent."""
    data = _request_data()
    scan_id = str(data.get("scan_id", "")).strip()
    cancelled = get_runtime().scan_state.cancel(scan_id or None)
    return jsonify({"success": True, "cancelled": cancelled, "message": "cancel signal sent"})


@scanner_bp.route('/scanner/quarantine', methods=['POST'])
@require_auth
def scanner_quarantine():
    """从扫描结果中一键隔离新发现文件。
    v2.0 fix: If file not found in Registry, auto-register it first.
    Scanner auto-registers findings during scanning, but this handles edge cases
    where the registry record was lost or the finding came from a saved scan.
    """
    try:
        file_path = request.form.get('file_path', '')
        if not file_path:
            return jsonify({"error": "缺少 file_path 参数"}), 400
        requested_site_id = request.form.get("site_id") or None
        identity = get_runtime().config.resolve_site_identity(
            file_path, site_id=requested_site_id
        )

        from anteumbra.application.path_service import path_to_key, normalize_path

        registry = get_runtime().registry
        target = path_to_key(file_path)
        record = None
        for r in registry.get_all(include_deleted=True, site_id=identity.site_id):
            if r.get("file_path") == target:
                record = r
                break

        # v2.0 fix: Auto-register scanner findings not yet in Registry
        if not record:
            actual_path = normalize_path(file_path)
            if actual_path.exists():
                try:
                    registry.add(
                        actual_path,
                        ["scanner_manual_quarantine"],
                        first_seen_ip="127.0.0.1",
                        detection_source="active",
                        site=identity,
                    )
                    current_app.logger.info(
                        f"[SCANNER] 自动注册后隔离: {file_path}")
                    # Re-read registry to get the new record
                    for r in registry.get_all(
                        include_deleted=True, site_id=identity.site_id
                    ):
                        if r.get("file_path") == target:
                            record = r
                            break
                except Exception as reg_err:
                    current_app.logger.error(
                        f"[SCANNER] 自动注册失败: {file_path} | {reg_err}")
            if not record:
                return jsonify({"error": "文件不在检测记录中且无法自动注册"}), 404

        if record and record.get("quarantine_id"):
            return jsonify({"error": "文件已被隔离", "quarantine_id": record["quarantine_id"]}), 409

        features = record.get("features", []) if record else ["scanner_manual_quarantine"]
        rule_name = features[0] if features else "manual_scan_quarantine"
        result = get_runtime().quarantine.quarantine_file(
            file_path=str(file_path),
            rule_name=rule_name,
            features=features,
            original_path=str(file_path),
            site_id=record.get("site_id", identity.site_id),
            site_name=record.get("site_name", identity.site_name),
        )

        if result is None:
            return jsonify({"error": "隔离失败，文件可能已被删除或移动"}), 500

        current_app.logger.info(
            f"[SCANNER] 手动隔离: {file_path} -> {result['quarantine_id']}")
        return jsonify({
            "success": True,
            "quarantine_id": result["quarantine_id"],
            "message": f"已隔离: {result['quarantine_id']}"
        })

    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        current_app.logger.error(f"[SCANNER] 隔离失败: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@scanner_bp.route('/scanner/history')
@require_auth
def scanner_history():
    """扫描历史列表（JSON）"""
    scans = load_scans_from_disk()
    summaries = []
    for s in scans[:20]:
        summaries.append({
            "scan_id": s.get("scan_id", ""),
            "target_dir": s.get("target_dir", ""),
            "site_id": s.get("site_id", ""),
            "site_name": s.get("site_name", ""),
            "start_time": s.get("start_time", 0),
            "end_time": s.get("end_time", 0),
            "status": s.get("status", "unknown"),
            "total_files": s.get("total_files", 0),
            "scanned_files": s.get("scanned_files", 0),
            "new_findings": s.get("new_findings", 0),
            "known_findings": s.get("known_findings", 0),
            "clean": s.get("clean", 0),
            "duration": s.get("duration", 0),
        })
    return jsonify({"scans": summaries})


@scanner_bp.route('/scanner/results')
@require_auth
def scanner_results_json():
    """从磁盘加载完整扫描结果（JSON）"""
    scan_id = request.args.get('scan_id', '')
    if not scan_id:
        return jsonify({"error": "missing scan_id"}), 400

    disk_file = Path("data") / "scans" / f"{scan_id}.json"
    if disk_file.exists():
        try:
            import json
            data = json.loads(disk_file.read_text(encoding='utf-8'))
            return jsonify(data)
        except Exception:
            return jsonify({"error": "failed to load scan data"}), 500
    return jsonify({"error": "scan not found"}), 404


@scanner_bp.route('/scanner/report')
@require_auth
def scanner_report():
    """生成可打印扫描报告"""
    scan_id = request.args.get('scan_id', '')
    result = get_runtime().scan_state.get_result(scan_id)

    if not result:
        disk_file = Path("data") / "scans" / f"{scan_id}.json"
        if disk_file.exists():
            try:
                import json
                raw = json.loads(disk_file.read_text(encoding='utf-8'))
                from anteumbra.application.scanner_service import ManualScanResult
                result = ManualScanResult(
                    scan_id=raw.get("scan_id", scan_id),
                    target_dir=raw.get("target_dir", ""),
                    start_time=raw.get("start_time", 0),
                    end_time=raw.get("end_time", 0),
                    status=raw.get("status", "completed"),
                    total_files=raw.get("total_files", 0),
                    scanned_files=raw.get("scanned_files", 0),
                    new_findings=raw.get("new_findings", 0),
                    known_findings=raw.get("known_findings", 0),
                    clean=raw.get("clean", 0),
                    errors=raw.get("errors", 0),
                    findings=raw.get("findings", []),
                    site_id=raw.get("site_id", ""),
                    site_name=raw.get("site_name", ""),
                )
            except Exception:
                return render_template('admin/error.html',
                    error="扫描结果不存在或已过期"), 404
        else:
            return render_template('admin/error.html',
                error="扫描结果不存在或已过期"), 404

    return render_template('admin/scanner_report.html',
        result=result,
        generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    )
