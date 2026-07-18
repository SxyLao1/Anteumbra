# -*- coding: utf-8 -*-
"""
v1.9.0: Blueprint 拆分 — 共享工具函数

从 admin_bp.py 提取，供所有拆分后的 Blueprint 使用。
"""
import base64
import json as _stdlib_json
import logging
import secrets
import threading
import time
from pathlib import Path
from typing import Optional



logger = logging.getLogger(__name__)

# ── 扫描结果持久化（scanner 共享） ──────────────────────

def save_scan_to_disk(result) -> None:
    """持久化扫描结果到 data/scans/"""
    try:
        data_dir = Path("data") / "scans"
        data_dir.mkdir(parents=True, exist_ok=True)
        record = {
            "scan_id": result.scan_id,
            "target_dir": result.target_dir,
            "start_time": result.start_time,
            "end_time": result.end_time,
            "status": result.status,
            "site_id": getattr(result, "site_id", ""),
            "site_name": getattr(result, "site_name", ""),
            "total_files": result.total_files,
            "scanned_files": result.scanned_files,
            "new_findings": result.new_findings,
            "known_findings": result.known_findings,
            "clean": result.clean,
            "errors": result.errors,
            "duration": round(result.end_time - result.start_time, 1) if result.end_time else 0,
            "findings": result.findings[:200],
        }
        filepath = data_dir / f"{result.scan_id}.json"
        filepath.write_text(_stdlib_json.dumps(record, indent=2, ensure_ascii=False), encoding='utf-8')
    except Exception:
        logger.debug("Failed to save scan result to disk", exc_info=True)


def load_scans_from_disk() -> list:
    """从磁盘加载所有扫描历史"""
    try:
        data_dir = Path("data") / "scans"
        if not data_dir.exists():
            return []
        scans = []
        for f in sorted(data_dir.glob("*.json"), reverse=True):
            try:
                scans.append(_stdlib_json.loads(f.read_text(encoding='utf-8')))
            except Exception:
                logger.debug("Failed to parse scan file %s", f.name, exc_info=True)
        return scans
    except Exception:
        logger.debug("Failed to load scan history", exc_info=True)
        return []


# ── 文件查看器安全验证 ──────────────────────────────────

def verify_file_in_registry(file_path: str) -> bool:
    """验证文件路径是否在 Registry 中（白名单）。
    v2.0 fix: Case-insensitive path comparison for Windows compatibility.
    Registry stores paths lowercased (via path_to_key), but frontend sends
    original-case paths from scanner findings.
    """
    try:
        from anteumbra.application.registry_service import get_all
        from anteumbra.application.path_service import path_to_key
        raw_key = path_to_key(file_path)
        records = get_all()
        for r in records:
            rp = path_to_key(r.get("file_path", ""))
            if rp == raw_key:
                return True
        return False
    except Exception:
        logger.warning(
            "Registry lookup failed while authorizing file access",
            exc_info=True,
        )
        return False


def verify_file_in_quarantine(qid: str) -> Optional[Path]:
    """验证文件是否在 Quarantine 中，返回实际路径"""
    try:
        from anteumbra.application.quarantine_service import get_quarantine_detail
        record = get_quarantine_detail(qid)
        if not record:
            return None
        fp = record.get("quarantine_path", "")
        p = Path(fp) if fp else None
        if p and p.exists() and p.is_file():
            return p
        return None
    except Exception:
        logger.warning(
            "Quarantine lookup failed for id %s",
            qid,
            exc_info=True,
        )
        return None


# v1.0.5: Use markupsafe.escape() instead of custom implementation (Kimi P2-3)
from markupsafe import escape as html_escape


# ── SSE Token 生成 ──────────────────────────────────────

def generate_secure_sse_token(username: str) -> str:
    random_part = secrets.token_urlsafe(16)
    token_str = f"{username}:{random_part}"
    return base64.b64encode(token_str.encode()).decode()




# ── 扫描结果内存缓存 ────────────────────────────────────

_scan_results_cache: dict = {}
_scan_results_lock = threading.Lock()


def _cache_put(key: str, value) -> None:
    """Thread-safe cache write."""
    with _scan_results_lock:
        _scan_results_cache[key] = value


def _cache_get(key: str):
    """Thread-safe cache read."""
    with _scan_results_lock:
        return _scan_results_cache.get(key)


def _cache_cleanup_stale(max_age: float = 3600) -> None:
    """Thread-safe removal of entries older than max_age seconds."""
    with _scan_results_lock:
        stale = [k for k, v in _scan_results_cache.items()
                 if time.time() - v.end_time > max_age]
        for k in stale:
            del _scan_results_cache[k]
