# -*- coding: utf-8 -*-
"""
v1.9.0: Blueprint 拆分 — 共享工具函数

从 admin_bp.py 提取，供所有拆分后的 Blueprint 使用。
"""
import base64
import logging
import secrets
from pathlib import Path
from typing import Optional

from anteumbra.interfaces.web.runtime import get_runtime

logger = logging.getLogger(__name__)

# ── 文件查看器安全验证 ──────────────────────────────────

def verify_file_in_registry(file_path: str) -> bool:
    """验证文件路径是否在 Registry 中（白名单）。
    v2.0 fix: Case-insensitive path comparison for Windows compatibility.
    Registry stores paths lowercased (via path_to_key), but frontend sends
    original-case paths from scanner findings.
    """
    try:
        from anteumbra.application.path_service import path_to_key
        raw_key = path_to_key(file_path)
        records = get_runtime().registry.get_all()
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
        record = get_runtime().quarantine.get_detail(qid)
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


# ── SSE Token 生成 ──────────────────────────────────────

def generate_secure_sse_token(username: str) -> str:
    random_part = secrets.token_urlsafe(16)
    token_str = f"{username}:{random_part}"
    return base64.b64encode(token_str.encode()).decode()
