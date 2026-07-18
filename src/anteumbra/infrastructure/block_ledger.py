# -*- coding: utf-8 -*-
"""
v1.9.0: IP 封禁台账 (Block Audit Ledger)

持久化记录所有封禁操作的 IP，支持备注编辑、分类统计、导出。
存储: data/block_ledger.json
"""
import json
import logging
import threading
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from anteumbra.domain.runtime import EventPublisherPort

logger = logging.getLogger("monitor.block_ledger")

_LEDGER_PATH = None
_LEDGER_LOCK = threading.RLock()
_LEDGER_CACHE: List[Dict] = []


def _init_path():
    """初始化台账路径（线程安全）"""
    global _LEDGER_PATH
    if _LEDGER_PATH is None:
        with _LEDGER_LOCK:
            if _LEDGER_PATH is None:
                _LEDGER_PATH = Path("data") / "block_ledger.json"


def _load() -> List[Dict]:
    """Load ledger records from authoritative JSON or SQLite recovery."""
    global _LEDGER_CACHE
    _init_path()
    if _LEDGER_CACHE:
        return _LEDGER_CACHE

    try:
        if _LEDGER_PATH.exists():
            data = json.loads(_LEDGER_PATH.read_text(encoding="utf-8"))
            if isinstance(data, list):
                _LEDGER_CACHE = data
                return data
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("[BLOCK_LEDGER] JSON load failed: %s", exc)

    try:
        from anteumbra.infrastructure.persistence import get_shadow_repository

        repo = get_shadow_repository("block_ledger")
        if repo is not None:
            records = repo.list_all(limit=999999)
            if records and any(record.get("ip") for record in records):
                _LEDGER_CACHE = records
                return records
    except Exception:
        logger.debug("SQLite shadow load failed", exc_info=True)
    return []


def _save(data: List[Dict]):
    """保存台账到磁盘 — v2.0: JSON primary + Repository shadow"""
    global _LEDGER_CACHE
    _init_path()
    _LEDGER_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = _LEDGER_PATH.with_suffix('.tmp')
    try:
        tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding='utf-8')
        tmp.replace(_LEDGER_PATH)
        _LEDGER_CACHE = data
    except Exception as e:
        logger.error(f"[BLOCK_LEDGER] 保存失败: {e}")

    # v2.0: Shadow-write to Repository for storage.backend = sqlite / both
    _repo_shadow_save(data)


def _repo_shadow_save(data: List[Dict]):
    """v2.0: Shadow-write block_ledger records to Repository interface.

    Best-effort — failures are silently ignored.
    """
    try:
        from anteumbra.infrastructure.persistence import get_shadow_repository

        repo = get_shadow_repository("block_ledger")
        if repo is None:
            return
        for item in data:
            key = item.get("ip", "")
            if key:
                try:
                    repo.save(key, dict(item))
                except Exception:
                    logger.debug("Repository shadow save block_ledger item failed", exc_info=True)
    except Exception:
        logger.debug("Repository shadow save block_ledger unavailable", exc_info=True)


def add_entry(
    ip: str,
    source: str = "manual",
    reason: str = "",
    profile_id: str = "",
    blocked_by: str = "admin",
    broadcast_results: Optional[List[Dict]] = None,
    event_publisher: EventPublisherPort | None = None,
) -> Dict:
    """添加封禁记录。返回新条目。"""
    with _LEDGER_LOCK:
        entries = _load()
        # 去重：如果已有同 IP 记录，更新而非新增
        for entry in entries:
            if entry.get("ip") == ip:
                entry["blocked_at"] = datetime.now().isoformat()
                entry["source"] = source
                entry["reason"] = reason or entry.get("reason", "")
                entry["profile_id"] = profile_id or entry.get("profile_id", "")
                entry["blocked_by"] = blocked_by
                if broadcast_results:
                    entry["broadcast_devices"] = [r.get("device", "") for r in broadcast_results]
                    entry["broadcast_status"] = "success" if all(r.get("success") for r in broadcast_results) else "partial"
                _save(entries)
                _emit_block_event(entry, event_publisher)
                return entry

        # 新条目
        devices = [r.get("device", "") for r in broadcast_results] if broadcast_results else []
        all_ok = all(r.get("success") for r in broadcast_results) if broadcast_results else True
        entry = {
            "ip": ip,
            "blocked_at": datetime.now().isoformat(),
            "source": source,
            "reason": reason,
            "notes": "",
            "blocked_by": blocked_by,
            "profile_id": profile_id,
            "broadcast_devices": devices,
            "broadcast_status": "success" if all_ok else ("partial" if broadcast_results else "pending"),
        }
        entries.append(entry)
        _save(entries)
        logger.info(f"[BLOCK_LEDGER] {ip} — {source} — {reason[:60]}")
        _emit_block_event(entry, event_publisher)
        return entry


def _emit_block_event(
    entry: Dict,
    event_publisher: EventPublisherPort | None,
) -> None:
    """Emit block_executed through the caller-owned event publisher."""
    if event_publisher is None:
        return
    try:
        event_publisher.publish("block_executed", "block_ledger", {
            "ip": entry.get("ip", ""),
            "source": entry.get("source", "manual"),
            "reason": entry.get("reason", ""),
            "profile_id": entry.get("profile_id", ""),
            "broadcast_status": entry.get("broadcast_status", "pending"),
        })
    except Exception:
        logger.debug("Block event publish failed", exc_info=True)


def update_notes(ip: str, notes: str) -> bool:
    """更新指定 IP 的备注"""
    with _LEDGER_LOCK:
        entries = _load()
        for entry in entries:
            if entry.get("ip") == ip:
                entry["notes"] = notes
                _save(entries)
                return True
    return False


def get_entries(
    limit: int = 50,
    offset: int = 0,
    source_filter: str = "",
    search: str = "",
) -> tuple:
    """获取台账条目列表，返回 (entries, total)"""
    with _LEDGER_LOCK:
        entries = _load()
    # 筛选
    if source_filter and source_filter != "all":
        entries = [e for e in entries if e.get("source") == source_filter]
    if search:
        q = search.lower()
        entries = [e for e in entries if q in e.get("ip", "").lower()
                   or q in e.get("reason", "").lower()
                   or q in e.get("notes", "").lower()]
    # 按时间倒序
    entries.sort(key=lambda e: e.get("blocked_at", ""), reverse=True)
    total = len(entries)
    return entries[offset:offset + limit], total


def get_by_ip(ip: str) -> Optional[Dict]:
    """查询单个 IP 的封禁记录"""
    with _LEDGER_LOCK:
        entries = _load()
    for entry in entries:
        if entry.get("ip") == ip:
            return entry
    return None


def get_stats() -> Dict:
    """获取台账统计"""
    with _LEDGER_LOCK:
        entries = _load()
    today = datetime.now().strftime("%Y-%m-%d")
    auto_count = sum(1 for e in entries if e.get("source") == "auto")
    manual_count = sum(1 for e in entries if e.get("source") == "manual")
    today_count = sum(1 for e in entries if e.get("blocked_at", "").startswith(today))
    return {
        "total": len(entries),
        "auto": auto_count,
        "manual": manual_count,
        "today": today_count,
    }


def export_ledger(fmt: str = "json") -> str:
    """导出台账数据"""
    with _LEDGER_LOCK:
        entries = _load()
    if fmt == "csv":
        import io
        output = io.StringIO()
        output.write("ip,blocked_at,source,reason,notes,blocked_by,profile_id,broadcast_status\n")
        for e in entries:
            output.write(f'{e.get("ip","")},{e.get("blocked_at","")},{e.get("source","")},'
                        f'"{e.get("reason","")}","{e.get("notes","")}",{e.get("blocked_by","")},'
                        f'{e.get("profile_id","")},{e.get("broadcast_status","")}\n')
        return output.getvalue()
    return json.dumps(entries, indent=2, ensure_ascii=False)


def remove_entry(ip: str) -> bool:
    """删除封禁记录（解封时调用）"""
    with _LEDGER_LOCK:
        entries = _load()
        before = len(entries)
        entries = [e for e in entries if e.get("ip") != ip]
        if len(entries) < before:
            _save(entries)
            return True
    return False
