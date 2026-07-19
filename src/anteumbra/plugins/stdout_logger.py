# -*- coding: utf-8 -*-
"""
v1.9.3: Stdout Logger Plugin — POC 内置插件

实现 Plugin + Notifier 接口。
将所有告警事件以彩色格式输出到终端。
"""
import json
import logging
import sys
from datetime import datetime
from typing import List, Optional, Dict, Any

from anteumbra.domain import Plugin, DomainEvent
from anteumbra.domain import Notifier, AlertMessage, AlertLevel

# 终端颜色
_COLORS = {
    AlertLevel.CRITICAL: "\033[1;31m",  # 红色加粗
    AlertLevel.HIGH:     "\033[0;31m",  # 红色
    AlertLevel.MEDIUM:   "\033[0;33m",  # 黄色
    AlertLevel.LOW:      "\033[0;36m",  # 青色
    AlertLevel.INFO:     "\033[0;37m",  # 白色
    "reset":             "\033[0m",
}


class StdoutLoggerPlugin(Plugin, Notifier):
    """终端输出插件 — 将告警彩色输出到 stdout"""

    def __init__(self, *, log: logging.Logger | None = None) -> None:
        self._logger = log or logging.getLogger(__name__)

    @property
    def name(self) -> str:
        return "stdout_logger"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def supported_events(self) -> List[str]:
        return ["alert_requested", "file_scanned", "block_executed", "file_quarantined", "threat_graph_updated", "wal_archived", "wal_replayed"]

    def activate(self, config: Dict[str, Any]) -> None:
        self._color = config.get("color", True)
        self._verbose = config.get("verbose", False)
        self._logger.info(
            "StdoutLogger: 已激活 (color=%s, verbose=%s)",
            self._color,
            self._verbose,
        )

    def deactivate(self) -> None:
        self._logger.info("StdoutLogger: 已停用")

    def on_event(self, event: DomainEvent) -> Optional[List[DomainEvent]]:
        ts = datetime.fromtimestamp(event.timestamp).strftime("%H:%M:%S")
        payload = event.payload or {}
        if event.event_type == "alert_requested":
            level = payload.get("level", "INFO")
            alert_type = payload.get("alert_type", "unknown")
            file_path = payload.get("file_path", "")
            batch = payload.get("batch_count")
            extra = f" (x{batch})" if batch else f" -> {file_path}" if file_path else ""
            print(f"[STDOUT][{ts}] {level:8s} {alert_type}{extra}")
        elif event.event_type == "file_scanned":
            fp = payload.get("file_path", "?")
            tag = "HIT" if payload.get("is_suspicious") else "SAFE"
            print(f"[STDOUT][{ts}] SCAN    [{tag}] {fp}")
        elif event.event_type == "block_executed":
            ip = payload.get("ip", "?")
            print(f"[STDOUT][{ts}] BLOCK   {ip}")
        elif event.event_type == "file_quarantined":
            fp = payload.get("file_path", "?")
            print(f"[STDOUT][{ts}] QUAR    {fp}")
        elif event.event_type == "threat_graph_updated":
            count = payload.get("active_profile_count", 0)
            top = payload.get("top_risk_score", 0)
            print(f"[STDOUT][{ts}] GRAPH   {count} profiles, top risk={top:.2f}")
        elif event.event_type == "wal_archived":
            ap = payload.get("archive_path", "?")
            print(f"[STDOUT][{ts}] WAL-ARC {ap}")
        elif event.event_type == "wal_replayed":
            rc = payload.get("recovered_count", 0)
            print(f"[STDOUT][{ts}] WAL-REP recovered {rc} records")
        elif self._verbose:
            payload_str = json.dumps(payload, ensure_ascii=False, default=str)[:200]
            print(f"[STDOUT][{ts}] {event.event_type} <- {event.source}: {payload_str}")
        return None

    def send(self, message: AlertMessage) -> bool:
        color = _COLORS.get(message.level, "")
        reset = _COLORS["reset"] if self._color else ""
        ts = datetime.now().strftime("%H:%M:%S")
        line = f"{color}[ALERT][{ts}] {message.level.value.upper():8s} {message.title}{reset}"
        # 确保输出到 stdout（非 stderr），避免与日志混淆
        sys.stdout.write(line + "\n")
        sys.stdout.flush()
        return True
