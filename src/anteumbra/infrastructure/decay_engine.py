# -*- coding: utf-8 -*-
"""
v1.8.3: 简单衰减引擎 — 后台线程遍历画像表，应用衰减公式

设计来自 PROJECT_MASTER Section 9:
    - 衰减公式：24h/0.5, 72h/0.1（线性）
    - 后台线程（daemon=True），每 N 秒遍历画像表
    - 高危(>80) 10min / 中危(20-80) 1h / 低危(<20) 6h
    - 7天无活动内存移除，30天WAL归档
"""
import logging
import threading
import time
from datetime import datetime
from typing import Dict, Optional

logger = logging.getLogger("monitor.decay")


class SimpleDecayEngine:
    """
    简单衰减引擎：
    - 后台线程每 check_interval 秒遍历全表
    - 计算每个画像距离 last_seen 的时间
    - 应用 24h/0.5, 72h/0.1 衰减公式
    - 风险分数 < 0.1 的画像标记为 expired
    - 7 天无活动：从内存表移除（WAL 保留历史）
    """

    def __init__(self, check_interval: int = 60):
        self.check_interval = check_interval
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._profile_table: Optional[Dict] = None  # 外部注入的画像表引用

    def attach(self, profile_table: Dict):
        """注入画像表引用（ThreatGraph._profiles）"""
        self._profile_table = profile_table

    def start(self):
        """启动后台衰减线程"""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._decay_loop, daemon=True, name="DecayEngine")
        self._thread.start()
        logger.info("[DECAY] Engine started (interval=%ds)", self.check_interval)

    def stop(self):
        self._running = False

    def _decay_loop(self):
        while self._running:
            try:
                self._run_decay_pass()
            except Exception as e:
                logger.warning(f"[DECAY] Pass failed: {e}")
            time.sleep(self.check_interval)

    def _run_decay_pass(self):
        if self._profile_table is None:
            return
        now = datetime.now()
        expired = []

        for pid, profile in list(self._profile_table.items()):
            if not profile.last_seen:
                continue
            delta_hours = (now - profile.last_seen).total_seconds() / 3600

            # Determine decay check interval based on risk score
            score = profile.risk_score
            if score > 0.8:
                decay_check = 0.17  # ~10 min
            elif score > 0.2:
                decay_check = 1.0   # ~1 hour
            else:
                decay_check = 6.0   # ~6 hours

            # Only decay at configured intervals
            if profile.last_decayed:
                since_last = (now - profile.last_decayed).total_seconds() / 3600
                if since_last < decay_check:
                    continue

            # Apply decay formula
            if delta_hours >= 168:  # 7 days
                expired.append(pid)
                profile.status = "expired"
            elif delta_hours >= 72:
                profile.risk_score = profile.raw_score * 0.1
                profile.decay_factor = 0.1
                if profile.status == "active":
                    profile.status = "dormant"
            elif delta_hours >= 24:
                profile.risk_score = profile.raw_score * 0.5 * (1 - (delta_hours - 24) / 48)
                profile.decay_factor = 0.5
            profile.last_decayed = now

        # Remove expired profiles from memory (WAL keeps history)
        for pid in expired:
            if pid in self._profile_table:
                del self._profile_table[pid]
                logger.info(f"[DECAY] Expired profile: {pid[:8]}")
