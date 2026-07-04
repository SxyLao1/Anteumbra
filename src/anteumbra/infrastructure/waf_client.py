# -*- coding: utf-8 -*-
"""
v1.8.1: WAF 事件源客户端 — Mock WAF 实现 + 扩展接口
"""
import json, logging, time, threading, os
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Optional, Dict

import requests

from anteumbra.domain import WAFEvent, WAFEventSource
from anteumbra.infrastructure.config.registry import ConfigRegistry
from anteumbra.infrastructure.utils.path_utils import normalize_path
from anteumbra.infrastructure.utils.logger_factory import log_with_symbol

logger = logging.getLogger("monitor.waf_client")


# ═══════════════════════════════════════════════════════════════
# Mock WAF Client
# ═══════════════════════════════════════════════════════════════

class MockWAFSource(WAFEventSource):
    """连接本地 Mock WAF Server"""

    def __init__(self, base_url: str = "http://127.0.0.1:9999"):
        self.base_url = base_url.rstrip("/")
        self._last_poll: Optional[datetime] = None

    def get_name(self) -> str:
        return "MockWAF"

    def is_available(self) -> bool:
        try:
            r = requests.get(f"{self.base_url}/status", timeout=3)
            return r.status_code == 200
        except Exception:
            return False

    def pull_events(self, start_time: datetime, end_time: datetime) -> List[WAFEvent]:
        url = f"{self.base_url}/api/open/events"
        params = {
            "start": start_time.strftime("%Y-%m-%dT%H:%M:%S"),
            "end": end_time.strftime("%Y-%m-%dT%H:%M:%S"),
        }
        try:
            r = requests.get(url, params=params, timeout=10)
            r.raise_for_status()
            raw = r.json()
            return [WAFEvent(
                event_id=e.get("event_id", ""),
                src_ip=e.get("src_ip", ""),
                timestamp=e.get("timestamp", ""),
                http_method=e.get("http_method", ""),
                url=e.get("url", ""),
                user_agent=e.get("user_agent", ""),
                waf_rule_id=e.get("waf_rule_id", ""),
                waf_score=float(e.get("waf_score", 0)),
                attack_type=e.get("attack_type", "unknown"),
            ) for e in raw]
        except Exception as e:
            logger.warning(f"[WAF_CLIENT] Poll failed: {e}")
            return []


# ═══════════════════════════════════════════════════════════════
# WAF Poller — 后台轮询，事件写入本地 JSONL 缓存
# ═══════════════════════════════════════════════════════════════

class WAFPoller:
    """后台线程定期轮询 WAF 事件源，写入本地缓存"""

    def __init__(self, source: WAFEventSource, poll_interval: int = 10):
        self.source = source
        self.poll_interval = poll_interval
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._cache_path: Optional[Path] = None
        self._last_poll_time: Optional[datetime] = None
        self._dest_ips: List[str] = []  # v1.9.0: 目的IP白名单过滤

    def start(self):
        if self._running:
            return
        self._running = True
        # v1.9.0: 加载目的IP过滤配置（空=自动探测本机IP）
        try:
            cfg = ConfigRegistry.get_raw_config()
            self._dest_ips = cfg.get('waf_source', {}).get('dest_ips', [])
            if not self._dest_ips:
                # Auto-detect local non-loopback IPs
                import socket
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    s.connect(('8.8.8.8', 80))
                    local_ip = s.getsockname()[0]
                    s.close()
                    self._dest_ips = [local_ip, '127.0.0.1']
                except Exception:
                    self._dest_ips = ['127.0.0.1']
            logger.info(f"[WAF_POLLER] Destination IP filter: {self._dest_ips}")
        except Exception:
            logger.debug("Failed to load WAF poller config for dest_ips", exc_info=True)
        # 确定缓存文件路径
        self._cache_path = normalize_path("data/waf_events.jsonl")
        self._cache_path.parent.mkdir(parents=True, exist_ok=True)
        # 从已有缓存恢复上次轮询时间
        self._load_checkpoint()
        # 启动后台线程
        self._thread = threading.Thread(target=self._poll_loop, daemon=True, name="WAFPoller")
        self._thread.start()
        log_with_symbol("notifier_init", "info", f"[WAF_POLLER] Started: {self.source.get_name()}, interval={self.poll_interval}s")

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)

    def is_running(self) -> bool:
        return self._running

    def _load_checkpoint(self):
        """从缓存文件最后一行恢复轮询位点"""
        if not self._cache_path or not self._cache_path.exists():
            return
        try:
            with open(self._cache_path, 'r', encoding='utf-8') as f:
                # 读最后一行
                last_line = None
                for line in f:
                    if line.strip():
                        last_line = line
                if last_line:
                    evt = json.loads(last_line)
                    self._last_poll_time = datetime.fromisoformat(evt["timestamp"])
                    logger.info(f"[WAF_POLLER] Checkpoint restored: {self._last_poll_time}")
        except Exception:
            logger.debug("Failed to load WAF checkpoint from cache file", exc_info=True)

    def _poll_loop(self):
        while self._running:
            try:
                # v2.0: Hot-reload — re-read URL from config each poll
                from anteumbra.infrastructure.config.registry import ConfigRegistry
                cfg = ConfigRegistry.get_raw_config()
                new_url = cfg.get("waf_source", {}).get("url", self.source.base_url)
                if new_url != self.source.base_url:
                    logger.info(f"[WAF_POLLER] URL hot-reloaded: {self.source.base_url} -> {new_url}")
                    self.source.base_url = new_url

                now = datetime.now()
                start = self._last_poll_time or (now - timedelta(seconds=self.poll_interval))
                end = now

                events = self.source.pull_events(start, end)
                if events:
                    self._append_cache(events)
                    self._last_poll_time = end
                    logger.debug(f"[WAF_POLLER] Received {len(events)} events")

            except Exception as e:
                logger.warning(f"[WAF_POLLER] Poll failed: {e}")

            time.sleep(self.poll_interval)

    def _append_cache(self, events: List[WAFEvent]):
        if not self._cache_path:
            return
        with open(self._cache_path, 'a', encoding='utf-8') as f:
            for evt in events:
                f.write(json.dumps({
                    "event_id": evt.event_id,
                    "src_ip": evt.src_ip,
                    "timestamp": evt.timestamp,
                    "http_method": evt.http_method,
                    "url": evt.url,
                    "user_agent": evt.user_agent,
                    "waf_rule_id": evt.waf_rule_id,
                    "waf_score": evt.waf_score,
                    "attack_type": evt.attack_type,
                }, ensure_ascii=False) + "\n")

    def get_cached_events(self, limit: int = 100) -> List[Dict]:
        """读取缓存的最近事件（供测试/调试用）"""
        if not self._cache_path or not self._cache_path.exists():
            return []
        events = []
        with open(self._cache_path, 'r', encoding='utf-8') as f:
            for line in f:
                if line.strip():
                    events.append(json.loads(line))
        return events[-limit:]


# ═══════════════════════════════════════════════════════════════
# Factory
# ═══════════════════════════════════════════════════════════════

_poller: Optional[WAFPoller] = None


def get_waf_poller() -> Optional[WAFPoller]:
    """获取或创建 WAF poller 单例"""
    global _poller
    if _poller is not None:
        return _poller

    try:
        cfg = ConfigRegistry.get_raw_config()
        waf_cfg = cfg.get("waf_source", {})
        if not waf_cfg.get("enabled", False):
            logger.info("[WAF_POLLER] Disabled in config")
            return None

        source_type = waf_cfg.get("type", "mock")
        if source_type == "mock":
            url = waf_cfg.get("url", "http://127.0.0.1:9999")
            source = MockWAFSource(base_url=url)
        else:
            logger.warning(f"[WAF_POLLER] Unknown source type: {source_type}")
            return None

        interval = ConfigRegistry.safe_int(waf_cfg.get("poll_interval", 10))
        _poller = WAFPoller(source, poll_interval=interval)
        return _poller
    except Exception as e:
        logger.warning(f"[WAF_POLLER] Init failed: {e}")
        return None
