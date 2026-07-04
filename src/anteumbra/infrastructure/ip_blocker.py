# -*- coding: utf-8 -*-
"""
v1.8.2: IP 封禁模块 — 多设备广播架构

设计参考：afoa0521 生产环境自动封禁工具
模式：单次 Block 请求 → 广播到所有已配置的安全设备

设备类型：
    - stdout: 仅日志输出（开发/测试）
    - http: 通用 HTTP POST 到防火墙/WAF API
    - mock: 内存黑名单（Mock 测试用）

配置 (config.toml):
    [ip_blocker]
    enabled = true
    auto_block_enabled = false   # 是否自动封禁（高危画像自动触发）
    auto_block_min_score = 0.8   # 自动封禁最低风险分

    [[ip_blocker.devices]]
    name = "Mock Firewall"
    type = "mock"

    [[ip_blocker.devices]]
    name = "Production WAF"
    type = "http"
    url = "https://waf.company.com/api/block"
    api_key = "${ANTEUMBRA_WAF_API_KEY:-}"
"""

import json, logging, threading, time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional

from anteumbra.infrastructure.config.registry import ConfigRegistry
from anteumbra.infrastructure.utils.path_utils import normalize_path

logger = logging.getLogger("monitor.ip_blocker")


# ═══════════════════════════════════════════════════════════════
# Data Classes
# ═══════════════════════════════════════════════════════════════

@dataclass
class BlockDecision:
    """封禁决策"""
    ip: str
    reason: str
    profile_id: str = ""
    risk_score: float = 0.0
    duration_seconds: int = 86400  # 默认24小时
    permanent: bool = False
    created_at: datetime = field(default_factory=datetime.now)


@dataclass
class BlockResult:
    """封禁结果（每个设备返回一个）"""
    device_name: str
    success: bool
    message: str
    ip: str
    timestamp: datetime = field(default_factory=datetime.now)


# ═══════════════════════════════════════════════════════════════
# Device Interface
# ═══════════════════════════════════════════════════════════════

class BlockDevice(ABC):
    """安全设备抽象接口——WAF / FW / NGFW 都实现这个"""

    @abstractmethod
    def get_name(self) -> str:
        pass

    @abstractmethod
    def block(self, decision: BlockDecision) -> BlockResult:
        """执行封禁"""
        pass

    @abstractmethod
    def unblock(self, ip: str) -> BlockResult:
        """解除封禁"""
        pass

    @abstractmethod
    def is_available(self) -> bool:
        """设备是否在线"""
        pass


# ═══════════════════════════════════════════════════════════════
# Device Implementations
# ═══════════════════════════════════════════════════════════════

class StdoutDevice(BlockDevice):
    """仅日志输出——开发/演示用"""
    def __init__(self, name="stdout"):
        self.name = name
    def get_name(self): return self.name
    def is_available(self): return True
    def block(self, decision):
        logger.info(f"[BLOCK][{self.name}] Would block {decision.ip} | reason={decision.reason} | profile={decision.profile_id[:8]}")
        logger.info(f"[IP_BLOCKER] {self.name}: BLOCK {decision.ip} — {decision.reason}")
        return BlockResult(device_name=self.name, success=True, message="logged", ip=decision.ip)
    def unblock(self, ip):
        logger.info(f"[BLOCK][{self.name}] Would unblock {ip}")
        return BlockResult(device_name=self.name, success=True, message="logged", ip=ip)


class MockDevice(BlockDevice):
    """内存黑名单——Mock 测试用"""
    def __init__(self, name="mock"):
        self.name = name
        self._blocklist: set = set()
    def get_name(self): return self.name
    def is_available(self): return True
    def block(self, decision):
        self._blocklist.add(decision.ip)
        logger.info(f"[BLOCK][{self.name}] Blocked {decision.ip}")
        return BlockResult(device_name=self.name, success=True, message="blocked (mock)", ip=decision.ip)
    def unblock(self, ip):
        self._blocklist.discard(ip)
        return BlockResult(device_name=self.name, success=True, message="unblocked (mock)", ip=ip)
    def is_blocked(self, ip): return ip in self._blocklist
    def list_all(self): return sorted(self._blocklist)


class HTTPDevice(BlockDevice):
    """通用 HTTP POST 设备——对接 WAF/FW REST API"""
    def __init__(self, name, url, api_key=""):
        self.name = name
        self.url = url
        self.api_key = api_key

    def get_name(self): return self.name

    def is_available(self):
        try:
            import requests
            r = requests.get(self.url.rsplit('/', 1)[0] + '/ping', timeout=3)
            return r.status_code == 200
        except Exception:
            return False

    def block(self, decision):
        import requests
        try:
            payload = {
                "ip": decision.ip,
                "comment": f"Anteumbra: {decision.reason} (profile: {decision.profile_id[:8]})",
                "permanent": decision.permanent,
                "duration": decision.duration_seconds,
                "risk_score": decision.risk_score,
            }
            headers = {"Content-Type": "application/json"}
            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"
            r = requests.post(self.url, json=payload, headers=headers, timeout=10)
            ok = r.status_code < 400
            return BlockResult(device_name=self.name, success=ok,
                message=r.text[:200] if not ok else "blocked", ip=decision.ip)
        except Exception as e:
            return BlockResult(device_name=self.name, success=False, message=str(e), ip=decision.ip)

    def unblock(self, ip):
        import requests
        try:
            url = self.url.replace('/block', '/unblock')
            r = requests.post(url, json={"ip": ip}, timeout=10)
            return BlockResult(device_name=self.name, success=r.status_code < 400,
                message="unblocked" if r.status_code < 400 else r.text[:200], ip=ip)
        except Exception as e:
            return BlockResult(device_name=self.name, success=False, message=str(e), ip=ip)


# ═══════════════════════════════════════════════════════════════
# IP Blocker Manager
# ═══════════════════════════════════════════════════════════════

@dataclass
class RetryItem:
    """重试队列条目"""
    decision: BlockDecision
    attempts: int = 0
    max_attempts: int = 5
    next_retry_at: float = 0.0  # Unix timestamp
    last_error: str = ""


class IPBlocker:
    """IP 封禁管理器——广播到所有设备 + 失败重试队列"""

    def __init__(self):
        self.devices: List[BlockDevice] = []
        self._auto_block_enabled = False
        self._auto_block_min_score = 0.8
        self._history: List[BlockResult] = []
        self._retry_queue: List[RetryItem] = []
        self._retry_thread: Optional[threading.Thread] = None
        self._retry_running = False
        self._retry_interval = 30  # base retry interval (seconds)
        self._persist_path: Optional[str] = None
        self._lock = threading.Lock()

    def add_device(self, device: BlockDevice):
        self.devices.append(device)

    def configure(self, config: dict):
        """从 config.toml [ip_blocker] 加载配置"""
        self._auto_block_enabled = config.get("auto_block_enabled", False)
        self._auto_block_min_score = config.get("auto_block_min_score", 0.8)

        # Load devices from config
        devices_cfg = config.get("devices", [])
        for dcfg in devices_cfg:
            dtype = dcfg.get("type", "stdout")
            name = dcfg.get("name", dtype)
            if dtype == "mock":
                self.add_device(MockDevice(name))
            elif dtype == "http":
                url = dcfg.get("url", "")
                key = dcfg.get("api_key", "")
                if url:
                    self.add_device(HTTPDevice(name, url, key))
            elif dtype == "stdout":
                self.add_device(StdoutDevice(name))

        # Default: always add stdout device for logging
        if not self.devices:
            self.add_device(StdoutDevice())

    def block(self, ips: List[str], reason: str = "", profile_id: str = "",
              risk_score: float = 0.0, permanent: bool = False) -> List[BlockResult]:
        """封禁 IP 列表，广播到所有设备。失败自动入重试队列。"""
        results = []
        with self._lock:
            for ip in ips:
                decision = BlockDecision(
                    ip=ip, reason=reason, profile_id=profile_id,
                    risk_score=risk_score, permanent=permanent)
                all_ok = True
                for device in self.devices:
                    try:
                        r = device.block(decision)
                        results.append(r)
                        self._history.append(r)
                        if not r.success:
                            all_ok = False
                    except Exception as e:
                        logger.warning(f"[BLOCK] {device.get_name()} failed: {e}")
                        results.append(BlockResult(
                            device_name=device.get_name(), success=False,
                            message=str(e), ip=ip))
                        all_ok = False
                # Any device failure → enqueue for retry
                if not all_ok:
                    self._enqueue_retry(decision)
        return results

    def _enqueue_retry(self, decision: BlockDecision):
        """入重试队列（指数退避）"""
        now = time.time()
        # Check if already queued for this IP
        existing = [item for item in self._retry_queue if item.decision.ip == decision.ip]
        if existing:
            return
        item = RetryItem(
            decision=decision,
            attempts=1,
            next_retry_at=now + self._retry_interval,
            last_error="Initial block failed")
        self._retry_queue.append(item)
        self._persist_retry_queue()
        logger.info(f"[RETRY] Queued {decision.ip} for retry in {self._retry_interval}s")

    def _retry_loop(self):
        """后台重试线程"""
        while self._retry_running:
            time.sleep(10)
            now = time.time()
            retry_now = []
            with self._lock:
                for item in self._retry_queue[:]:
                    if now >= item.next_retry_at:
                        retry_now.append(item)
                        self._retry_queue.remove(item)

            for item in retry_now:
                success = True
                for device in self.devices:
                    try:
                        r = device.block(item.decision)
                        if not r.success:
                            success = False
                            item.last_error = r.message
                    except Exception as e:
                        success = False
                        item.last_error = str(e)

                if success:
                    logger.info(f"[RETRY] {item.decision.ip}: OK after {item.attempts} retries")
                elif item.attempts < item.max_attempts:
                    # Exponential backoff: 30s, 60s, 120s, 240s, 480s
                    item.attempts += 1
                    item.next_retry_at = now + (self._retry_interval * (2 ** (item.attempts - 1)))
                    with self._lock:
                        self._retry_queue.append(item)
                    logger.warning(f"[RETRY] {item.decision.ip}: attempt {item.attempts}/{item.max_attempts}, next in {item.next_retry_at - now:.0f}s")
                else:
                    logger.error(f"[RETRY] {item.decision.ip}: FAILED after {item.max_attempts} attempts — abandoned")

            self._persist_retry_queue()

    def start_retry_worker(self, persist_path: str = None):
        """启动重试后台线程（线程安全）"""
        if persist_path:
            self._persist_path = persist_path
            self._load_retry_queue()
        with self._lock:
            if self._retry_running:
                return
            self._retry_running = True
        self._retry_thread = threading.Thread(target=self._retry_loop, daemon=True, name="BlockRetry")
        self._retry_thread.start()
        logger.info("[RETRY] Worker started")

    def stop_retry_worker(self):
        with self._lock:
            self._retry_running = False

    def get_retry_queue_status(self) -> Dict:
        """返回重试队列状态（前端展示用）"""
        with self._lock:
            return {
                "pending": len(self._retry_queue),
                "items": [{
                    "ip": item.decision.ip,
                    "reason": item.decision.reason,
                    "attempts": item.attempts,
                    "max_attempts": item.max_attempts,
                    "next_retry_at": datetime.fromtimestamp(item.next_retry_at).strftime("%H:%M:%S"),
                    "last_error": item.last_error,
                } for item in self._retry_queue[:20]],
            }

    def _persist_retry_queue(self):
        if not self._persist_path:
            return
        try:
            data = [{
                "ip": item.decision.ip, "reason": item.decision.reason,
                "profile_id": item.decision.profile_id,
                "attempts": item.attempts, "max_attempts": item.max_attempts,
                "next_retry_at": item.next_retry_at, "last_error": item.last_error,
            } for item in self._retry_queue]
            tmp = self._persist_path + '.tmp'
            with open(tmp, 'w', encoding='utf-8') as f:
                json.dump(data, f)
            import os
            os.replace(tmp, self._persist_path)
        except Exception:
            logger.debug("Failed to persist retry queue to disk", exc_info=True)

    def _load_retry_queue(self):
        if not self._persist_path:
            return
        import os
        if not os.path.exists(self._persist_path):
            return
        try:
            with open(self._persist_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            for d in data:
                decision = BlockDecision(
                    ip=d["ip"], reason=d.get("reason", ""),
                    profile_id=d.get("profile_id", ""))
                item = RetryItem(
                    decision=decision, attempts=d.get("attempts", 0),
                    max_attempts=d.get("max_attempts", 5),
                    next_retry_at=d.get("next_retry_at", 0),
                    last_error=d.get("last_error", ""))
                self._retry_queue.append(item)
            logger.info(f"[RETRY] Loaded {len(self._retry_queue)} pending items from disk")
        except Exception as e:
            logger.warning(f"[RETRY] Load failed: {e}")

    def unblock(self, ips: List[str]) -> List[BlockResult]:
        """解封 IP 列表"""
        results = []
        with self._lock:
            for ip in ips:
                for device in self.devices:
                    try:
                        r = device.unblock(ip)
                        results.append(r)
                    except Exception as e:
                        results.append(BlockResult(
                            device_name=device.get_name(), success=False,
                            message=str(e), ip=ip))
        return results

    def auto_block(self, profile_id: str, ips: List[str], risk_score: float, reason: str = ""):
        """自动封禁：仅当 auto_block_enabled 且分数达标时触发"""
        if not self._auto_block_enabled:
            return []
        if risk_score < self._auto_block_min_score:
            return []
        logger.info(f"[AUTO_BLOCK] Profile {profile_id[:8]}: {len(ips)} IPs, score={risk_score}")
        return self.block(ips, reason=reason, profile_id=profile_id, risk_score=risk_score)

    def get_blocklist(self) -> List[Dict]:
        """返回当前黑名单（仅 mock 设备）"""
        result = []
        for device in self.devices:
            if isinstance(device, MockDevice):
                for ip in device.list_all():
                    result.append({"ip": ip, "source": device.get_name()})
        return result

    def get_history(self, limit: int = 50) -> List[Dict]:
        """返回封禁历史"""
        return [{
            "device": r.device_name, "ip": r.ip, "success": r.success,
            "message": r.message, "time": r.timestamp.isoformat()
        } for r in self._history[-limit:]]


# ═══════════════════════════════════════════════════════════════
# Singleton
# ═══════════════════════════════════════════════════════════════

_blocker: Optional[IPBlocker] = None


def get_ip_blocker() -> IPBlocker:
    global _blocker
    if _blocker is None:
        _blocker = IPBlocker()
        try:
            cfg = ConfigRegistry.get_raw_config().get("ip_blocker", {})
            if cfg.get("enabled", False):
                _blocker.configure(cfg)
                _blocker.start_retry_worker(
                    persist_path=str(normalize_path("data/block_retry_queue.json"))
                )
                logger.info(f"[IP_BLOCKER] Initialized with {len(_blocker.devices)} device(s) + retry worker")
        except Exception as e:
            logger.warning(f"[IP_BLOCKER] Config load failed: {e}")
            _blocker.add_device(StdoutDevice())
    return _blocker
