# -*- coding: utf-8 -*-
"""
v1.8.1: 攻击者画像引擎 MVP — ThreatGraph
"""
import logging
logger = logging.getLogger(__name__)

"""
v1.8.1: 攻击者画像引擎 MVP — ThreatGraph
从 WAF 事件 + Registry 文件检测中聚类攻击者行为指纹。

核心思路（来自 PROJECT_MASTER 6.x）：
    画像 ID 不是 IP。代理池 IP 会变，但工具指纹（UA + 文件簇 + 时间桶）是稳定的。
    三轨聚类：UA 规范化 → 文件路径模式 → 时间窗口 → SHA256 哈希

数据结构：
    AttackerProfile  — 画像实体
    IPReputation     — IP 信誉表（从 WAF 事件聚合）
    FileReputation   — 文件信誉表（从 Registry 聚合）
"""

import hashlib, json, os, re, threading, time
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from anteumbra.infrastructure.utils.path_utils import normalize_path
from anteumbra.infrastructure.utils.logger_factory import log_with_symbol
from anteumbra.infrastructure.models import (
    AttackEvent, AttackerProfile, IPReputation, FileReputation
)


# ═══════════════════════════════════════════════════════════════
# Threat Graph Engine
# ═══════════════════════════════════════════════════════════════

class ThreatGraph:
    """
    攻击者画像引擎。

    使用方式：
        graph = ThreatGraph()
        graph.ingest_waf_event(event_dict)
        graph.ingest_registry_entry(registry_dict)
        profiles = graph.get_active_profiles()
        ip_info = graph.query_ip("10.0.0.1")
    """

    def __init__(self):
        self._lock = threading.RLock()
        self._profiles: Dict[str, AttackerProfile] = {}
        self._ip_table: Dict[str, IPReputation] = {}
        self._file_table: Dict[str, FileReputation] = {}
        self._persist_path: Optional[Path] = None
        self._management_ips: list = []
        self._time_window: int = 4
        self._load_config()

    def _load_config(self):
        """v1.9.0: 从 config.toml 加载画像参数"""
        try:
            from anteumbra.infrastructure.config.registry import ConfigRegistry
            cfg = ConfigRegistry.get_raw_config()
            self._management_ips = cfg.get('management', {}).get('ips', [])
            self._time_window = cfg.get('profiling', {}).get('time_window_hours', 4)
        except Exception:
            pass

    def _is_management_ip(self, ip: str) -> bool:
        """检查是否管理IP——这些IP不参与画像但监控层仍会告警"""
        if not ip:
            return False
        for entry in self._management_ips:
            if '/' in entry:  # CIDR
                try:
                    import ipaddress
                    if ipaddress.ip_address(ip) in ipaddress.ip_network(entry, strict=False):
                        return True
                except Exception:
                    pass
            if ip == entry:
                return True
        return False

    # ── Profile ID Generation ─────────────────────────────────

    @staticmethod
    def _normalize_ua(ua: str) -> str:
        """规范化 UA：去掉版本号，保留工具类型标识"""
        if not ua:
            return "empty"
        # AntSword/2.1.15 → antsword
        ua_lower = ua.lower()
        # Known tools
        for tool, sig in [
            ("antsword", "antsword"), ("behinder", "behinder"),
            ("godzilla", "godzilla"), ("sqlmap", "sqlmap"),
            ("python-requests", "python-requests"),
            ("nmap", "nmap"), ("burp", "burpsuite"),
            ("chrome", "browser"), ("firefox", "browser"),
        ]:
            if tool in ua_lower:
                return sig
        # Generic: strip version numbers, return first token
        import re as _re
        stripped = _re.sub(r'\d+\.\d+(\.\d+)?', '', ua_lower)
        return stripped.strip().split('/')[0][:20] or "unknown"

    @staticmethod
    def _normalize_url(url: str) -> str:
        """提取 URL 路径模式，去掉具体文件名和参数"""
        if not url:
            return "/"
        import re as _re
        path = url.split('?')[0]
        # Normalize filename-embedded numbers: upload_0.jsp → upload_{id}.{script}
        path = _re.sub(r'_\d+\.', '_{id}.', path)
        # Normalize path-segment numbers: /123/ → /{id}/
        path = _re.sub(r'/\d+/', '/{id}/', path)
        path = _re.sub(r'/\d+$', '/{id}', path)
        # Normalize file extension patterns
        path = _re.sub(r'\.(php|jsp|asp|aspx|jspx)', '.{script}', path)
        return path

    def generate_profile_id(
        self, ua: str, time_window_hours: int = 4
    ) -> str:
        """生成画像 ID：UA 指纹 + 时间桶

        v1.8.1 fix: URL 不参与聚类主键——攻击者不会按 URL 命名规律行动。
        URL 降级为画像 metadata，只显示给用户看。
        文件内容相似度（ssdeep/tlsh）留给 v2.0 三轨哈希引擎。
        """
        ua_norm = self._normalize_ua(ua)
        now = datetime.now()
        # 4-hour buckets: same attacker within a 4h window gets same profile
        hour_block = now.hour // time_window_hours
        time_bucket = now.strftime(f"%Y%m%d{hour_block:02d}")
        features = f"{ua_norm}|{time_bucket}"
        return hashlib.sha256(features.encode()).hexdigest()[:16]

    # ── Event Ingestion ───────────────────────────────────────

    def ingest_waf_event(self, event: Dict) -> Optional[str]:
        """
        摄入一条 WAF 事件，更新 IP 信誉 + 画像。
        返回关联的 profile_id（可能创建新画像）。
        """
        with self._lock:
            ip = event.get("src_ip", "")
            ua = event.get("user_agent", "")
            url = event.get("url", "")
            ts_str = event.get("timestamp", "")
            waf_score = float(event.get("waf_score", 0))
            rule_id = event.get("waf_rule_id", "")

            # Parse timestamp
            try:
                ts = datetime.fromisoformat(ts_str)
            except (ValueError, TypeError):
                ts = datetime.now()

            # v1.9.0: 管理IP不参与画像（监控层仍会告警）
            if self._is_management_ip(ip):
                return None

            # ── Update IP reputation ──────────────────────────
            if ip not in self._ip_table:
                self._ip_table[ip] = IPReputation(
                    ip=ip, first_seen=ts, last_seen=ts
                )
            ip_rep = self._ip_table[ip]
            ip_rep.last_seen = ts
            ip_rep.event_count += 1
            ip_rep.unique_urls.add(url)
            # Moving average for WAF score
            n = ip_rep.event_count
            ip_rep.waf_score_avg = (ip_rep.waf_score_avg * (n - 1) + waf_score) / n

            # ── Cluster level assessment ──────────────────────
            if ip_rep.event_count > 100:
                ip_rep.cluster_level = 3  # confirmed attacker / proxy pool
            elif ip_rep.event_count > 10:
                ip_rep.cluster_level = 2  # suspicious
            elif ip_rep.event_count > 1:
                ip_rep.cluster_level = 1

            # ── Find or create profile ────────────────────────
            pid = self.generate_profile_id(ua)
            if pid not in self._profiles:
                self._profiles[pid] = AttackerProfile(
                    profile_id=pid,
                    created_at=ts,
                    updated_at=ts,
                    ua_fingerprint=self._normalize_ua(ua),
                    file_pattern=self._normalize_url(url),
                )
            profile = self._profiles[pid]
            profile.updated_at = ts
            profile.last_seen = ts
            profile.ip_pool.add(ip)
            profile.target_urls.add(url)

            # Add event to attack chain (keep last 100)
            evt = AttackEvent(
                timestamp=ts, event_type="waf_alert",
                src_ip=ip, user_agent=ua, url=url,
                waf_rule_id=rule_id, waf_score=waf_score,
            )
            profile.attack_chain.append(evt)
            if len(profile.attack_chain) > 100:
                profile.attack_chain = profile.attack_chain[-100:]

            # ── Risk scoring ──────────────────────────────────
            # Base score from WAF confidence
            profile.raw_score = max(profile.raw_score, waf_score)
            # Bonus for IP pool diversity (proxy detection)
            ip_diversity_bonus = min(len(profile.ip_pool) * 0.005, 0.5)
            # Bonus for URL diversity
            url_diversity = len(profile.target_urls)
            url_bonus = min(url_diversity * 0.02, 0.3)
            profile.risk_score = min(profile.raw_score + ip_diversity_bonus + url_bonus, 1.0)

            # ── Cross-reference ────────────────────────────────
            ip_rep.profile_ids.add(pid)
            profile.tool_signature = rule_id if rule_id else profile.tool_signature

            return pid

    def ingest_registry_entry(self, entry: Dict) -> Optional[str]:
        """
        摄入一条 Registry 检测记录，更新文件信誉 + 关联画像 + 文件相似度聚类。
        """
        with self._lock:
            file_path = entry.get("file_path", "")
            features = entry.get("features", [])
            ip = entry.get("first_seen_ip") or "unknown"
            ts_str = entry.get("detected_at", "")
            has_qid = bool(entry.get("quarantine_id"))

            # v1.8.3: 文件相似度聚类
            cluster_id = None
            try:
                from anteumbra.infrastructure.detection.file_cluster import get_file_cluster_engine
                cluster_id, hash_val = get_file_cluster_engine().cluster_file(file_path)
                if cluster_id:
                    logger.info(f"[PROFILE] File {file_path.rsplit(chr(92),1)[-1]} -> cluster {cluster_id[:8]}")
            except Exception as e:
                logger.error(f"[PROFILE] Cluster failed for {file_path}: {e}")

            try:
                ts = datetime.fromisoformat(ts_str) if ts_str else datetime.now()
            except (ValueError, TypeError):
                ts = datetime.now()

            # ── Update file reputation ────────────────────────
            fp_key = file_path.lower()
            if fp_key not in self._file_table:
                self._file_table[fp_key] = FileReputation(
                    path=file_path, first_seen=ts, last_seen=ts
                )
            fr = self._file_table[fp_key]
            fr.last_seen = ts
            fr.detection_count += 1
            fr.unique_ips.add(ip)
            fr.yara_rules = list(set(fr.yara_rules + features))
            fr.file_exists = entry.get("file_exists", True)
            if has_qid:
                fr.quarantine_id = entry.get("quarantine_id")
            if cluster_id:
                fr.cluster_id = cluster_id  # v1.8.3

            # ── Cross-reference with IP table ─────────────────
            if ip in self._ip_table:
                self._ip_table[ip].unique_files.add(file_path)
                # v1.9.0: 如果该 IP 关联了画像，把文件也关联到画像
                for pid in self._ip_table[ip].profile_ids:
                    if pid in self._profiles:
                        self._profiles[pid].target_files.add(file_path)
                        self._profiles[pid].updated_at = ts

            # ── Find matching profiles by file path pattern ───
            matched_pid = None
            url_pattern = self._normalize_url(file_path)
            for pid, profile in self._profiles.items():
                if profile.file_pattern and profile.file_pattern in url_pattern:
                    profile.target_files.add(file_path)
                    profile.updated_at = ts
                    fr.profile_ids.add(pid)
                    matched_pid = pid

            return matched_pid

    # ── Query API ─────────────────────────────────────────────

    def query_ip(self, ip: str) -> Optional[IPReputation]:
        return self._ip_table.get(ip)

    def query_file(self, path: str) -> Optional[FileReputation]:
        return self._file_table.get(path.lower())

    def query_profile(self, profile_id: str) -> Optional[AttackerProfile]:
        return self._profiles.get(profile_id)

    def get_active_profiles(self, min_score: float = 0.0) -> List[AttackerProfile]:
        """返回活跃画像，按风险分降序"""
        active = [p for p in self._profiles.values()
                  if p.status == "active" and p.risk_score >= min_score]
        return sorted(active, key=lambda p: p.risk_score, reverse=True)

    def get_cluster_level(self, ip: str, file_path: str = "") -> Tuple[int, int, str]:
        """返回 (ip_cluster_level, file_detection_count, profile_id)"""
        ip_rep = self._ip_table.get(ip)
        ip_level = ip_rep.cluster_level if ip_rep else 0
        fr = self._file_table.get(file_path.lower())
        file_count = fr.detection_count if fr else 0
        # Find best matching profile
        pid = ""
        if ip_rep and ip_rep.profile_ids:
            # Return highest-risk profile for this IP
            best = max(
                (self._profiles.get(p) for p in ip_rep.profile_ids if self._profiles.get(p)),
                key=lambda p: p.risk_score, default=None
            )
            pid = best.profile_id if best else ""
        return (ip_level, file_count, pid)

    # ── IP Pool Merge ───────────────────────────────────────

    def merge_overlapping_profiles(self, min_overlap: int = 3):
        """合并 IP 池重叠的画像——同一攻击者使用多个 UA 时自动合并"""
        merged = 0
        pids = list(self._profiles.keys())
        for i, pid1 in enumerate(pids):
            if pid1 not in self._profiles:
                continue
            p1 = self._profiles[pid1]
            for pid2 in pids[i + 1:]:
                if pid2 not in self._profiles:
                    continue
                p2 = self._profiles[pid2]
                overlap = p1.ip_pool & p2.ip_pool
                if len(overlap) >= min_overlap:
                    # Merge p2 into p1
                    p1.ip_pool |= p2.ip_pool
                    p1.target_files |= p2.target_files
                    p1.target_urls |= p2.target_urls
                    p1.attack_chain.extend(p2.attack_chain)
                    p1.attack_chain.sort(key=lambda e: e.timestamp)
                    p1.risk_score = max(p1.risk_score, p2.risk_score)
                    p1.raw_score = max(p1.raw_score, p2.raw_score)
                    p1.updated_at = datetime.now()
                    # Update IP table references
                    for ip in p2.ip_pool:
                        if ip in self._ip_table:
                            self._ip_table[ip].profile_ids.discard(pid2)
                            self._ip_table[ip].profile_ids.add(pid1)
                    del self._profiles[pid2]
                    merged += 1
        if merged:
            log_with_symbol("notice", "info", f"[THREAT_GRAPH] Merged {merged} profiles by IP overlap")

    # ── Basic Decay ───────────────────────────────────────────

    def decay_profiles(self, now: Optional[datetime] = None):
        """对长时间未活跃的画像进行风险衰减"""
        now = now or datetime.now()
        with self._lock:
            expired = []
            for pid, profile in self._profiles.items():
                if not profile.last_seen:
                    continue
                delta_hours = (now - profile.last_seen).total_seconds() / 3600
                if delta_hours >= 72:
                    profile.risk_score = profile.raw_score * 0.1
                    profile.decay_factor = 0.1
                    profile.status = "dormant"
                elif delta_hours >= 24:
                    profile.risk_score = profile.raw_score * 0.5
                    profile.decay_factor = 0.5
                profile.last_decayed = now

                # 7 days no activity → expire
                if delta_hours >= 168:
                    expired.append(pid)

            for pid in expired:
                self._profiles[pid].status = "expired"

    # ── Persistence ───────────────────────────────────────────

    def set_persist_path(self, path: str):
        self._persist_path = Path(path)

    def persist(self):
        """持久化到 JSON"""
        if not self._persist_path:
            return
        self._persist_path.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "profiles": {
                pid: {
                    "profile_id": p.profile_id,
                    "created_at": p.created_at.isoformat(),
                    "updated_at": p.updated_at.isoformat(),
                    "ip_pool": list(p.ip_pool),
                    "target_files": list(p.target_files),
                    "target_urls": list(p.target_urls),
                    "ua_fingerprint": p.ua_fingerprint,
                    "tool_signature": p.tool_signature,
                    "risk_score": p.risk_score,
                    "status": p.status,
                    "last_seen": p.last_seen.isoformat() if p.last_seen else None,
                } for pid, p in self._profiles.items()
            },
            "ip_table": {
                ip: {
                    "ip": r.ip,
                    "first_seen": r.first_seen.isoformat(),
                    "last_seen": r.last_seen.isoformat(),
                    "event_count": r.event_count,
                    "waf_score_avg": r.waf_score_avg,
                    "cluster_level": r.cluster_level,
                } for ip, r in self._ip_table.items()
            },
        }
        tmp = self._persist_path.with_suffix('.tmp')
        with open(tmp, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        tmp.replace(self._persist_path)

        # v2.0: Shadow-write to Repository for storage.backend = sqlite / both
        self._repo_shadow_persist(data)

    def _repo_shadow_persist(self, data: dict):
        """v2.0: Shadow-write threat profiles to Repository interface.

        Best-effort — failures are silently ignored.
        """
        try:
            from anteumbra.infrastructure.persistence import get_repository
            repo = get_repository("threat_profiles")
            for pid, pd in data.get("profiles", {}).items():
                try:
                    repo.save(pid, dict(pd))
                except Exception:
                    pass
        except Exception:
            pass

    def load(self):
        """从持久化文件加载。

        v2.0: Repository-first loading. When storage.backend is sqlite or both,
        reads profiles from SQLite via Repository. Falls back to JSON when
        backend is json or Repository is unavailable.
        """
        # v2.0: Try Repository first (SQLite primary)
        data = None
        try:
            from anteumbra.infrastructure.config.registry import ConfigRegistry
            config = ConfigRegistry.get_raw_config()
            backend = config.get("storage", {}).get("backend", "json")
            if backend != "json":
                from anteumbra.infrastructure.persistence import get_repository
                repo = get_repository("threat_profiles")
                profiles_list = repo.list_all(limit=999999)
                if profiles_list:
                    # Reconstruct profiles from flat dicts
                    profiles_dict = {}
                    for pd in profiles_list:
                        pid = pd.get("profile_id", "")
                        if pid:
                            profiles_dict[pid] = pd
                    data = {"profiles": profiles_dict, "ip_table": {}}
        except Exception:
            pass

        # Fallback: load from JSON file
        if data is None:
            if not self._persist_path or not self._persist_path.exists():
                return
            try:
                with open(self._persist_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
            except Exception:
                return

        # Reconstruct domain objects from data dict (shared logic)
        try:
            for pid, pd in data.get("profiles", {}).items():
                p = AttackerProfile(
                    profile_id=pid,
                    created_at=datetime.fromisoformat(pd["created_at"]),
                    updated_at=datetime.fromisoformat(pd["updated_at"]),
                    ip_pool=set(pd.get("ip_pool", [])),
                    target_files=set(pd.get("target_files", [])),
                    target_urls=set(pd.get("target_urls", [])),
                    ua_fingerprint=pd.get("ua_fingerprint", ""),
                    tool_signature=pd.get("tool_signature", ""),
                    risk_score=pd.get("risk_score", 0),
                    status=pd.get("status", "active"),
                    last_seen=datetime.fromisoformat(pd["last_seen"]) if pd.get("last_seen") else None,
                )
                self._profiles[pid] = p
            for ip, rd in data.get("ip_table", {}).items():
                self._ip_table[ip] = IPReputation(
                    ip=ip,
                    first_seen=datetime.fromisoformat(rd["first_seen"]),
                    last_seen=datetime.fromisoformat(rd["last_seen"]),
                    event_count=rd.get("event_count", 0),
                    waf_score_avg=rd.get("waf_score_avg", 0),
                    cluster_level=rd.get("cluster_level", 0),
                )
        except Exception as e:
            log_with_symbol("error_scan", "error", f"[THREAT_GRAPH] Load failed: {e}")


# ═══════════════════════════════════════════════════════════════
# Singleton
# ═══════════════════════════════════════════════════════════════

_graph: Optional[ThreatGraph] = None


def get_threat_graph() -> ThreatGraph:
    global _graph
    if _graph is None:
        _graph = ThreatGraph()
        _graph.set_persist_path(normalize_path("data/threat_intel/threat_graph.json"))
        _graph.load()
    return _graph
