# -*- coding: utf-8 -*-
"""
v1.8.1: 攻击者画像引擎 MVP — ThreatGraph
"""
import hashlib
import json
import logging
import threading
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterator, List, Mapping, Optional, Tuple

from anteumbra.domain import Repository
from anteumbra.domain.logging import log_with_symbol
from anteumbra.domain.site import SiteIdentity
from anteumbra.infrastructure.detection.file_cluster import FileClusterEngine
from anteumbra.infrastructure.models import (
    AttackEvent,
    AttackerProfile,
    FileReputation,
    IPReputation,
)

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

    def __init__(
        self,
        config: Mapping[str, object],
        file_cluster_engine: FileClusterEngine,
        *,
        shadow_repository: Repository | None = None,
        log: logging.Logger | None = None,
    ):
        self._lock = threading.RLock()
        self._file_cluster_engine = file_cluster_engine
        self._shadow = shadow_repository
        self._logger = log or logger
        self._profiles: Dict[str, AttackerProfile] = {}
        self._ip_table: Dict[tuple[str, str], IPReputation] = {}
        self._file_table: Dict[tuple[str, str], FileReputation] = {}
        self._persist_path: Optional[Path] = None
        management = config.get("management", {})
        profiling = config.get("profiling", {})
        self._management_ips = list(
            management.get("ips", []) if isinstance(management, Mapping) else []
        )
        self._time_window = int(
            profiling.get("time_window_hours", 4)
            if isinstance(profiling, Mapping)
            else 4
        )

    @staticmethod
    def _site(record: Mapping[str, Any]) -> SiteIdentity:
        site_id = str(record.get("site_id") or "").strip()
        site_name = str(record.get("site_name") or "").strip()
        if not site_id and not site_name:
            return SiteIdentity.legacy()
        return SiteIdentity.from_values(site_id or None, site_name or site_id)

    @staticmethod
    def _normalize_site_id(site_id: str) -> str:
        normalized = str(site_id).strip().lower()
        if not normalized:
            raise ValueError("site_id must not be empty")
        return normalized

    @staticmethod
    def _path_key(path: str) -> str:
        return str(path).replace("\\", "/").casefold()

    @classmethod
    def _ip_key(cls, site_id: str, ip: str) -> tuple[str, str]:
        return cls._normalize_site_id(site_id), str(ip)

    @classmethod
    def _file_key(cls, site_id: str, path: str) -> tuple[str, str]:
        return cls._normalize_site_id(site_id), cls._path_key(path)

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
                    self._logger.debug(
                        "CIDR check failed for management IP entry", exc_info=True
                    )
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
        self,
        ua: str,
        time_window_hours: int = 4,
        *,
        site_id: str = "legacy",
        site_name: str = "",
        observed_at: datetime | None = None,
    ) -> str:
        """生成画像 ID：站点 + UA 指纹 + 时间桶。

        v1.8.1 fix: URL 不参与聚类主键——攻击者不会按 URL 命名规律行动。
        URL 降级为画像 metadata，只显示给用户看。
        文件内容相似度（ssdeep/tlsh）留给 v2.0 三轨哈希引擎。
        """
        if time_window_hours <= 0:
            raise ValueError("time_window_hours must be positive")
        identity = SiteIdentity.from_values(site_id, site_name or site_id)
        ua_norm = self._normalize_ua(ua)
        now = observed_at or datetime.now()
        # 4-hour buckets: same attacker within a 4h window gets same profile
        hour_block = now.hour // time_window_hours
        time_bucket = now.strftime(f"%Y%m%d{hour_block:02d}")
        features = f"{identity.site_id}|{ua_norm}|{time_bucket}"
        return hashlib.sha256(features.encode()).hexdigest()[:16]

    # ── Event Ingestion ───────────────────────────────────────

    def ingest_waf_event(self, event: Dict) -> Optional[str]:
        """
        摄入一条 WAF 事件，更新 IP 信誉 + 画像。
        返回关联的 profile_id（可能创建新画像）。
        """
        with self._lock:
            site = self._site(event)
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
            ip_key = self._ip_key(site.site_id, ip)
            if ip_key not in self._ip_table:
                self._ip_table[ip_key] = IPReputation(
                    ip=ip,
                    first_seen=ts,
                    last_seen=ts,
                    site_id=site.site_id,
                    site_name=site.site_name,
                )
            ip_rep = self._ip_table[ip_key]
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
            pid = self.generate_profile_id(
                ua,
                self._time_window,
                site_id=site.site_id,
                site_name=site.site_name,
                observed_at=ts,
            )
            if pid not in self._profiles:
                self._profiles[pid] = AttackerProfile(
                    profile_id=pid,
                    created_at=ts,
                    updated_at=ts,
                    site_id=site.site_id,
                    site_name=site.site_name,
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
                timestamp=ts,
                site_id=site.site_id,
                site_name=site.site_name,
                event_type="waf_alert",
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

    def _cluster_file(self, file_path: str) -> str | None:
        try:
            cluster_id, _hash_value = self._file_cluster_engine.cluster_file(file_path)
            if cluster_id:
                self._logger.info(
                    "[PROFILE] File %s -> cluster %s",
                    Path(file_path).name,
                    cluster_id[:8],
                )
            return cluster_id
        except Exception as exc:
            self._logger.error("[PROFILE] Cluster failed for %s: %s", file_path, exc)
            return None

    @staticmethod
    def _event_time(value: Any) -> datetime:
        try:
            return datetime.fromisoformat(str(value)) if value else datetime.now()
        except (ValueError, TypeError):
            return datetime.now()

    def ingest_registry_entry(self, entry: Dict) -> Optional[str]:
        """
        摄入一条 Registry 检测记录，更新文件信誉 + 关联画像 + 文件相似度聚类。
        """
        with self._lock:
            site = self._site(entry)
            file_path = entry.get("file_path", "")
            features = entry.get("features", [])
            ip = entry.get("first_seen_ip") or "unknown"
            has_qid = bool(entry.get("quarantine_id"))
            cluster_id = self._cluster_file(file_path)
            ts = self._event_time(entry.get("detected_at"))

            # ── Update file reputation ────────────────────────
            fp_key = self._file_key(site.site_id, file_path)
            if fp_key not in self._file_table:
                self._file_table[fp_key] = FileReputation(
                    path=file_path,
                    first_seen=ts,
                    last_seen=ts,
                    site_id=site.site_id,
                    site_name=site.site_name,
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
            ip_key = self._ip_key(site.site_id, ip)
            if ip_key in self._ip_table:
                self._ip_table[ip_key].unique_files.add(file_path)
                # v1.9.0: 如果该 IP 关联了画像，把文件也关联到画像
                for pid in self._ip_table[ip_key].profile_ids:
                    if pid in self._profiles:
                        self._profiles[pid].target_files.add(file_path)
                        self._profiles[pid].updated_at = ts

            # ── Find matching profiles by file path pattern ───
            matched_pid = None
            url_pattern = self._normalize_url(file_path)
            for pid, profile in self._profiles.items():
                if (
                    profile.site_id == site.site_id
                    and profile.file_pattern
                    and profile.file_pattern in url_pattern
                ):
                    profile.target_files.add(file_path)
                    profile.updated_at = ts
                    fr.profile_ids.add(pid)
                    matched_pid = pid

            return matched_pid

    # ── Query API ─────────────────────────────────────────────

    def query_ip(
        self,
        ip: str,
        site_id: str | None = None,
    ) -> Optional[IPReputation]:
        """Return one site-qualified IP reputation or reject an ambiguous lookup."""
        with self._lock:
            if site_id is not None:
                return self._ip_table.get(self._ip_key(site_id, ip))
            matches = [
                reputation
                for (_record_site, record_ip), reputation in self._ip_table.items()
                if record_ip == str(ip)
            ]
            return matches[0] if len(matches) == 1 else None

    def query_file(
        self,
        path: str,
        site_id: str | None = None,
    ) -> Optional[FileReputation]:
        """Return one site-qualified file reputation or reject ambiguity."""
        path_key = self._path_key(path)
        with self._lock:
            if site_id is not None:
                return self._file_table.get(self._file_key(site_id, path))
            matches = [
                reputation
                for (_record_site, record_path), reputation in self._file_table.items()
                if record_path == path_key
            ]
            return matches[0] if len(matches) == 1 else None

    def query_profile(
        self,
        profile_id: str,
        site_id: str | None = None,
    ) -> Optional[AttackerProfile]:
        with self._lock:
            profile = self._profiles.get(profile_id)
            if profile is None or site_id is None:
                return profile
            return profile if profile.site_id == self._normalize_site_id(site_id) else None

    def get_active_profiles(
        self,
        min_score: float = 0.0,
        site_id: str | None = None,
    ) -> List[AttackerProfile]:
        """返回活跃画像，按风险分降序"""
        normalized_site = self._normalize_site_id(site_id) if site_id else None
        with self._lock:
            active = [p for p in self._profiles.values()
                      if p.status == "active"
                      and p.risk_score >= min_score
                      and (normalized_site is None or p.site_id == normalized_site)]
        return sorted(active, key=lambda p: p.risk_score, reverse=True)

    def get_cluster_level(
        self,
        ip: str,
        file_path: str = "",
        site_id: str | None = None,
    ) -> Tuple[int, int, str]:
        """返回 (ip_cluster_level, file_detection_count, profile_id)"""
        ip_rep = self.query_ip(ip, site_id=site_id)
        ip_level = ip_rep.cluster_level if ip_rep else 0
        fr = self.query_file(file_path, site_id=site_id) if file_path else None
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
        with self._lock:
            pids = list(self._profiles.keys())
            for i, pid1 in enumerate(pids):
                if pid1 not in self._profiles:
                    continue
                p1 = self._profiles[pid1]
                for pid2 in pids[i + 1:]:
                    if pid2 not in self._profiles:
                        continue
                    p2 = self._profiles[pid2]
                    if p1.site_id != p2.site_id:
                        continue
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
                        # Update only this site's IP references.
                        for ip in p2.ip_pool:
                            ip_key = self._ip_key(p2.site_id, ip)
                            if ip_key in self._ip_table:
                                self._ip_table[ip_key].profile_ids.discard(pid2)
                                self._ip_table[ip_key].profile_ids.add(pid1)
                        del self._profiles[pid2]
                        merged += 1
        if merged:
            log_with_symbol(
                "notice",
                "info",
                f"[THREAT_GRAPH] Merged {merged} profiles by IP overlap",
                self._logger,
            )

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

    def set_persist_path(self, path: str | Path) -> None:
        self._persist_path = Path(path)

    def persist(self) -> None:
        """Persist one site-qualified snapshot to authoritative JSON."""
        if not self._persist_path:
            return
        with self._lock:
            ip_table: dict[str, dict[str, dict[str, Any]]] = {}
            for reputation in self._ip_table.values():
                ip_table.setdefault(reputation.site_id, {})[reputation.ip] = (
                    self._ip_to_data(reputation)
                )
            file_table: dict[str, dict[str, dict[str, Any]]] = {}
            for reputation in self._file_table.values():
                file_table.setdefault(reputation.site_id, {})[
                    self._path_key(reputation.path)
                ] = self._file_to_data(reputation)
            data = {
                "schema_version": 2,
                "profiles": {
                    profile_id: self._profile_to_data(profile)
                    for profile_id, profile in self._profiles.items()
                },
                "ip_table": ip_table,
                "file_table": file_table,
            }

        self._persist_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._persist_path.with_suffix(".tmp")
        with tmp.open("w", encoding="utf-8") as handle:
            json.dump(data, handle, ensure_ascii=False, indent=2)
        tmp.replace(self._persist_path)
        self._shadow_persist(data)

    def _shadow_persist(self, data: dict[str, Any]) -> None:
        """Best-effort shadow write without affecting authoritative JSON."""
        if self._shadow is None:
            return
        for pid, profile_data in data.get("profiles", {}).items():
            try:
                self._shadow.save(pid, dict(profile_data))
            except Exception:
                self._logger.warning(
                    "Threat profile SQLite shadow write failed for %s",
                    pid,
                    exc_info=True,
                )

    def load(self) -> None:
        """Load the JSON source of truth, with SQLite profile recovery."""
        data: dict[str, Any] | None = None
        if self._persist_path and self._persist_path.exists():
            try:
                with open(self._persist_path, "r", encoding="utf-8") as handle:
                    data = json.load(handle)
            except Exception:
                self._logger.warning(
                    "[THREAT_GRAPH] Failed to load persisted JSON from %s",
                    self._persist_path,
                    exc_info=True,
                )

        if data is None and self._shadow is not None:
            try:
                profiles_list = self._shadow.list_all(limit=999999)
                if profiles_list:
                    profiles_dict: dict[str, dict[str, Any]] = {}
                    for profile_data in profiles_list:
                        profile_id = profile_data.get("profile_id", "")
                        if profile_id:
                            profiles_dict[profile_id] = profile_data
                    data = {
                        "schema_version": 2,
                        "profiles": profiles_dict,
                        "ip_table": {},
                        "file_table": {},
                    }
                    self._logger.warning(
                        "[THREAT_GRAPH] Recovered profiles from SQLite shadow; "
                        "IP reputation data requires the JSON backup"
                    )
            except Exception:
                self._logger.debug("SQLite shadow load failed", exc_info=True)

        if data is None:
            return

        with self._lock:
            self._profiles.clear()
            self._ip_table.clear()
            self._file_table.clear()
            self._load_profiles(data.get("profiles", {}))
            self._load_ip_reputations(data.get("ip_table", {}))
            self._load_file_reputations(data.get("file_table", {}))

    def _load_profiles(self, profiles: Any) -> None:
        if not isinstance(profiles, Mapping):
            return
        for profile_id, raw_profile in profiles.items():
            if not isinstance(raw_profile, Mapping):
                continue
            try:
                profile = self._profile_from_data(str(profile_id), raw_profile)
                self._profiles[profile.profile_id] = profile
            except Exception:
                self._logger.warning(
                    "[THREAT_GRAPH] Skipping invalid profile %s",
                    profile_id,
                    exc_info=True,
                )

    def _load_ip_reputations(self, table: Any) -> None:
        for site_id, ip, raw_reputation in self._persisted_records(
            table, identity_field="ip"
        ):
            try:
                reputation = self._ip_from_data(
                    ip, self._with_site_defaults(raw_reputation, site_id)
                )
                self._ip_table[
                    self._ip_key(reputation.site_id, reputation.ip)
                ] = reputation
            except Exception:
                self._logger.warning(
                    "[THREAT_GRAPH] Skipping invalid IP reputation %s/%s",
                    site_id,
                    ip,
                    exc_info=True,
                )

    def _load_file_reputations(self, table: Any) -> None:
        for site_id, path_key, raw_reputation in self._persisted_records(
            table, identity_field="path"
        ):
            try:
                reputation = self._file_from_data(
                    path_key, self._with_site_defaults(raw_reputation, site_id)
                )
                self._file_table[
                    self._file_key(reputation.site_id, reputation.path)
                ] = reputation
            except Exception:
                self._logger.warning(
                    "[THREAT_GRAPH] Skipping invalid file reputation %s/%s",
                    site_id,
                    path_key,
                    exc_info=True,
                )

    @staticmethod
    def _with_site_defaults(
        record: Mapping[str, Any],
        site_id: str,
    ) -> dict[str, Any]:
        payload = dict(record)
        payload.setdefault("site_id", site_id)
        payload.setdefault(
            "site_name",
            SiteIdentity.legacy().site_name if site_id == "legacy" else site_id,
        )
        return payload

    @staticmethod
    def _datetime(value: Any, *, default: datetime | None = None) -> datetime | None:
        if isinstance(value, datetime):
            return value
        if value:
            return datetime.fromisoformat(str(value))
        return default

    @classmethod
    def _event_to_data(cls, event: AttackEvent) -> dict[str, Any]:
        return {
            "timestamp": event.timestamp.isoformat(),
            "site_id": event.site_id,
            "site_name": event.site_name,
            "event_type": event.event_type,
            "src_ip": event.src_ip,
            "user_agent": event.user_agent,
            "url": event.url,
            "file_path": event.file_path,
            "waf_rule_id": event.waf_rule_id,
            "waf_score": event.waf_score,
        }

    @classmethod
    def _event_from_data(cls, data: Mapping[str, Any]) -> AttackEvent:
        site = cls._site(data)
        return AttackEvent(
            timestamp=cls._datetime(data.get("timestamp"), default=datetime.now()),
            site_id=site.site_id,
            site_name=site.site_name,
            event_type=str(data.get("event_type", "")),
            src_ip=str(data.get("src_ip", "")),
            user_agent=str(data.get("user_agent", "")),
            url=str(data.get("url", "")),
            file_path=str(data.get("file_path", "")),
            waf_rule_id=str(data.get("waf_rule_id", "")),
            waf_score=float(data.get("waf_score", 0)),
        )

    @classmethod
    def _profile_to_data(cls, profile: AttackerProfile) -> dict[str, Any]:
        return {
            "profile_id": profile.profile_id,
            "site_id": profile.site_id,
            "site_name": profile.site_name,
            "created_at": profile.created_at.isoformat(),
            "updated_at": profile.updated_at.isoformat(),
            "ip_pool": sorted(profile.ip_pool),
            "target_files": sorted(profile.target_files),
            "target_urls": sorted(profile.target_urls),
            "ua_fingerprint": profile.ua_fingerprint,
            "tool_signature": profile.tool_signature,
            "file_pattern": profile.file_pattern,
            "attack_chain": [cls._event_to_data(event) for event in profile.attack_chain],
            "risk_score": profile.risk_score,
            "raw_score": profile.raw_score,
            "decay_factor": profile.decay_factor,
            "last_decayed": (
                profile.last_decayed.isoformat() if profile.last_decayed else None
            ),
            "last_seen": profile.last_seen.isoformat() if profile.last_seen else None,
            "status": profile.status,
            "last_alert_sent": (
                profile.last_alert_sent.isoformat() if profile.last_alert_sent else None
            ),
            "alert_cooldown_seconds": profile.alert_cooldown_seconds,
        }

    @classmethod
    def _profile_from_data(
        cls,
        profile_id: str,
        data: Mapping[str, Any],
    ) -> AttackerProfile:
        site = cls._site(data)
        created_at = cls._datetime(data.get("created_at"), default=datetime.now())
        updated_at = cls._datetime(data.get("updated_at"), default=created_at)
        return AttackerProfile(
            profile_id=str(data.get("profile_id") or profile_id),
            created_at=created_at,
            updated_at=updated_at,
            site_id=site.site_id,
            site_name=site.site_name,
            ip_pool=set(data.get("ip_pool", [])),
            target_files=set(data.get("target_files", [])),
            target_urls=set(data.get("target_urls", [])),
            ua_fingerprint=str(data.get("ua_fingerprint", "")),
            tool_signature=str(data.get("tool_signature", "")),
            file_pattern=str(data.get("file_pattern", "")),
            attack_chain=[
                cls._event_from_data(event)
                for event in data.get("attack_chain", [])
                if isinstance(event, Mapping)
            ],
            risk_score=float(data.get("risk_score", 0)),
            raw_score=float(data.get("raw_score", data.get("risk_score", 0))),
            decay_factor=float(data.get("decay_factor", 1.0)),
            last_decayed=cls._datetime(data.get("last_decayed")),
            last_seen=cls._datetime(data.get("last_seen")),
            status=str(data.get("status", "active")),
            last_alert_sent=cls._datetime(data.get("last_alert_sent")),
            alert_cooldown_seconds=int(data.get("alert_cooldown_seconds", 60)),
        )

    @staticmethod
    def _ip_to_data(reputation: IPReputation) -> dict[str, Any]:
        return {
            "ip": reputation.ip,
            "site_id": reputation.site_id,
            "site_name": reputation.site_name,
            "first_seen": reputation.first_seen.isoformat(),
            "last_seen": reputation.last_seen.isoformat(),
            "event_count": reputation.event_count,
            "unique_files": sorted(reputation.unique_files),
            "unique_urls": sorted(reputation.unique_urls),
            "waf_score_avg": reputation.waf_score_avg,
            "reputation_score": reputation.reputation_score,
            "cluster_level": reputation.cluster_level,
            "profile_ids": sorted(reputation.profile_ids),
        }

    @classmethod
    def _ip_from_data(
        cls,
        ip: str,
        data: Mapping[str, Any],
    ) -> IPReputation:
        site = cls._site(data)
        return IPReputation(
            ip=str(data.get("ip") or ip),
            first_seen=cls._datetime(data.get("first_seen"), default=datetime.now()),
            last_seen=cls._datetime(data.get("last_seen"), default=datetime.now()),
            site_id=site.site_id,
            site_name=site.site_name,
            event_count=int(data.get("event_count", 0)),
            unique_files=set(data.get("unique_files", [])),
            unique_urls=set(data.get("unique_urls", [])),
            waf_score_avg=float(data.get("waf_score_avg", 0)),
            reputation_score=float(data.get("reputation_score", 0)),
            cluster_level=int(data.get("cluster_level", 0)),
            profile_ids=set(data.get("profile_ids", [])),
        )

    @staticmethod
    def _file_to_data(reputation: FileReputation) -> dict[str, Any]:
        return {
            "path": reputation.path,
            "site_id": reputation.site_id,
            "site_name": reputation.site_name,
            "first_seen": reputation.first_seen.isoformat(),
            "last_seen": reputation.last_seen.isoformat(),
            "detection_count": reputation.detection_count,
            "unique_ips": sorted(reputation.unique_ips),
            "yara_rules": list(reputation.yara_rules),
            "file_exists": reputation.file_exists,
            "quarantine_id": reputation.quarantine_id,
            "cluster_id": reputation.cluster_id,
            "profile_ids": sorted(reputation.profile_ids),
        }

    @classmethod
    def _file_from_data(
        cls,
        path: str,
        data: Mapping[str, Any],
    ) -> FileReputation:
        site = cls._site(data)
        return FileReputation(
            path=str(data.get("path") or path),
            first_seen=cls._datetime(data.get("first_seen"), default=datetime.now()),
            last_seen=cls._datetime(data.get("last_seen"), default=datetime.now()),
            site_id=site.site_id,
            site_name=site.site_name,
            detection_count=int(data.get("detection_count", 0)),
            unique_ips=set(data.get("unique_ips", [])),
            yara_rules=list(data.get("yara_rules", [])),
            file_exists=bool(data.get("file_exists", True)),
            quarantine_id=data.get("quarantine_id"),
            cluster_id=data.get("cluster_id"),
            profile_ids=set(data.get("profile_ids", [])),
        )

    @staticmethod
    def _persisted_records(
        table: Any,
        *,
        identity_field: str,
    ) -> Iterator[tuple[str, str, Mapping[str, Any]]]:
        """Yield schema-v2 nested records and legacy flat records uniformly."""
        if not isinstance(table, Mapping):
            return
        for outer_key, outer_value in table.items():
            if not isinstance(outer_value, Mapping):
                continue
            if identity_field in outer_value and (
                "first_seen" in outer_value or "last_seen" in outer_value
            ):
                yield "legacy", str(outer_key), outer_value
                continue
            for record_key, record in outer_value.items():
                if isinstance(record, Mapping):
                    yield str(outer_key), str(record_key), record

    def close(self) -> None:
        """Release the injected shadow repository."""
        close = getattr(self._shadow, "close", None)
        if callable(close):
            close()
