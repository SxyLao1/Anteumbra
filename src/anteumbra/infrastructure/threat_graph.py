# -*- coding: utf-8 -*-
"""
v1.8.1: 攻击者画像引擎 MVP — ThreatGraph
"""
import logging
import threading
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Tuple

from anteumbra.domain import threat_profile_rules
from anteumbra.domain.logging import log_with_symbol
from anteumbra.domain.service_ports import (
    FileClusterEnginePort,
    ThreatProfileRepositoryPort,
)
from anteumbra.domain.site import SiteIdentity
from anteumbra.infrastructure.models import (
    AttackerProfile,
    AttackEvent,
    FileReputation,
    IPReputation,
)
from anteumbra.infrastructure.threat_graph_store import (
    ThreatGraphSnapshot,
    ThreatGraphStore,
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
        file_cluster_engine: FileClusterEnginePort,
        *,
        shadow_repository: ThreatProfileRepositoryPort | None = None,
        log: logging.Logger | None = None,
    ):
        self._lock = threading.RLock()
        self._file_cluster_engine = file_cluster_engine
        self._shadow = shadow_repository
        self._logger = log or logger
        self._store = ThreatGraphStore(shadow_repository, self._logger)
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
        return threat_profile_rules.normalize_user_agent(ua)

    @staticmethod
    def _normalize_url(url: str) -> str:
        return threat_profile_rules.normalize_url_pattern(url)

    def generate_profile_id(
        self,
        ua: str,
        time_window_hours: int = 4,
        *,
        site_id: str = "legacy",
        site_name: str = "",
        observed_at: datetime | None = None,
    ) -> str:
        return threat_profile_rules.generate_profile_id(
            ua,
            time_window_hours,
            site_id=site_id,
            site_name=site_name,
            observed_at=observed_at or datetime.now(),
        )
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

            ip_rep.cluster_level = threat_profile_rules.cluster_level(
                ip_rep.event_count
            )
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

            profile.raw_score = max(profile.raw_score, waf_score)
            profile.risk_score = threat_profile_rules.calculate_risk_score(
                profile.raw_score,
                len(profile.ip_pool),
                len(profile.target_urls),
            )
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

    def find_profiles_for_file(
        self,
        path: str,
        site_id: str | None = None,
    ) -> List[AttackerProfile]:
        """Return profiles linked to a file without exposing the profile table."""
        path_key = self._path_key(path)
        normalized_site = self._normalize_site_id(site_id) if site_id else None
        with self._lock:
            matches = [
                profile
                for profile in self._profiles.values()
                if (normalized_site is None or profile.site_id == normalized_site)
                and any(self._path_key(item) == path_key for item in profile.target_files)
            ]
        return sorted(matches, key=lambda profile: profile.risk_score, reverse=True)

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
        """Merge same-site profiles whose IP pools overlap."""
        merged = 0
        with self._lock:
            profile_ids = list(self._profiles)
            for index, primary_id in enumerate(profile_ids):
                if primary_id not in self._profiles:
                    continue
                primary = self._profiles[primary_id]
                for secondary_id in profile_ids[index + 1:]:
                    if secondary_id not in self._profiles:
                        continue
                    secondary = self._profiles[secondary_id]
                    if primary.site_id != secondary.site_id:
                        continue
                    if len(primary.ip_pool & secondary.ip_pool) < min_overlap:
                        continue

                    threat_profile_rules.merge_profile_into(
                        primary,
                        secondary,
                        merged_at=datetime.now(),
                    )
                    for ip in secondary.ip_pool:
                        ip_key = self._ip_key(secondary.site_id, ip)
                        if ip_key in self._ip_table:
                            self._ip_table[ip_key].profile_ids.discard(secondary_id)
                            self._ip_table[ip_key].profile_ids.add(primary_id)
                    del self._profiles[secondary_id]
                    merged += 1

        if merged:
            log_with_symbol(
                "notice",
                "info",
                f"[THREAT_GRAPH] Merged {merged} profiles by IP overlap",
                self._logger,
            )
        return merged

    def decay_profiles(self, now: Optional[datetime] = None):
        """Apply inactivity decay to all profiles."""
        current_time = now or datetime.now()
        with self._lock:
            expired = [
                profile_id
                for profile_id, profile in self._profiles.items()
                if threat_profile_rules.decay_profile(profile, current_time)
            ]
            for profile_id in expired:
                self._profiles[profile_id].status = "expired"
        return len(expired)
    # ── Persistence ───────────────────────────────────────────

    def set_persist_path(self, path: str | Path) -> None:
        self._persist_path = Path(path)

    def persist(self) -> None:
        """Persist one site-qualified snapshot to authoritative JSON."""
        if not self._persist_path:
            return
        with self._lock:
            self._store.persist(
                self._persist_path,
                ThreatGraphSnapshot(
                    profiles=dict(self._profiles),
                    ip_table=dict(self._ip_table),
                    file_table=dict(self._file_table),
                ),
            )

    def load(self) -> None:
        """Load authoritative JSON, with profile-only shadow recovery."""
        snapshot = self._store.load(self._persist_path)
        if snapshot is None:
            return
        with self._lock:
            self._profiles = snapshot.profiles
            self._ip_table = snapshot.ip_table
            self._file_table = snapshot.file_table

    def close(self) -> None:
        self._store.close()
