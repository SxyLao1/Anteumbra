# -*- coding: utf-8 -*-
"""
@Time: 1/5/2026 1:26 PM
@Auth: SxyLao1
@File: models.py
@IDE: PyCharm
@Motto: HACK THE REAL
v1.7.4增强：ScanOptions支持access_log_path配置
"""
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from anteumbra.domain.scan import ScanOptions
from anteumbra.domain.site import SiteIdentity
from anteumbra.infrastructure.utils.path_utils import normalize_path


# ═══════════════════════════════════════════════════════════════
# v1.8.3: 画像引擎数据模型（从 threat_graph.py 迁移至此后统一管理）
# ═══════════════════════════════════════════════════════════════

@dataclass
class AttackEvent:
    """单次攻击事件"""
    timestamp: 'datetime'
    site_id: str = "legacy"
    site_name: str = "Legacy / unassigned"
    event_type: str = ""
    src_ip: str = ""
    user_agent: str = ""
    url: str = ""
    file_path: str = ""
    waf_rule_id: str = ""
    waf_score: float = 0.0

@dataclass
class AttackerProfile:
    """攻击者画像"""
    profile_id: str
    created_at: 'datetime'
    updated_at: 'datetime'
    site_id: str = "legacy"
    site_name: str = "Legacy / unassigned"
    ip_pool: Set[str] = field(default_factory=set)
    target_files: Set[str] = field(default_factory=set)
    target_urls: Set[str] = field(default_factory=set)
    ua_fingerprint: str = ""
    tool_signature: str = ""
    file_pattern: str = ""
    attack_chain: list = field(default_factory=list)
    risk_score: float = 0.0
    raw_score: float = 0.0
    decay_factor: float = 1.0
    last_decayed: Optional['datetime'] = None
    last_seen: Optional['datetime'] = None
    status: str = "active"
    last_alert_sent: Optional['datetime'] = None
    alert_cooldown_seconds: int = 60

@dataclass
class IPReputation:
    """IP 信誉"""
    ip: str
    first_seen: 'datetime'
    last_seen: 'datetime'
    site_id: str = "legacy"
    site_name: str = "Legacy / unassigned"
    event_count: int = 0
    unique_files: Set[str] = field(default_factory=set)
    unique_urls: Set[str] = field(default_factory=set)
    waf_score_avg: float = 0.0
    reputation_score: float = 0.0
    cluster_level: int = 0
    profile_ids: Set[str] = field(default_factory=set)

@dataclass
class FileReputation:
    """文件信誉"""
    path: str
    first_seen: 'datetime'
    last_seen: 'datetime'
    site_id: str = "legacy"
    site_name: str = "Legacy / unassigned"
    detection_count: int = 0
    unique_ips: Set[str] = field(default_factory=set)
    yara_rules: list = field(default_factory=list)
    file_exists: bool = True
    quarantine_id: Optional[str] = None
    cluster_id: Optional[str] = None
    profile_ids: Set[str] = field(default_factory=set)


@dataclass
class Website:
    """网站配置对象"""
    name: str
    path: Path
    port: int
    enabled: bool = False
    scan_options: ScanOptions = field(default_factory=ScanOptions)
    log_config: Dict[str, Any] = field(default_factory=dict)
    # Keep this after the pre-existing positional fields. Older integrations
    # may still construct Website(name, path, port, enabled, options, logs).
    site_id: str = ""

    def __post_init__(self):
        """Normalize the site identity and validate the parsed website configuration."""
        identity = SiteIdentity.from_values(self.site_id, self.name)
        self.site_id = identity.site_id
        self.name = identity.site_name
        """对象创建后的自动验证"""
        # 确保path是Path对象
        if isinstance(self.path, str):
            self.path = normalize_path(self.path)
        # 端口范围验证
        if not (1 <= self.port <= 65535):
            raise ValueError(f"端口 {self.port} 超出范围(1-65535)")

    def is_reachable(self) -> bool:
        """检查端口是否可达"""
        from anteumbra.infrastructure.detection.scanner import check_port
        return check_port("127.0.0.1", self.port)

    def __str__(self):
        """用于友好打印"""
        return (
            f"Website(site_id='{self.site_id}', name='{self.name}', "
            f"path={self.path}, port={self.port}, enabled={self.enabled})"
        )
