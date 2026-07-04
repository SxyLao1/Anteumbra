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
from pathlib import Path
from typing import List, Optional, Set

from anteumbra.infrastructure.utils.path_utils import normalize_path


# ═══════════════════════════════════════════════════════════════
# v1.8.3: 画像引擎数据模型（从 threat_graph.py 迁移至此后统一管理）
# ═══════════════════════════════════════════════════════════════

@dataclass
class AttackEvent:
    """单次攻击事件"""
    timestamp: 'datetime'
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
    detection_count: int = 0
    unique_ips: Set[str] = field(default_factory=set)
    yara_rules: list = field(default_factory=list)
    file_exists: bool = True
    quarantine_id: Optional[str] = None
    cluster_id: Optional[str] = None
    profile_ids: Set[str] = field(default_factory=set)


@dataclass
class ScanOptions:
    """扫描策略配置"""
    monitor_extensions: List[str] = field(default_factory=lambda: [".php"])
    exclude_dirs: List[str] = field(default_factory=list)
    exclude_files: List[str] = field(default_factory=list)
    max_file_size: str = "10MB"
    debug_mode: bool = False
    # v1.7.4新增：access_log_path支持（用于通配符配置）
    access_log_path: Optional[str] = None  # 新增字段

    @property
    def max_size_bytes(self) -> int:
        """将文件大小字符串转换为字节"""
        size_str = self.max_file_size.upper()
        multipliers = {'KB': 1024, 'MB': 1024**2, 'GB': 1024**3, 'TB': 1024**4}
        for unit, multiplier in multipliers.items():
            if size_str.endswith(unit):
                return int(size_str.replace(unit, '')) * multiplier
        return int(size_str)

@dataclass
class Website:
    """网站配置对象"""
    name: str
    path: Path
    port: int
    enabled: bool = False
    scan_options: ScanOptions = field(default_factory=ScanOptions)

    def __post_init__(self):
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
        return f"Website(name='{self.name}', path={self.path}, port={self.port}, enabled={self.enabled})"
