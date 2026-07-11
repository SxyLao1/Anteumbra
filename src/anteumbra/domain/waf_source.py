# -*- coding: utf-8 -*-
"""WAF/FW event source abstraction.

Anteumbra does not parse raw traffic; it consumes structured event summaries
already emitted by WAFs or log adapters.
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional


@dataclass
class WAFEvent:
    """WAF 返回的单条攻击事件"""
    event_id: str
    src_ip: str
    timestamp: str          # ISO format
    http_method: str
    url: str
    user_agent: str
    waf_rule_id: str
    waf_score: float
    attack_type: str        # webshell, sqli, rce, c2, scanner, mixed

    # 画像引擎使用的额外字段
    file_path: Optional[str] = None    # 关联的本地文件路径（文件事件关联后填充）
    profile_id: Optional[str] = None   # 画像引擎分配后回写


class WAFEventSource(ABC):
    """WAF/FW 事件源抽象接口"""

    @abstractmethod
    def pull_events(self, start_time: datetime, end_time: datetime) -> List[WAFEvent]:
        """从 WAF 拉取指定时间窗口内的攻击事件"""
        pass

    @abstractmethod
    def is_available(self) -> bool:
        """检查 WAF 源是否可用"""
        pass

    @abstractmethod
    def get_name(self) -> str:
        """返回事件源名称"""
        pass
