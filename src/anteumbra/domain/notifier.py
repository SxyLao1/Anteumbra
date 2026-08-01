# -*- coding: utf-8 -*-
"""
v1.9.0: Notifier 抽象接口

告警通知插件契约。所有通知渠道（邮件、微信、Webhook、
Syslog、CEF）都实现此接口。
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class AlertLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class AlertMessage:
    """统一告警消息结构"""
    alert_id: str
    level: AlertLevel
    title: str
    body: str                          # 纯文本版本
    body_html: Optional[str] = None    # HTML 版本（邮件等富文本渠道）
    metadata: Dict[str, Any] = field(default_factory=dict)
    # 常见元数据键: file_path, src_ip, profile_id, rule_name, score


class Notifier(ABC):
    """通知器抽象接口"""

    @property
    @abstractmethod
    def name(self) -> str:
        """通知渠道名称，如 'email', 'wechat', 'webhook', 'syslog'"""
        ...

    @property
    def enabled(self) -> bool:
        """是否默认启用"""
        return True

    @abstractmethod
    def send(self, message: AlertMessage) -> bool:
        """发送单条告警。返回是否成功。"""
        ...

    def send_batch(self, messages: List[AlertMessage]) -> Dict[str, bool]:
        """批量发送告警。默认逐条调用 send()。

        子类可 override 实现真正的批量推送（如聚合 Webhook）。
        返回 {alert_id: success} 字典。
        """
        return {m.alert_id: self.send(m) for m in messages}
