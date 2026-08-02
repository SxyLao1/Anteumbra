# -*- coding: utf-8 -*-
"""
Plugin abstraction for Anteumbra extension points.

Detectors, notifiers, event sources, and repositories can implement this
contract and be registered through PluginManager.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class DomainEvent:
    """统一领域事件结构（v1.9.x 与旧 dict 共存，v2.0 强制使用）"""

    event_type: str
    timestamp: float
    source: str
    payload: Dict[str, Any]


class Plugin(ABC):
    """所有插件的基类"""

    @property
    @abstractmethod
    def name(self) -> str:
        """插件唯一标识"""
        ...

    @property
    def version(self) -> str:
        """插件版本，默认 '1.0.0'"""
        return "1.0.0"

    @property
    def supported_events(self) -> List[str]:
        """本插件订阅的事件类型列表。

        返回空列表表示不订阅任何领域事件
        （例如纯拉模式的 EventSource 插件）。
        """
        return []

    @abstractmethod
    def activate(self, config: Dict[str, Any]) -> None:
        """激活插件，传入配置字典。

        PluginManager 在注册后调用此方法。
        插件应在此完成资源初始化（数据库连接、文件打开等）。
        """
        ...

    @abstractmethod
    def deactivate(self) -> None:
        """停用插件，释放资源。

        PluginManager 在卸载前调用此方法。
        插件应在此关闭连接、刷盘缓冲区、停止后台线程。
        """
        ...

    @abstractmethod
    def on_event(self, event: DomainEvent) -> Optional[List[DomainEvent]]:
        """处理领域事件。

        返回 None 或空列表表示不产生新事件。
        返回 DomainEvent 列表则这些事件将被 PluginManager
        继续分发给其他订阅者（事件链）。
        """
        ...
