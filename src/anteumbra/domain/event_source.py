# -*- coding: utf-8 -*-
"""
v1.9.0: EventSource 抽象接口

外部事件源插件契约。所有数据摄入渠道（WAF 轮询、Syslog 接收、
日志文件追踪、文件系统监控）都实现此接口。
"""
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Callable, List


class EventSource(ABC):
    """外部事件源抽象接口"""

    @property
    @abstractmethod
    def name(self) -> str:
        """事件源名称，如 'modsecurity', 'cloudflare', 'nginx_log'"""
        ...

    @abstractmethod
    def start(self) -> None:
        """启动事件源（开始拉取/监听）"""
        ...

    @abstractmethod
    def stop(self) -> None:
        """停止事件源"""
        ...

    @abstractmethod
    def is_running(self) -> bool:
        """事件源是否正在运行"""
        ...

    def set_callback(self, callback: Callable) -> None:
        """设置事件回调函数。

        事件源产生新事件时调用 callback(event)。
        默认实现存储 self._callback，子类可 override。
        """
        self._callback = callback


class PollableEventSource(EventSource):
    """轮询式事件源（WAF API 等）"""

    @abstractmethod
    def poll(self, start_time: datetime, end_time: datetime,
             limit: int = 100) -> List[dict]:
        """拉取指定时间窗口内的事件"""
        ...


class StreamEventSource(EventSource):
    """流式事件源（Syslog、WebSocket 等）"""

    @abstractmethod
    def connect(self) -> bool:
        """建立连接"""
        ...

    @abstractmethod
    def disconnect(self) -> None:
        """断开连接"""
        ...
