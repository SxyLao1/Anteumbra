# -*- coding: utf-8 -*-
"""
v1.9.0: Repository 抽象接口

数据仓库契约。统一 Registry、Quarantine、BlockLedger、
ThreatGraph 等所有持久化层的 CRUD 操作。

v1.9.x 提供 JSON 和 SQLite 两种实现。
v2.0 可扩展 PostgreSQL/MySQL 实现。
"""
from abc import ABC, abstractmethod
from contextlib import contextmanager
from typing import Any, Dict, Iterator, List, Optional


class Repository(ABC):
    """通用数据仓库抽象接口"""

    @abstractmethod
    def save(self, record_id: str, data: Dict[str, Any]) -> None:
        """保存或更新一条记录"""
        ...

    @abstractmethod
    def get(self, record_id: str) -> Optional[Dict[str, Any]]:
        """按 ID 获取单条记录"""
        ...

    @abstractmethod
    def list_all(self, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        """分页列出所有记录"""
        ...

    @abstractmethod
    def query(self, filters: Dict[str, Any],
              limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        """条件查询"""
        ...

    @abstractmethod
    def delete(self, record_id: str) -> bool:
        """删除一条记录，返回是否成功"""
        ...

    @abstractmethod
    def count(self, filters: Optional[Dict[str, Any]] = None) -> int:
        """统计记录数"""
        ...

    @contextmanager
    def transaction(self) -> Iterator[None]:
        """事务上下文管理器（原子写入）。

        默认实现为空操作（无事务支持）。
        子类可 override 实现真实事务。
        """
        yield


class EventRepository(Repository):
    """时序事件专用仓库（WAL 语义）"""

    @abstractmethod
    def append(self, event: Dict[str, Any]) -> None:
        """追加一条事件（只追加，不修改）"""
        ...

    @abstractmethod
    def replay(self, since: Optional[float] = None) -> List[Dict[str, Any]]:
        """重放事件（从指定时间戳起）"""
        ...
