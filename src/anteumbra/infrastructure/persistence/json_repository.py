# -*- coding: utf-8 -*-
"""
v1.9.0: JSON 文件仓库实现

从 SuspiciousRegistry / BlockLedger 等现有模块提取通用 JSON 持久化逻辑。
线程安全（threading.Lock），向后兼容现有 data/*.json 文件格式。

v1.9.1 将新增 SqliteRepository，通过相同的 Repository 接口切换。
"""
import json
import logging
import os
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional

from anteumbra.domain import Repository

logger = logging.getLogger(__name__)


class JsonRepository(Repository):
    """基于 JSON 文件的数据仓库"""

    def __init__(self, file_path: Path, key_field: str = "id",
                 auto_save: bool = True):
        """
        Args:
            file_path: JSON 文件路径
            key_field: 记录的主键字段名（默认 'id'）
            auto_save: 每次修改后自动刷盘（默认 True）
        """
        self._file_path = Path(file_path)
        self._key_field = key_field
        self._auto_save = auto_save
        self._lock = threading.Lock()
        self._data: Dict[str, Dict[str, Any]] = {}
        self._load()

    # ── 内部方法 ──────────────────────────────────────────

    def _load(self) -> None:
        """从磁盘加载数据"""
        if not self._file_path.exists():
            logger.info("JsonRepository: %s not found, starting empty", self._file_path)
            self._data = {}
            return
        try:
            with open(self._file_path, "r", encoding="utf-8") as f:
                raw = json.load(f)
            # 支持两种格式: JSON 数组 或 以 key_field 为键的字典
            if isinstance(raw, list):
                self._data = {}
                for item in raw:
                    key = item.get(self._key_field)
                    if key is None:
                        continue
                    self._data[str(key)] = item
            elif isinstance(raw, dict):
                self._data = raw
            else:
                self._data = {}
            logger.info("JsonRepository: loaded %d records from %s",
                        len(self._data), self._file_path)
        except (json.JSONDecodeError, OSError) as e:
            logger.error("JsonRepository: failed to load %s: %s", self._file_path, e)
            self._data = {}

    def _save(self) -> None:
        """刷盘到 JSON 文件（原子写入：先写临时文件再替换）"""
        tmp_path = self._file_path.with_suffix(".tmp")
        try:
            self._file_path.parent.mkdir(parents=True, exist_ok=True)
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(self._data, f, ensure_ascii=False, indent=2, default=str)
            os.replace(tmp_path, self._file_path)  # 原子替换
        except OSError as e:
            logger.error("JsonRepository: failed to save %s: %s", self._file_path, e)

    # ── Repository 接口实现 ───────────────────────────────

    def save(self, record_id: str, data: Dict[str, Any]) -> None:
        """保存或更新一条记录"""
        with self._lock:
            # 确保 key_field 在数据中
            data[self._key_field] = record_id
            self._data[record_id] = data
            if self._auto_save:
                self._save()

    def get(self, record_id: str) -> Optional[Dict[str, Any]]:
        """按 ID 获取单条记录"""
        with self._lock:
            return self._data.get(record_id)

    def list_all(self, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        """分页列出所有记录"""
        with self._lock:
            items = list(self._data.values())
            return items[offset:offset + limit]

    def query(self, filters: Dict[str, Any],
              limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        """条件查询（简单等值匹配）"""
        with self._lock:
            results = []
            for item in self._data.values():
                match = True
                for k, v in filters.items():
                    if item.get(k) != v:
                        match = False
                        break
                if match:
                    results.append(item)
            return results[offset:offset + limit]

    def delete(self, record_id: str) -> bool:
        """删除一条记录"""
        with self._lock:
            if record_id in self._data:
                del self._data[record_id]
                if self._auto_save:
                    self._save()
                return True
            return False

    def count(self, filters: Optional[Dict[str, Any]] = None) -> int:
        """统计记录数"""
        with self._lock:
            if filters is None:
                return len(self._data)
            count = 0
            for item in self._data.values():
                if all(item.get(k) == v for k, v in filters.items()):
                    count += 1
            return count

    def flush(self) -> None:
        """强制刷盘"""
        with self._lock:
            self._save()

    def __len__(self) -> int:
        return self.count()

    def __repr__(self) -> str:
        return f"JsonRepository({self._file_path.name}, {len(self)} records)"
