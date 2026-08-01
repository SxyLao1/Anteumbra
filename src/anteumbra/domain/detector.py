# -*- coding: utf-8 -*-
"""
v1.9.0: Detector 抽象接口

检测器插件契约。所有检测引擎（YARA、静态特征、解码器、
日志启发式、内存马扫描等）都实现此接口。
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from anteumbra.domain.entities import ScanResult  # noqa: F401 - compatibility re-export


@dataclass
class ScanRequest:
    """扫描请求"""
    file_path: Path
    mime_type: Optional[str] = None
    file_size: int = 0
    context: dict = field(default_factory=dict)  # 额外上下文（来源IP等）



class Detector(ABC):
    """检测器抽象接口"""

    @property
    @abstractmethod
    def name(self) -> str:
        """检测器名称，如 'yara', 'static', 'decoder', 'log_heuristic'"""
        ...

    @property
    def priority(self) -> int:
        """检测优先级，数字越小越先执行。默认 50"""
        return 50

    @abstractmethod
    def scan(self, request: ScanRequest) -> Optional[ScanResult]:
        """对单个文件执行检测。

        返回 None 表示未检出（clean）。
        返回 ScanResult 表示检出可疑（is_suspicious=True）或需进一步分析。
        """
        ...

    def is_available(self) -> bool:
        """检测器是否可用（依赖是否安装等）"""
        return True
