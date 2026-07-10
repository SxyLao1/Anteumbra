import sys
import os

# Ensure project root is in path when running standalone
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# -*- coding: utf-8 -*-
"""
@Time: 1/18/2026 3:26 PM
@Auth: SxyLao1
@File: config_watcher_logger.py
@IDE: PyCharm
@Motto: HACK THE REAL
配置热加载历史持久化工具（库模块，不设置TOOL_MODE）
"""
import json
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any
from anteumbra.infrastructure.utils.path_utils import normalize_path


class ConfigWatcherLogger:
    """配置热加载历史持久化"""

    def __init__(self, history_file: Path = None):
        if history_file is None:
            self.history_file = normalize_path("data/config_history.json")
        else:
            self.history_file = normalize_path(history_file)

        self.history_file.parent.mkdir(parents=True, exist_ok=True)

        # 如果文件不存在，创建空历史记录
        if not self.history_file.exists():
            self.history_file.write_text(
                json.dumps({"history": []}, indent=2),
                encoding='utf-8'
            )

    def log_reload(self, config_snapshot: Dict[str, Any], changed_keys: List[str], reload_duration_ms: float):
        """记录配置热加载事件（不含敏感信息）"""
        try:
            # 加载现有历史
            try:
                data = json.loads(self.history_file.read_text(encoding='utf-8'))
            except:
                data = {"history": []}

            # 创建新记录（商业级字段）
            record = {
                "timestamp": datetime.now().isoformat(),
                "timestamp_display": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                "changed_keys": changed_keys,
                "duration_ms": round(reload_duration_ms, 2),
                "config_summary": {
                    "websites_count": len(config_snapshot.get("website", [])),
                    "notifier_enabled": config_snapshot.get("notifier", {}).get("enabled", False),
                    "yara_rules_count": self._count_yara_rules(),
                    "registry_async_enabled": config_snapshot.get("registry", {}).get("async_save_enabled", False)
                },
                "user_triggered": False
            }

            # 添加到历史（保留最近50条）
            data["history"].insert(0, record)
            data["history"] = data["history"][:50]

            # 持久化到磁盘（原子写入）
            temp_file = self.history_file.with_suffix('.tmp')
            temp_file.write_text(json.dumps(data, indent=2), encoding='utf-8')
            temp_file.replace(self.history_file)

            return True
        except Exception as e:
            print(f"[CONFIG_HISTORY] 记录失败: {e}")
            return False

    def get_history(self, limit: int = 10) -> List[Dict[str, Any]]:
        """获取最近的热加载历史"""
        try:
            data = json.loads(self.history_file.read_text(encoding='utf-8'))
            return data.get("history", [])[:limit]
        except Exception as e:
            print(f"[CONFIG_HISTORY] 读取失败: {e}")
            return []

    def _count_yara_rules(self) -> int:
        """统计当前YARA规则文件数量"""
        try:
            rules_dir = normalize_path("rules/webshell")
            return len(list(rules_dir.glob("*.yar")))
        except:
            return 0

    def clear_history(self):
        """清空历史记录"""
        try:
            self.history_file.write_text(
                json.dumps({"history": []}, indent=2),
                encoding='utf-8'
            )
            return True
        except Exception as e:
            print(f"[CONFIG_HISTORY] 清空失败: {e}")
            return False


# 全局实例
_watcher_logger = None


def get_config_watcher_logger() -> ConfigWatcherLogger:
    """获取配置历史记录器单例"""
    global _watcher_logger
    if _watcher_logger is None:
        _watcher_logger = ConfigWatcherLogger()
    return _watcher_logger
