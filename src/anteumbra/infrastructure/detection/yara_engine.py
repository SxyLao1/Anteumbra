# -*- coding: utf-8 -*-
"""
@Time: 1/6/2026 1:44 PM
@Auth: SxyLao1
@File: yara_engine.py
@IDE: PyCharm
@Motto: HACK THE REAL
v1.7.0重构：清理遗漏的硬编码
"""
import os
from datetime import datetime

import yara
import logging
from pathlib import Path
from typing import List, Dict, Optional, Any, Tuple
from dataclasses import dataclass

from anteumbra.infrastructure.config.registry import ConfigRegistry
from anteumbra.infrastructure.utils.logger_factory import log_with_symbol
from anteumbra.infrastructure.utils.path_utils import normalize_path


@dataclass
class YaraMatch:
    rule_name: str
    namespace: str
    meta: Dict[str, str]
    strings: List[Dict]
    severity: str  # low/medium/high/critical


class YaraEngine:
    """YARA规则引擎封装"""

    def __init__(self, rules_path: Path, logger: logging.Logger):
        self.rules_path = normalize_path(rules_path).resolve()
        self.logger = logger
        self.compiled_rules: Optional[yara.Rules] = None
        self._load_rules()

    def _load_rules(self):
        """加载并编译YARA规则（精简日志）"""
        try:

            # 释放旧规则对象（防止内存泄漏）
            if self.compiled_rules is not None:
                old_rules = self.compiled_rules
                self.compiled_rules = None
                del old_rules  # 删除Python引用

                # 强制GC回收（关键：触发C层内存释放）
                import gc
                gc.collect()
                self.logger.debug("[YARA][GC] 已触发垃圾回收")

            # 单个文件预编译（不输出详细日志）
            valid_rule_files = {}
            total_files = 0

            for yar_file in self.rules_path.glob("*.yar"):
                total_files += 1
                try:
                    yara.compile(filepath=str(yar_file))
                    valid_rule_files[yar_file.stem] = str(yar_file)
                except Exception as e:
                    self.logger.warning(f"[YARA][SKIP] 规则文件损坏: {yar_file.name} - {e}")
                    continue

            if not valid_rule_files:

                self.logger.warning(f"[YARA] 未找到有效规则文件（共扫描 {total_files} 个）")
                self.compiled_rules = None
                return

            # 编译所有有效规则（只输出汇总）
            log_with_symbol("yara_list", "debug", f"正在编译 {len(valid_rule_files)}/{total_files} 个规则文件...", self.logger)
            self.compiled_rules = yara.compile(filepaths=valid_rule_files)

            # 统计规则数
            rule_count = sum(1 for _ in self.compiled_rules)
            log_with_symbol("yara_list", "debug", f"加载成功！规则总数: {rule_count} | 跳过: {total_files - len(valid_rule_files)} 个损坏文件", self.logger)

        except Exception as e:
            log_with_symbol("yara_error", "error", f"编译失败: {e}", self.logger)
            self.compiled_rules = None

    def scan(self, file_path: Path) -> List[YaraMatch]:
        """
        扫描文件并返回匹配结果
        v1.7.9-fix: 改用内存扫描(data=)替代filepath=，解决Windows中文路径YARA C库无法打开的问题
        """
        if self.compiled_rules is None:
            self.logger.warning(f"[YARA] 规则未加载，跳过扫描: {file_path.name}")
            return []

        if not file_path.exists():
            self.logger.warning(f"[YARA] 文件不存在: {file_path}")
            return []

        # v1.7.0重构：从配置读取大小限制
        config = ConfigRegistry.get_raw_config()
        filesizes_cfg = config.get("filesizes", {})
        max_size_mb = filesizes_cfg.get("max_scan_file_size_mb", 10)

        file_size = file_path.stat().st_size
        if file_size > max_size_mb * 1024 * 1024:
            self.logger.warning(f"[YARA] 文件过大，跳过: {file_path.name}")
            return []

        try:
            # v1.7.9-fix: 读取文件内容到内存，避免中文/特殊字符路径导致YARA C库报错
            # 参考: https://github.com/VirusTotal/yara-python/issues/48
            with open(file_path, 'rb') as f:
                file_data = f.read()
            matches = self.compiled_rules.match(data=file_data)

            if not matches:
                self.logger.debug(f"[YARA][SAFE] {file_path.name}")
                return []

            self.logger.info(f"[YARA][MATCH] {file_path.name} 命中 {len(matches)} 条规则")

            results = []
            for match in matches:
                # 提取元数据（保持不变）
                meta = match.meta if hasattr(match, 'meta') else {}
                severity = meta.get('severity', 'medium')

                results.append(YaraMatch(
                    rule_name=match.rule,
                    namespace=match.namespace,
                    meta=meta,
                    strings=[],  # 简化处理
                    severity=severity
                ))

            # 按严重程度排序（保持不变）
            severity_order = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
            results.sort(key=lambda x: severity_order.get(x.severity, 0), reverse=True)

            return results

        except Exception as e:
            self.logger.error(f"[YARA][SCAN] 扫描失败 {file_path}: {e}", exc_info=True)
            return []

    def get_rule_stats(self) -> Dict[str, int]:
        """统计各语言规则数量"""
        if not self.compiled_rules:
            return {}

        stats = {}
        # 遍历规则对象并手动分类
        try:
            for rule in self.compiled_rules:
                rule_name = rule.identifier if hasattr(rule, 'identifier') else str(rule)

                # 根据规则名前缀分类（匹配常见命名约定）
                if rule_name.startswith('PHP') or 'php' in rule_name.lower():
                    stats['php'] = stats.get('php', 0) + 1
                elif rule_name.startswith('ASP') or 'asp' in rule_name.lower():
                    stats['asp'] = stats.get('asp', 0) + 1
                elif rule_name.startswith('JSP') or 'jsp' in rule_name.lower():
                    stats['jsp'] = stats.get('jsp', 0) + 1
                elif rule_name.startswith('Custom_'):
                    stats['custom'] = stats.get('custom', 0) + 1
                else:
                    stats['other'] = stats.get('other', 0) + 1
        except Exception as e:
            self.logger.warning(f"[YARA] 统计规则时出错: {e}")
            return {"unknown": len(list(self.compiled_rules))}

        return stats

    def get_rule_files(self) -> List[Dict[str, Any]]:
        """获取规则文件列表（供蓝图调用）"""
        if not self.rules_path.exists():
            return []

        files = []
        for yar_file in self.rules_path.glob("*.yar"):
            try:
                stats = yar_file.stat()
                files.append({
                    "filename": yar_file.name,
                    "size": stats.st_size,
                    "modified": datetime.fromtimestamp(stats.st_mtime).isoformat()
                })
            except Exception:
                continue
        return files

    def validate_rule_string(self, rule_content: str) -> Tuple[bool, Optional[str]]:
        """验证规则字符串语法"""
        try:
            yara.compile(source=rule_content)
            return True, None
        except Exception as e:
            return False, str(e)


# 全局YARA引擎实例
_yara_engine: Optional[YaraEngine] = None

def get_yara_engine(logger: logging.Logger = None) -> YaraEngine:
    """获取YARA引擎单例（延迟初始化）"""
    global _yara_engine
    if logger is None:
        logger = logging.getLogger("anteumbra.yara_engine")
        if not logger.handlers:
            logger.setLevel(logging.INFO)
            handler = logging.StreamHandler()
            handler.setFormatter(logging.Formatter('[%(asctime)s] [YARA] %(message)s'))
            logger.addHandler(handler)
    if _yara_engine is None:
        # v1.7.0修复：确保ConfigRegistry已导入并初始化
        try:
            from anteumbra.infrastructure.config.registry import ConfigRegistry
            ConfigRegistry.initialize()
        except RuntimeError:
            pass

        config = ConfigRegistry.get_raw_config()
        yara_cfg = config.get("scanner", {}).get("yara", {})

        if yara_cfg.get("enabled", False):
            # v1.7.0重构：从配置读取规则路径
            paths_cfg = config.get("paths", {})
            rules_path = normalize_path(
                yara_cfg.get("rules_path") or
                paths_cfg.get("yara_rules_path", "rules/webshell")
            )
            _yara_engine = YaraEngine(rules_path, logger)
        else:
            # 返回空引擎（避免None检查）
            class DummyEngine:
                """v1.0.5: Explicit methods replace __getattr__ (Kimi P2-5)."""
                compiled_rules = None

                def scan(self, path): return []

                def get_rule_stats(self): return {}

                def match(self, data=None, filepath=None): return []

            _yara_engine = DummyEngine()
            logger.warning("[YARA] 引擎未启用，返回空引擎")

    return _yara_engine
