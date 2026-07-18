# -*- coding: utf-8 -*-
"""
@Time: 1/3/2026 9:53 PM
@Auth: SxyLao1
@File: scanner.py
@IDE: PyCharm
@Motto: HACK THE REAL
v1.7.0重构：从配置读取规则路径和文件大小限制
"""
import re
import socket
import sys
import logging
import time
from pathlib import Path
from abc import ABC, abstractmethod
from typing import List, Optional, Dict, Any

from anteumbra.infrastructure.config.registry import ConfigRegistry
from anteumbra.infrastructure.utils.logger_factory import log_with_symbol
from anteumbra.infrastructure.monitoring.metrics import get_metrics
from anteumbra.infrastructure.utils.path_utils import normalize_path
from anteumbra.domain.entities import ScanResult

from anteumbra.infrastructure.models import ScanOptions

# 抽象基类
class BaseScanner(ABC):
    """所有扫描引擎的抽象基类"""

    @abstractmethod
    def can_scan(self, file_path: Path) -> bool:
        """判断该引擎是否能处理此文件"""
        pass

    @abstractmethod
    def scan(self, file_path: Path, context: Dict[str, Any]) -> ScanResult:
        """执行扫描，返回结果"""
        pass

    @abstractmethod
    def get_name(self) -> str:
        """返回引擎名称（用于日志和统计）"""
        pass

class StaticScanner(BaseScanner):
    """静态字符串特征扫描器"""

    def __init__(self, patterns: List[str] = None):
        self.patterns = patterns or [
            "eval(", "exec(", "system(", "base64_decode(",
            "file_get_contents(", "passthru(", "shell_exec("
        ]
        self._regexes = [re.compile(re.escape(p), re.IGNORECASE) for p in self.patterns]

    def can_scan(self, file_path: Path) -> bool:
        try:
            # v1.7.0重构：从配置读取大小限制
            config = ConfigRegistry.get_raw_config()
            filesizes_cfg = config.get("filesizes", {})
            max_size_mb = filesizes_cfg.get("max_scan_file_size_mb", 5)

            return file_path.stat().st_size < max_size_mb * 1024 * 1024
        except Exception:
            return False

    def scan(self, file_path: Path, context: Dict) -> ScanResult:
        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
            matches = []
            for i, regex in enumerate(self._regexes):
                if regex.search(content):
                    matches.append(self.patterns[i])

            if matches:
                return ScanResult(
                    file_path=file_path,
                    is_suspicious=True,
                    features=matches,
                    score=min(len(matches) * 0.3, 0.95),
                    engine="static"
                )

            return ScanResult(file_path, False, [], engine="static")

        except Exception as e:
            return ScanResult(file_path, False, [], error=str(e), engine="static")

    def get_name(self) -> str:
        return "StaticFeature"

class YaraScanner(BaseScanner):
    """YARA规则扫描器"""

    def __init__(self, rules_path: Path):
        self.rules_path = rules_path
        self._engine = None
        self._logger = None

    def _get_engine(self):
        if self._engine is None:
            from anteumbra.infrastructure.detection.yara_engine import get_yara_engine
            from anteumbra.infrastructure.utils.logger_factory import get_logger
            self._engine = get_yara_engine(get_logger("yara"))
        return self._engine

    def can_scan(self, file_path: Path) -> bool:
        # v1.7.0重构：从配置读取大小限制
        config = ConfigRegistry.get_raw_config()
        filesizes_cfg = config.get("filesizes", {})
        max_size_mb = filesizes_cfg.get("max_scan_file_size_mb", 10)

        # 支持PHP/ASP/JSP，且文件<配置大小
        return (file_path.suffix.lower() in ['.php', '.asp', '.jsp', '.aspx', '.jspx'] and
                file_path.stat().st_size < max_size_mb * 1024 * 1024)

    def scan(self, file_path: Path, context: Dict) -> ScanResult:
        engine = self._get_engine()

        # 如果引擎未初始化，回退到静态扫描
        if hasattr(engine, 'scan') and engine.compiled_rules is None:
            return ScanResult(file_path, False, [], engine="yara", error="YARA规则未加载")

        matches = engine.scan(file_path)

        if matches:
            # 提取最严重的一条规则
            worst_match = matches[0]
            severity = worst_match.severity

            # 动态计算分数
            score_map = {'critical': 0.95, 'high': 0.85, 'medium': 0.7, 'low': 0.5}
            score = score_map.get(severity, 0.6)

            features = [f"YARA:{m.rule_name}({m.severity})" for m in matches[:3]]  # 取前3个

            return ScanResult(
                file_path=file_path,
                is_suspicious=True,
                features=features,
                score=score,
                engine="yara",
                analysis_data={
                    "yara_matches": len(matches),
                    "top_rule": worst_match.rule_name,
                    "severity": severity,
                    "rule_namespace": worst_match.namespace
                }
            )

        return ScanResult(file_path, False, [], engine="yara")

    def get_name(self) -> str:
        return "YaraEngine"

# v1.6 API扫描器预留
class ApiScanner(BaseScanner):
    """第三方API扫描器（v1.6实现）"""

    def __init__(self, provider: str, api_key: str, endpoint: str):
        self.provider = provider
        self.api_key = api_key
        self.endpoint = endpoint
        self._session = None

    def can_scan(self, file_path: Path) -> bool:
        try:
            return file_path.stat().st_size > 10 * 1024 * 1024
        except Exception:
            return False

    def scan(self, file_path: Path, context: Dict) -> ScanResult:
        return ScanResult(
            file_path=file_path,
            is_suspicious=False,
            features=["API扫描"],
            score=0.0,
            engine="api"
        )

    def get_name(self) -> str:
        return "ApiEngine"

class EmergencyScanner(BaseScanner):
    """应急扫描器：YARA失效时的完整兜底方案"""

    def __init__(self):
        # 高危模式（比原版更精准，减少误报）

        import sys  # 确保类初始化时sys可用

        self.patterns = {
            'php_eval': r'eval\s*\(\s*\$_(POST|Union[GET, REQUEST])\[[^\]]+\]\s*\)',
            'php_system': r'system\s*\(\s*\$_(POST|Union[GET, REQUEST])\[[^\]]+\]\s*\)',
            'php_exec': r'exec\s*\(\s*\$_(POST|Union[GET, REQUEST])\[[^\]]+\]\s*\)',
            'php_base64': r'eval\s*\(\s*base64_decode\s*\(\s*\$_(POST|Union[GET, REQUEST])',
        }
        self.logger = logging.getLogger("emergency_scanner")

    def get_name(self) -> str:
        """返回引擎名称"""
        return "EmergencyScanner"

    def can_scan(self, file_path: Path) -> bool:
        """检查文件是否可扫描（安全模式，无logger依赖）"""
        try:
            # 检查扩展名
            if file_path.suffix.lower() not in ['.php', '.asp', '.jsp', '.aspx', '.jspx']:
                return False

            # v1.7.0重构：从配置读取大小限制
            config = ConfigRegistry.get_raw_config()
            filesizes_cfg = config.get("filesizes", {})
            max_size_mb = filesizes_cfg.get("max_scan_file_size_mb", 5)

            return file_path.stat().st_size <= max_size_mb * 1024 * 1024
        except Exception:
            return False

    def scan(self, file_path: Path, context: Dict) -> ScanResult:
        """完整扫描逻辑（复刻quick_scan的健壮性）"""

        import sys # 局部导入，绕过解释器缓存问题

        logger = context.get("logger")
        if not logger:
            logger = logging.getLogger("emergency_scanner")

        metrics = get_metrics()  # 获取全局 metrics 实例

        result = ScanResult(
            file_path=file_path,
            is_suspicious=False,
            features=[],
            engine="emergency"
        )

        try:
            # 文件存在性检查
            if not file_path.exists():
                result.error = "文件不存在"
                logger.debug(f"[SCAN][SKIP][NOT_FOUND] {file_path.name}")
                return result

            # 权限检查（包含VMware绕过检测）
            try:
                stat = file_path.stat()
            except PermissionError:
                logger.critical(f"[SCAN][SUSPICIOUS][PERM] 权限混淆: {file_path}")

                # 基础权限混淆检测
                return ScanResult(
                    file_path=file_path,
                    is_suspicious=True,
                    features=["PERMISSION_CONFUSION"],
                    score=0.85,
                    engine="emergency"
                )

            except Exception as e:
                logger.error(f"[SCAN][ERROR] 无法获取文件状态 {file_path}: {e}")
                result.error = f"状态错误: {e}"
                return result

            # 文件大小检查
            max_size = context.get("scan_options", {}).max_size_bytes if context.get("scan_options") else 5 * 1024 ** 2
            if stat.st_size > max_size:
                logger.info(f"[SCAN][SKIP][SIZE] {file_path.name} > {max_size} bytes")
                result.error = "文件过大"
                return result

            # 三次重试读取文件
            content = None
            for attempt in range(3):
                try:
                    content = file_path.read_text(encoding='utf-8', errors='ignore')
                    if attempt > 0:
                        logger.info(f"[SCAN][RETRY_SUCCESS] {file_path.name} (第{attempt}次)")
                    break
                except PermissionError:
                    if attempt < 2:
                        logger.warning(f"[SCAN][RETRY] {file_path.name} 100ms后重试...")
                        time.sleep(0.1)
                        continue
                    else:
                        logger.error(f"[SCAN][PERM] 三次重试失败: {file_path}")
                        result.error = "权限拒绝（系统繁忙）"
                        return result
                except Exception as e:
                    logger.error(f"[SCAN][ERROR] 读取失败 {file_path}: {e}")
                    result.error = f"读取失败: {e}"
                    return result

            if content is None:
                result.error = "内容为空"
                return result

            # 正则匹配（精准模式）
            found_features = []
            for name, pattern in self.patterns.items():
                if re.search(pattern, content, re.IGNORECASE):
                    found_features.append(name)

            if found_features:
                result.is_suspicious = True
                result.features = [f"EMERGENCY:{f}" for f in found_features]

                metrics.increment("scan_suspicious")

                logger.info(f"[SCAN][EMERGENCY][HIT] {file_path.name} features: {', '.join(found_features)}")

            return result

        except Exception as e:
            logger.error(f"[SCAN][EMERGENCY][ERROR] {file_path}: {e}", exc_info=True)
            return ScanResult(file_path, False, [], error=str(e), engine="emergency")

# 引擎调度器
class ScannerChain:
    """扫描引擎链：按优先级组合多个引擎"""

    def __init__(self, logger: logging.Logger):
        self.engines = []
        self.logger = logger

    def add_engine(self, engine: BaseScanner, priority: int = 0):
        self.engines.append((priority, engine))
        self.engines.sort(key=lambda x: x[0])

    def scan(self, file_path: Path) -> ScanResult:
        """按优先级链式扫描（统一计数逻辑）"""
        # 无论结果如何，都计入总计
        get_metrics().increment("scan_total")

        for priority, engine in self.engines:
            try:
                if not engine.can_scan(file_path):
                    continue

                result = engine.scan(file_path, {})

                if result.is_suspicious:
                    self.logger.info(f"[SCAN][CHAIN] {engine.get_name()} 命中: {file_path.name}")
                    return result

            except Exception as e:
                self.logger.error(f"[SCAN][{engine.get_name()}] 失败: {e}", exc_info=True)

        # 未命中，返回安全结果
        return ScanResult(file_path, False, [], engine="chain")

# 全局扫描器实例
_scanner_chain: Optional[ScannerChain] = None


def get_scanner_chain(logger: logging.Logger) -> ScannerChain:
    """扫描器链：YARA优先，应急兜底"""
    global _scanner_chain
    if _scanner_chain is None:
        _scanner_chain = ScannerChain(logger)

        # v1.7.0重构：从配置读取YARA设置
        config = ConfigRegistry.get_raw_config()
        scanner_cfg = config.get("scanner", {})
        yara_cfg = scanner_cfg.get("yara", {})

        if yara_cfg.get("enabled", False):
            # 从配置读取规则路径
            paths_cfg = config.get("paths", {})
            rules_path = normalize_path(
                yara_cfg.get("rules_path") or
                paths_cfg.get("yara_rules_path", "rules/webshell")
            )
            yara_scanner = YaraScanner(rules_path)
            _scanner_chain.add_engine(yara_scanner, priority=5)

        # 兜底引擎：EmergencyScanner（低优先级）
        emergency = EmergencyScanner()
        _scanner_chain.add_engine(emergency, priority=20)

    return _scanner_chain

def check_port(host: str, port: int, timeout: int = 3) -> bool:
    """检查端口是否开放"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except Exception as e:
        return False

def quick_scan_yara(file_path: Path, scan_options: ScanOptions, logger: logging.Logger) -> ScanResult:
    """
    v1.7.7-Patch8: 修复指标分裂问题，统一由ScannerChain计数
    """
    configured_extensions = getattr(scan_options, "monitor_extensions", None)
    if configured_extensions:
        monitor_extensions = {
            str(extension).lower() for extension in configured_extensions
        }
    else:
        config = ConfigRegistry.get_raw_config()
        paths_cfg = config.get("paths", {})
        monitor_extensions = {
            str(extension).lower()
            for extension in paths_cfg.get(
                "monitor_extensions", [".php", ".asp", ".jsp", ".aspx", ".jspx"]
            )
        }

    # ===== 1. 后缀过滤 =====
    if file_path.suffix.lower() not in monitor_extensions:
        logger.debug(f"[SCAN][SKIP] 后缀过滤: {file_path.suffix}")
        return ScanResult(
            file_path=file_path,
            is_suspicious=False,
            features=[],
            score=0.0,
            engine="filter"
        )

    # ===== 2. 扫描并统计（统一由ScannerChain处理）=====
    chain = get_scanner_chain(logger)
    result = chain.scan(file_path)

    # ===== 2b. v1.8.3: 如果文件扫描未命中，尝试解码混淆代码后重新扫描 =====
    if not result.is_suspicious:
        try:
            from anteumbra.infrastructure.detection.decoder import WebShellDecoder
            from anteumbra.infrastructure.detection.yara_engine import get_yara_engine
            raw_data = file_path.read_bytes()
            if len(raw_data) < 5 * 1024 * 1024:
                decoded = WebShellDecoder.decode(raw_data)
                content = raw_data.decode('utf-8', errors='replace') + '\n' + decoded
                yara_engine = get_yara_engine(logger)
                if yara_engine.compiled_rules:
                    matches = yara_engine.scan_data(
                        content,
                        source_name=f"{file_path}#decoded",
                    )
                    if matches:
                        features = [f"DECODED:{m.rule_name}" for m in matches]
                        score_map = {
                            'critical': 0.95,
                            'high': 0.85,
                            'medium': 0.7,
                            'low': 0.5,
                        }
                        worst_match = matches[0]
                        result = ScanResult(
                            file_path=file_path, is_suspicious=True,
                            features=features,
                            score=score_map.get(worst_match.severity, 0.6),
                            engine="decoder+yara",
                            analysis_data={
                                "yara_matches": len(matches),
                                "top_rule": worst_match.rule_name,
                                "severity": worst_match.severity,
                                "rule_namespace": worst_match.namespace,
                            },
                        )
                        logger.info(f"[DECODER] Hit after decode: {file_path.name} -> {', '.join(features[:3])}")
        except Exception:
            logger.debug("Decoder pass failed in quick_scan_yara, using original scan result", exc_info=True)

    # ===== 3. 日志记录（v1.7.9: add()移到_do_scan统一管理，避免遗漏）=====
    if result.is_suspicious:
        log_with_symbol("scan_hit", "critical",
                        f"{file_path.name} | 引擎: {result.engine} | 特征: {', '.join(result.features[:3])}", logger)
    else:
        logger.debug(f"[SCAN][SAFE] {file_path.name} | 引擎: {result.engine}")

    return result

__all__ = ["quick_scan_yara", "get_scanner_chain", "EmergencyScanner"]
