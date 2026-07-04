# -*- coding: utf-8 -*-
"""
@Time: 1/5/2026 3:25 PM
@Auth: SxyLao1
@File: logger_factory.py
@IDE: PyCharm
@Motto: HACK THE REAL
v1.7.3-Final-Patch7：修复符号配置访问，重构三重加载策略逻辑
"""
import logging
import os
import sys
from pathlib import Path
from logging.handlers import RotatingFileHandler
from typing import Optional
from anteumbra.infrastructure.config.registry import ConfigRegistry
from anteumbra.infrastructure.utils.path_utils import normalize_path


def _is_tool_mode() -> bool:
    """检测是否为工具脚本模式"""
    return os.environ.get("ANTEUMBRA_TOOL_MODE", "false") == "true"


def log_with_symbol(
        symbol_key: str,
        level: str,
        message: str,
        logger: Optional[logging.Logger] = None
):
    """
    v1.7.3-Patch7：重构三重加载策略，确保符号配置正确加载

    加载优先级：
    1. ConfigRegistry单例（主应用，带状态污染自动修复）
    2. 直接加载config.toml（工具脚本）
    3. 硬编码fallback（确保不崩溃）
    """
    # ============================================================================
    # 策略1：ConfigRegistry单例（增强版）
    # ============================================================================
    prefix = _load_from_registry(symbol_key)

    # ============================================================================
    # 策略2：直接加载config.toml（工具脚本专用）
    # ============================================================================
    if prefix.startswith("[UNKNOWN]") and _is_tool_mode():
        prefix = _load_directly(symbol_key)

    # ============================================================================
    # 策略3：硬编码fallback（最后防线）
    # ============================================================================
    if prefix.startswith("[UNKNOWN]"):
        prefix = _load_fallback(symbol_key)

    # ============================================================================
    # 输出日志
    # ============================================================================
    if logger is None:
        logger = logging.getLogger("monitor.default")

    try:
        level_method = getattr(logger, level.lower())
        level_method(f"{prefix} {message}")
    except AttributeError:
        logger.error(f"{prefix} [INVALID_LEVEL:{level}] {message}")


def _load_from_registry(symbol_key: str) -> str:
    """从ConfigRegistry单例加载符号（带自动修复）"""
    try:
        # ============================================================================
        # 核心修复：确保ConfigRegistry真正就绪
        # ============================================================================
        # 检查1：实例存在
        if ConfigRegistry._instance is None:
            raise RuntimeError("ConfigRegistry._instance 为 None")

        # 检查2：已初始化标记
        if not ConfigRegistry._initialized:
            raise RuntimeError("ConfigRegistry._initialized = False")

        # 检查3：配置对象存在
        if ConfigRegistry._config is None:
            raise RuntimeError("ConfigRegistry._config 为 None")

        # 检查4：symbols段存在
        if "logging" not in ConfigRegistry._config or "symbols" not in ConfigRegistry._config["logging"]:
            raise RuntimeError("ConfigRegistry._config 结构不完整")

        symbols_cfg = ConfigRegistry._config["logging"]["symbols"]

        if symbol_key in symbols_cfg:
            return symbols_cfg[symbol_key]
        else:
            # 符号不存在，记录调试信息
            if _is_tool_mode():
                available = list(symbols_cfg.keys())
                print(f"[CONFIG REGISTRY] 符号 '{symbol_key}' 不存在", file=sys.stderr)
                print(f"[CONFIG REGISTRY] 可用符号: {available[:10]}", file=sys.stderr)
            return f"[UNKNOWN][{symbol_key}]"

    except Exception as e:
        # 仅在工具模式打印调试信息（避免生产环境噪音）
        if _is_tool_mode() or os.environ.get("ANTEUMBRA_DEBUG") == "true":
            print(f"[CONFIG REGISTRY] 加载失败: {e}", file=sys.stderr)
        return f"[UNKNOWN][{symbol_key}]"

def _load_directly(symbol_key: str) -> str:
    """直接加载config.toml（工具脚本模式）"""
    try:
        config_file = normalize_path("config.toml")
        if not config_file.exists():
            print(f"[CONFIG DIRECT] config.toml不存在: {config_file}", file=sys.stderr)
            return f"[UNKNOWN][{symbol_key}]"

        from config.loader import load_toml_config
        config = load_toml_config(str(config_file))

        symbols_cfg = config.get("logging", {}).get("symbols", {})
        if symbol_key in symbols_cfg:
            print(f"[CONFIG DIRECT] ✓ 直接加载: {symbol_key} = {symbols_cfg[symbol_key]}", file=sys.stderr)
            return symbols_cfg[symbol_key]
        else:
            print(f"[CONFIG DIRECT] 符号 '{symbol_key}' 不存在", file=sys.stderr)
            return f"[UNKNOWN][{symbol_key}]"

    except Exception as e:
        print(f"[CONFIG DIRECT] 加载失败: {e}", file=sys.stderr)
        return f"[UNKNOWN][{symbol_key}]"


def _load_fallback(symbol_key: str) -> str:
    """硬编码fallback（内置常见符号）"""
    print(f"[CONFIG FALLBACK] ⚠ 使用硬编码符号: {symbol_key}", file=sys.stderr)

    # 内置常见符号映射（与config.toml保持一致）
    fallback_symbols = {
        # 成功类
        "success": "[MONITOR][START][SUCCESS]",
        "critical_start": "[MONITOR][START][CRITICAL]",
        "create_dir": "[MONITOR][DIR][CREATE]",
        "create_file": "[MONITOR][FILE][CREATE]",
        "scan_hit": "[SCAN][FILE][HIT]",
        "scan_safe": "[SCAN][FILE][SAFE]",

        # 跳过类
        "skip_duplicate": "[MONITOR][SKIP][DUPLICATE]",
        "skip_exclude": "[MONITOR][SKIP][EXCLUDE]",
        "skip_size": "[MONITOR][SKIP][SIZE_LIMIT]",

        # 警告类
        "warning_config_reload": "[CONFIG][RELOAD][WARNING]",
        "warning_wal_fail": "[REGISTRY][WAL][WARNING]",
        "notice_yara_skip": "[SCAN][YARA][NOTICE]",

        # 错误类
        "error_notifier_email": "[NOTIFIER][EMAIL][ERROR]",
        "error_scan_fail": "[SCAN][CHAIN][ERROR]",
        "error_registry_save": "[REGISTRY][SAVE][ERROR]",

        # 严重类
        "critical_alert_apt": "[ALERT][APT][CRITICAL]",
        "critical_alert_high": "[ALERT][HIGH_FREQ][CRITICAL]",
        "critical_system_start": "[SYSTEM][START][CRITICAL]",
    }

    return fallback_symbols.get(symbol_key, f"[UNKNOWN][{symbol_key}]")


def get_logger(site_name: str) -> logging.Logger:
    """获取监控logger（修正命名空间为monitor.*）"""
    config = ConfigRegistry.get_raw_config()
    filesizes_cfg = config.get("filesizes", {})
    paths_cfg = config.get("paths", {})

    log_base_dir = normalize_path(paths_cfg.get("log_base_dir", "logs"))
    log_dir = log_base_dir / site_name
    log_dir.mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger(f"monitor.{site_name}")
    logger.setLevel(logging.DEBUG)

    if not logger.handlers:
        max_mb = filesizes_cfg.get("log_rotation_size_mb", 100)
        max_bytes = max_mb * 1024 * 1024
        backup_count = filesizes_cfg.get("log_backup_count", 5)

        file_handler = RotatingFileHandler(
            log_dir / "monitor.log",
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding="utf-8"
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(logging.Formatter(
            '[%(asctime)s] %(levelname)s - %(message)s'
        ))
        logger.addHandler(file_handler)

        console = logging.StreamHandler()
        console.setLevel(logging.WARNING if _is_tool_mode() else logging.INFO)
        console.setFormatter(logging.Formatter('%(message)s'))
        logger.addHandler(console)

    logger.propagate = False
    return logger


def get_access_logger() -> logging.Logger:
    """Access Log - HTTP访问日志"""
    if _is_tool_mode():
        logger = logging.getLogger("access")
        logger.setLevel(logging.INFO)
        logger.propagate = False
        logger.handlers.clear()
        return logger

    config = ConfigRegistry.get_raw_config()
    logging_cfg = config.get("logging", {})
    flask_cfg = logging_cfg.get("flask", {})

    flask_log_path = flask_cfg.get("flask_log_path", "logs/Anteumbra/access.log")
    log_file = normalize_path(flask_log_path)
    log_file.parent.mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger("access")
    logger.setLevel(logging.INFO)
    logger.propagate = False

    logger.handlers.clear()

    file_handler = RotatingFileHandler(
        log_file,
        maxBytes=10 * 1024 * 1024,
        backupCount=5,
        encoding="utf-8"
    )
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(logging.Formatter('%(message)s'))
    logger.addHandler(file_handler)

    return logger


def get_flask_runtime_logger() -> logging.Logger:
    """Flask运行时日志"""
    if _is_tool_mode():
        logger = logging.getLogger("flask.runtime")
        logger.setLevel(logging.ERROR)
        logger.propagate = False
        logger.handlers.clear()
        return logger

    config = ConfigRegistry.get_raw_config()
    filesizes_cfg = config.get("filesizes", {})

    log_dir = normalize_path("logs/Anteumbra")
    log_dir.mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger("flask.runtime")
    logger.setLevel(logging.DEBUG)

    if not logger.handlers:
        max_mb = filesizes_cfg.get("log_rotation_size_mb", 100)
        max_bytes = max_mb * 1024 * 1024
        backup_count = filesizes_cfg.get("log_backup_count", 5)

        file_handler = RotatingFileHandler(
            log_dir / "flask_runtime.log",
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding="utf-8"
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(logging.Formatter(
            '[%(asctime)s] %(levelname)s - [%(name)s] %(message)s'
        ))
        logger.addHandler(file_handler)

        console = logging.StreamHandler()
        console.setLevel(logging.INFO)
        console.setFormatter(logging.Formatter('[FLASK] %(message)s'))
        logger.addHandler(console)

    logger.propagate = False
    return logger


def get_system_logger() -> logging.Logger:
    """系统级日志"""
    if _is_tool_mode():
        logger = logging.getLogger("system")
        logger.setLevel(logging.ERROR)
        logger.propagate = False
        logger.handlers.clear()
        return logger

    log_dir = normalize_path("logs/Anteumbra")
    log_dir.mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger("system")
    logger.setLevel(logging.INFO)

    if not logger.handlers:
        file_handler = RotatingFileHandler(
            log_dir / "system.log",
            maxBytes=100 * 1024 * 1024,
            backupCount=10,
            encoding="utf-8"
        )
        file_handler.setLevel(logging.INFO)
        file_handler.setFormatter(logging.Formatter(
            '[%(asctime)s] %(levelname)s - %(message)s'
        ))
        logger.addHandler(file_handler)

        console = logging.StreamHandler()
        console.setLevel(logging.CRITICAL)
        console.setFormatter(logging.Formatter('%(message)s'))
        logger.addHandler(console)

    logger.propagate = False
    return logger


def silence_werkzeug():
    """静默werkzeug横幅"""
    import flask.cli
    flask.cli.show_server_banner = lambda *args, **kwargs: None

    werkzeug_logger = logging.getLogger('werkzeug')
    werkzeug_logger.handlers.clear()
    werkzeug_logger.propagate = True
    werkzeug_logger.setLevel(logging.INFO)


__all__ = ['log_with_symbol', 'get_logger', 'get_access_logger', 'get_flask_runtime_logger', 'get_system_logger',
           'silence_werkzeug']