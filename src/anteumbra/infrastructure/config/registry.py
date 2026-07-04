# -*- coding: utf-8 -*-
"""
@Time: 1/5/2026 1:30 PM
@Auth: SxyLao1
@File: registry.py
@IDE: PyCharm
@Motto: HACK THE REAL
v1.7.3-Final-Patch7：修复ConfigRegistry单例状态污染，确保符号配置可访问
"""
import json
import os
import re
import threading
from pathlib import Path


# v1.7.9: 加载 .env 环境变量（开发环境用，生产环境由 Docker/K8s 注入）
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # 生产环境未安装 python-dotenv 时跳过
from typing import Dict, List, Optional, Any

from anteumbra.infrastructure.config.loader import load_toml_config
from anteumbra.infrastructure.models import Website, ScanOptions
from anteumbra.infrastructure.utils.path_utils import normalize_path


class ConfigRegistry:
    _instance: Optional['ConfigRegistry'] = None
    _config: Optional[Dict] = None
    _websites: Optional[List[Website]] = None
    _lock = threading.RLock()
    _initialized = False
    _logger = None
    _config_path: Optional[Path] = None
    _init_attempts = 0  # v1.7.3-Patch7新增：初始化尝试计数

    @classmethod
    def _get_logger(cls):
        if cls._logger is None:
            import logging
            cls._logger = logging.getLogger("config.registry")
        return cls._logger

    @classmethod
    def initialize(cls, config_path: str = None, force: bool = False):
        """v1.7.3-Patch7：增强初始化，解决单例状态污染"""
        logger = cls._get_logger()

        # 强制重置（解决状态污染）
        if force:
            logger.info("[CONFIG] 收到强制重置指令")
            with cls._lock:
                cls._config = None
                cls._websites = None
                cls._initialized = False
                cls._instance = None
                cls._config_path = None
                cls._init_attempts = 0
            logger.debug("[CONFIG] 状态已清空，准备重新初始化")

        # 快速路径：已初始化且无强制标志
        if cls._initialized and cls._config is not None:
            logger.debug("[CONFIG] 配置已就绪，跳过初始化")
            return

        # 避免重复初始化风暴（限制尝试次数）
        with cls._lock:
            if cls._init_attempts > 3:
                logger.error("[CONFIG] 初始化尝试超过3次，拒绝重试")
                raise RuntimeError("配置初始化失败超过3次，可能存在循环依赖或配置损坏")
            cls._init_attempts += 1

        # 获取配置路径（绝对路径确保一致性）
        if config_path:
            cls._config_path = normalize_path(config_path).resolve()
        elif cls._config_path is None:
            project_root = normalize_path(__file__).resolve().parent.parent.parent.parent.parent  # src/anteumbra/infrastructure/config/ → 5 levels up
            cls._config_path = (project_root / "config.toml").resolve()

        if not cls._config_path.exists():
            raise FileNotFoundError(
                f"[CONFIG FATAL] 配置文件不存在: {cls._config_path.absolute()}"
            )

        try:
            # 获取锁（带超时防止死锁）
            lock_acquired = cls._lock.acquire(timeout=15.0)
            if not lock_acquired:
                raise RuntimeError("获取配置锁超时（15秒）")

            # ============================================================================
            # 核心修复：深度拷贝配置，避免引用污染
            # ============================================================================
            logger.info(f"[CONFIG] 正在加载: {cls._config_path}")

            # 加载原始配置（使用load_toml_config确保兼容性）
            raw_config = load_toml_config(str(cls._config_path))

            # 深度验证配置结构
            if not raw_config or not isinstance(raw_config, dict):
                raise ValueError(f"TOML解析返回无效数据: {type(raw_config)}")

            # 验证symbols配置段（P0级验证）
            if "logging" not in raw_config:
                logger.warning("[CONFIG] [logging]段不存在，将创建空配置")
                raw_config["logging"] = {}

            if "symbols" not in raw_config["logging"]:
                logger.warning("[CONFIG] [logging.symbols]段不存在，将使用默认符号")
                # 提供默认符号确保功能可用
                raw_config["logging"]["symbols"] = {
                    "success": "[MONITOR][DEFAULT][SUCCESS]",
                    "scan_hit": "[MONITOR][DEFAULT][HIT]",
                    "error": "[MONITOR][DEFAULT][ERROR]"
                }

            symbol_count = len(raw_config["logging"]["symbols"])
            logger.info(f"[CONFIG] ✓ 加载symbols配置: {symbol_count}条")

            # 打印前3个符号用于调试（仅非生产环境）
            if os.environ.get("ANTEUMBRA_PRODUCTION") != "true":
                symbols_preview = list(raw_config["logging"]["symbols"].items())[:3]
                logger.debug(f"[CONFIG] symbols预览: {symbols_preview}")

            # 解析网站配置
            websites = cls._parse_websites(raw_config)

            # ============================================================================
            # 核心修复：确保配置正确存储到类变量和实例变量
            # ============================================================================
            # 创建单例实例
            if cls._instance is None:
                cls._instance = ConfigRegistry()
                logger.debug("[CONFIG] 创建ConfigRegistry单例实例")

            # 深度拷贝并存储配置
            import copy
            cls._config = copy.deepcopy(raw_config)
            cls._websites = copy.deepcopy(websites)
            cls._initialized = True

            # 同步到实例变量（双重保险）
            if cls._instance:
                cls._instance._config = copy.deepcopy(raw_config)
                cls._instance._websites = copy.deepcopy(websites)
                cls._instance._initialized = True

            # 重置初始化计数器
            cls._init_attempts = 0

            logger.info(f"[CONFIG] ✓ 配置加载成功，启用网站: {len(websites)}个")

            # 最终验证：确认symbols可访问
            final_check = cls._config.get("logging", {}).get("symbols", {})
            if final_check:
                logger.debug(f"[CONFIG] 最终验证: symbols共{len(final_check)}条")
                # 测试访问一个具体符号
                test_symbol = final_check.get("success")
                if test_symbol:
                    logger.debug(f"[CONFIG] 符号测试: success = {test_symbol}")
            else:
                logger.error("[CONFIG] ✗ 最终验证失败: symbols配置不可用")
                raise RuntimeError("symbols配置存储失败")

        except Exception as e:
            logger.error(f"[CONFIG] 初始化失败: {e}", exc_info=True)
            cls._initialized = False  # 标记为未初始化
            raise
        finally:
            if lock_acquired:
                try:
                    cls._lock.release()
                except RuntimeError:
                    pass

    @classmethod
    def reset(cls):
        """测试专用：安全重置单例状态"""
        logger = cls._get_logger()
        logger.debug("[CONFIG] 收到重置请求")

        lock_acquired = False
        try:
            lock_acquired = cls._lock.acquire(timeout=5.0)
            if not lock_acquired:
                logger.warning("[CONFIG] 重置时获取锁超时，强制重建锁")
                cls._lock = threading.RLock()
                lock_acquired = cls._lock.acquire(timeout=3.0)

            # 执行安全重置
            cls._config = None
            cls._websites = None
            cls._initialized = False
            cls._instance = None
            cls._config_path = None
            cls._init_attempts = 0
            logger.debug("[CONFIG] 状态安全重置完成")

        except Exception as e:
            logger.error(f"[CONFIG] 重置失败: {e}", exc_info=True)
        finally:
            if lock_acquired:
                try:
                    cls._lock.release()
                except RuntimeError:
                    pass

    @classmethod
    def get_raw_config(cls) -> Dict:
        """v1.7.3-Patch7：增强配置访问，自动修复状态污染"""
        # 快速路径：配置已就绪
        if cls._config is not None:
            return cls._config

        # 配置未就绪但已初始化：状态污染，需要修复
        if cls._initialized:
            logger = cls._get_logger()
            logger.error("[CONFIG] 状态污染检测到: _config为None但_initialized=True")
            logger.warning("[CONFIG] 触发自动修复...")
            try:
                cls.initialize(force=True)
                if cls._config is not None:
                    logger.info("[CONFIG] ✓ 自动修复成功")
                    return cls._config
                else:
                    logger.error("[CONFIG] ✗ 自动修复失败")
                    raise RuntimeError("ConfigRegistry自动修复失败，_config仍为None")
            except Exception as e:
                logger.error(f"[CONFIG] 自动修复异常: {e}", exc_info=True)
                raise RuntimeError(f"ConfigRegistry状态污染且无法自动修复: {e}") from e

        # 未初始化：尝试自动初始化
        logger = cls._get_logger()
        if _is_tool_script():
            logger.warning("[CONFIG] 工具脚本模式自动初始化")
            try:
                cls.initialize()
                return cls._config
            except Exception as e:
                raise RuntimeError(f"工具脚本模式下配置自动初始化失败: {e}") from e
        else:
            raise RuntimeError("配置未初始化。请先调用ConfigRegistry.initialize()")

    @classmethod
    def get_websites(cls) -> List[Website]:
        if cls._websites is None:
            raise RuntimeError("配置未初始化")
        return cls._websites

    @classmethod
    def get_enabled_websites(cls) -> List[Website]:
        return [w for w in cls.get_websites() if w.enabled]

    @staticmethod
    def safe_int(value, default=0):
        """Safely convert config value to int, stripping comments if needed."""
        try:
            if isinstance(value, (int, float)):
                return int(value)
            return int(str(value).split('#')[0].strip())
        except Exception:
            return default

    @classmethod
    def _parse_websites(cls, config: Dict) -> List[Website]:
        """解析网站配置"""
        logger = cls._get_logger()
        websites = []

        # 支持多种配置格式（向后兼容）
        site_data = config.get("website")
        if isinstance(site_data, dict):
            if site_data.get("enabled", False):
                site = cls._create_website(site_data)
                if site:
                    websites.append(site)
        elif isinstance(site_data, list):
            for data in site_data:
                if data.get("enabled", False):
                    site = cls._create_website(data)
                    if site:
                        websites.append(site)

        return websites

    @classmethod
    def _create_website(cls, data: Dict) -> Optional[Website]:
        """创建网站对象"""
        logger = cls._get_logger()
        try:
            scan_opts_data = data.get("scan_options", {})
            scan_options = ScanOptions(**scan_opts_data)

            path = data["path"]
            if isinstance(path, str):
                path = normalize_path(path)

            site = Website(
                name=data["name"],
                path=path,
                port=data["port"],
                enabled=data.get("enabled", True),
                scan_options=scan_options
            )
            logger.debug(f"[CONFIG] 创建网站: {site}")
            return site
        except Exception as e:
            logger.error(f"[CONFIG] 创建网站失败 '{data.get('name', '未知')}': {e}")
            return None


def _is_tool_script() -> bool:
    """检测工具脚本模式"""
    return os.environ.get("ANTEUMBRA_TOOL_MODE", "false") == "true"


def _load_json_with_comments(file_path: str) -> Dict[str, Any]:
    """加载带注释的JSON文件"""
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
        content = re.sub(r'(?<!")//.*$', '', content, flags=re.MULTILINE)
        content = re.sub(r'(?<!")#.*$', '', content, flags=re.MULTILINE)
        return json.loads(content)
    # v1.0.9: removed unreachable _resolve_env_vars dead code after return on line 326.
    # The _load_json_with_comments function (never called) had @staticmethod /
    # @classmethod decorators after a return statement — unreachable and broken.

