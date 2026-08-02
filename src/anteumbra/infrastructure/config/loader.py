# -*- coding: utf-8 -*-
"""
@Time: 1/3/2026 8:48 PM
@Auth: SxyLao1
@File: loader.py
@IDE: PyCharm
@Motto: HACK THE REAL
v1.7.8-Patch1：12-Factor 配置模式 — 敏感值从 .env / 环境变量读取
"""

import logging
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict

logger = logging.getLogger(__name__)


def _resolve_env_value(value: str) -> str:
    """
    解析字符串中的环境变量占位符。

    支持语法：
        ${VAR}              → 读取环境变量 VAR，不存在则报错
        ${VAR:-default}     → 读取环境变量 VAR，不存在则使用默认值
        ${VAR:?error}       → 读取环境变量 VAR，不存在则抛出异常

    示例：
        secret_key = "${ANTEUMBRA_SECRET_KEY:-YOUR_SECRET_KEY_HERE}"
        → 如果环境变量 ANTEUMBRA_SECRET_KEY 存在，用它的值
        → 如果不存在，保留 "YOUR_SECRET_KEY_HERE"
    """
    if not isinstance(value, str):
        return value

    # 匹配 ${VAR} 或 ${VAR:-default} 或 ${VAR:?error}
    pattern = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::([\-?])([^}]*))?\}")

    def replacer(match):
        var_name = match.group(1)
        operator = match.group(2)  # '-' 或 '?' 或 None
        default_or_error = match.group(3)  # 默认值或错误信息

        env_val = os.environ.get(var_name)

        if env_val is not None:
            return env_val

        # 环境变量不存在
        if operator == "-":
            # ${VAR:-default} → 用默认值
            return default_or_error if default_or_error is not None else ""
        elif operator == "?":
            # ${VAR:?error} → 报错
            msg = (
                default_or_error
                if default_or_error
                else f"Environment variable {var_name} is required"
            )
            raise RuntimeError(f"[CONFIG] {msg}")
        else:
            # ${VAR} → 无默认值，保留原样（防止意外空值）
            return match.group(0)

    return pattern.sub(replacer, value)


def _deep_resolve_env(obj: Any) -> Any:
    """递归遍历 dict/list，解析所有字符串中的环境变量占位符。"""
    if isinstance(obj, dict):
        return {k: _deep_resolve_env(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [_deep_resolve_env(item) for item in obj]
    elif isinstance(obj, str):
        return _resolve_env_value(obj)
    else:
        return obj


def load_toml_config(config_path: str = "config.toml") -> Dict[str, Any]:
    """
    加载 TOML 配置文件，并自动从 .env / 环境变量解析敏感值。

    设计原则：
    1. 先加载 TOML 文件（所有字段结构）
    2. 加载 .env 文件（如果有的话），注入到 os.environ
    3. 递归解析所有 ${VAR:-default} 占位符
    4. 返回最终配置（敏感值已被环境变量覆盖）
    """
    # 计算绝对路径
    config_file = Path(config_path).resolve()

    if not config_file.exists():
        # v1.0.9: 优先 CWD，其次全局安装注册表，最后包所在源码树
        cwd_config = Path.cwd() / "config.toml"
        if cwd_config.exists():
            config_file = cwd_config
        else:
            try:
                from anteumbra.infrastructure.config.install_registry import get_install_info

                info = get_install_info()
                if info:
                    reg_config = Path(info["install_path"]) / "config.toml"
                    if reg_config.exists():
                        config_file = reg_config
            except Exception:
                logger.debug(
                    "Failed to discover config from the installation registry",
                    exc_info=True,
                )
        if not config_file.exists():
            import anteumbra as _pkg

            pkg_dir = Path(_pkg.__file__).resolve().parent
            dev_config = pkg_dir.parent.parent / "config.toml"
            if dev_config.exists():
                config_file = dev_config

        if not config_file.exists():
            raise FileNotFoundError(
                "[CONFIG FATAL] 配置文件不存在: "
                f"尝试路径1={Path(config_path).resolve()}, "
                f"尝试路径2={config_file}, "
                f"当前工作目录={Path.cwd()}"
            )

    # 加载 .env 文件（如果存在）
    project_root = config_file.parent
    dotenv_path = project_root / ".env"
    if dotenv_path.exists():
        try:
            from dotenv import load_dotenv

            load_dotenv(dotenv_path, override=True)
        except ImportError:
            # 如果 python-dotenv 没安装，跳过（但会打印警告）
            logger.warning(
                "[CONFIG WARNING] .env file exists but python-dotenv is not installed, skipping env var loading"
            )

    try:
        # 读取并解析 TOML
        if sys.version_info >= (3, 11):
            import tomllib

            with open(config_file, "rb") as f:
                config = tomllib.load(f)
        else:
            import tomli

            with open(config_file, "rb") as f:
                config = tomli.load(f)

        if not config:
            raise ValueError("TOML解析返回空配置")

        # 解析环境变量占位符
        config = _deep_resolve_env(config)

        return config

    except Exception as e:
        logger.error("[CONFIG FATAL] TOML parse failed: %s", config_file)
        logger.error("Error type: %s", type(e).__name__)
        logger.error("Error message: %s", str(e))
        raise


# API 兼容别名 (v1.7.8 CI/CD 测试兼容)
load_config = load_toml_config
