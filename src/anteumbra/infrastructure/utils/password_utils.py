# -*- coding: utf-8 -*-
"""
@Time: 1/19/2026 11:47 PM
@Auth: SxyLao1
@File: password_utils.py
@IDE: PyCharm
@Motto: HACK THE REAL
v1.7.6: 密码操作核心库（Web + CLI 共用）
"""
import logging
import re
from pathlib import Path
from typing import Tuple, Set
from werkzeug.security import generate_password_hash
from anteumbra.infrastructure.config.registry import ConfigRegistry
from anteumbra.infrastructure.utils.path_utils import normalize_path

logger = logging.getLogger(__name__)

# 弱口令字典缓存（全局单例，避免重复I/O）
_WEAK_PASSWORDS_CACHE: Set[str] = set()
_WEAK_PASSWORDS_LOADED = False


def load_weak_passwords() -> Set[str]:
    """
    从 tools/top1000.txt 加载弱口令字典
    仅加载一次，后续从缓存读取
    """
    global _WEAK_PASSWORDS_CACHE, _WEAK_PASSWORDS_LOADED

    if _WEAK_PASSWORDS_LOADED:
        return _WEAK_PASSWORDS_CACHE

    weak_file = normalize_path("tools/top1000.txt")
    if weak_file.exists():
        try:
            content = weak_file.read_text(encoding='utf-8', errors='ignore')
            # 清洗并加载密码（转小写用于比较）
            _WEAK_PASSWORDS_CACHE = {
                line.strip().lower()
                for line in content.splitlines()
                if line.strip() and len(line.strip()) >= 4  # 只加载长度>=4的密码
            }
            # 额外添加常见组合
            _WEAK_PASSWORDS_CACHE.update({
                "12345678", "password", "admin123", "root123", "qwertyui",
                "trident", "webshell", "scanner", "detector", "monitor"
            })
        except Exception as e:
            # 加载失败时返回空集合（不阻塞功能）
            logger.warning(f"Failed to load weak password dictionary: {e}")
            _WEAK_PASSWORDS_CACHE = set()
    else:
        # 文件不存在时使用内置最小集合
        _WEAK_PASSWORDS_CACHE = {
            "12345678", "password", "admin123", "root123",
            "qwertyui", "trident", "webshell"
        }

    _WEAK_PASSWORDS_LOADED = True
    return _WEAK_PASSWORDS_CACHE


def check_password_strength(password: str) -> Tuple[bool, str]:
    """
    密码强度验证（纯逻辑，无I/O）

    Returns:
        Tuple[bool, str]: (是否通过, 提示消息)
    """
    # 长度检查
    if len(password) < 8:
        return False, "密码长度至少8位"

    if len(password) > 64:
        return False, "密码长度不能超过64位"

    # 弱口令检查
    weak_passwords = load_weak_passwords()
    if password.lower() in weak_passwords:
        return False, "密码过于简单，禁止使用常见弱口令"

    # 复杂度检查（至少三种）
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(c in "@#$%^&+=-_!~.,:;*?/\\|" for c in password)

    complexity_score = sum([has_upper, has_lower, has_digit, has_symbol])
    if complexity_score < 3:
        return False, "密码复杂度不足（至少包含大小写字母、数字、符号中的三种）"

    # 连续重复字符检查（如 "aaa", "111"）
    if re.search(r'(.)\1{2,}', password):
        return False, "禁止连续重复字符（如aaa、111）"

    # 键盘序检查（如 "qwerty", "asdf"）
    keyboard_patterns = ["qwerty", "asdf", "zxcv", "1234", "abcd", "qaz", "wsx"]
    lowered = password.lower()
    if any(pattern in lowered for pattern in keyboard_patterns):
        return False, "禁止键盘序（如qwerty、asdf）"

    # 用户名相关性检查（避免密码包含用户名）
    # 注：Web端会传入用户名，CLI端不检查此项
    return True, "密码强度符合要求"


def update_password_hash_in_config(new_hash: str) -> Tuple[bool, str]:
    """
    原子更新 config.toml 中的 password_hash

    Args:
        new_hash: werkzeug生成的scrypt哈希值

    Returns:
        Tuple[bool, str]: (是否成功, 提示消息)
    """
    try:
        config_path = normalize_path("config.toml")

        # 确保配置文件存在
        if not config_path.exists():
            return False, "配置文件不存在"

        content = config_path.read_text(encoding='utf-8')

        # 正则查找并替换 password_hash
        pattern = r'(password_hash\s*=\s*)\"[^\"]*\"'
        if re.search(pattern, content):
            # 已存在，直接替换
            new_content = re.sub(pattern, f'\\1"{new_hash}"', content)
        else:
            # 不存在，在 [web_admin] 段内插入
            if "[web_admin]" not in content:
                # 如果连 [web_admin] 段都不存在，先创建
                content += "\n[web_admin]\nenabled = true\nhost = \"127.0.0.1\"\nport = 8080\nusername = \"admin\"\n"

            # 找到 [web_admin] 段的位置
            section_start = content.index("[web_admin]")
            section_end = content.find("\n[", section_start + 1)
            if section_end == -1:
                section_end = len(content)

            # 在段内添加 password_hash
            section = content[section_start:section_end]
            if not section.strip().endswith("\n"):
                section += "\n"
            section += f'password_hash = "{new_hash}"\n'

            new_content = content[:section_start] + section + content[section_end:]

        # 原子写入：先写临时文件再替换
        temp_path = config_path.with_suffix('.toml.tmp')
        temp_path.write_text(new_content, encoding='utf-8')

        # Windows 兼容性处理：确保句柄释放
        if config_path.exists():
            try:
                config_path.unlink()
            except PermissionError:
                # 文件被占用，等待100ms后重试
                import time
                time.sleep(0.1)
                config_path.unlink()

        temp_path.replace(config_path)

        return True, "密码已更新，重启服务后生效"

    except PermissionError:
        return False, "配置文件被占用，请关闭其他进程后重试"
    except Exception as e:
        return False, f"配置更新失败: {e}"


def validate_current_password(input_password: str) -> Tuple[bool, str]:
    """
    验证当前密码是否正确

    Args:
        input_password: 用户输入的明文密码

    Returns:
        Tuple[bool, str]: (是否匹配, 提示消息)
    """
    try:
        config = ConfigRegistry.get_raw_config()
        web_admin_cfg = config.get("web_admin", {})
        stored_hash = web_admin_cfg.get("password_hash", "")

        if not stored_hash:
            return False, "密码哈希未配置"

        from werkzeug.security import check_password_hash

        if check_password_hash(stored_hash, input_password):
            return True, "当前密码正确"
        else:
            return False, "当前密码错误"

    except Exception as e:
        return False, f"验证失败: {e}"