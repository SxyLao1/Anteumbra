# -*- coding: utf-8 -*-
"""
@Time: 1/8/2026 4:38 PM
@Auth: SxyLao1
@File: path_utils.py
@IDE: PyCharm
@Motto: HACK THE REAL
"""
from pathlib import Path
from typing import Union  # 必须导入 Union


def normalize_path(path: Union[str, Path]) -> Path:
    """统一路径标准化（解决反斜杠转义问题）"""
    if isinstance(path, str):
        # 将所有反斜杠转为正斜杠
        path = path.replace('\\', '/')
    return Path(path).resolve()

def path_to_key(path: Union[str, Path]) -> str:
    """
    生成唯一路径键（用于Registry去重）- 必须使用resolve().lower()
    幽灵目录场景：即使路径已删除，也返回标准化后的字符串键
    """
    # 关键：必须resolve()确保绝对路径，然后转小写
    try:
        return str(normalize_path(path).resolve()).lower()
    except Exception:
        # 路径已删除无法resolve，使用原始字符串
        if isinstance(path, Path):
            path_str = str(path)
        else:
            path_str = path
        # 统一分隔符并转小写
        return path_str.replace('\\', '/').lower()