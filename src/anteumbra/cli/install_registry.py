# -*- coding: utf-8 -*-
"""
Anteumbra 全局安装注册表 — 单机单实例锁。

存储在 ~/.anteumbra/installs.json，记录当前设备上唯一的 Anteumbra 部署实例路径。
"""

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict


def _registry_dir() -> Path:
    """返回注册表目录 ~/.anteumbra/，确保存在。"""
    d = Path.home() / ".anteumbra"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _registry_path() -> Path:
    """返回注册表文件路径 ~/.anteumbra/installs.json。"""
    return _registry_dir() / "installs.json"


def get_install_info() -> Optional[Dict]:
    """读取全局安装注册表，返回已安装实例的信息；未安装则返回 None。"""
    try:
        rp = _registry_path()
        if not rp.exists():
            return None
        data = json.loads(rp.read_text(encoding="utf-8"))
        if isinstance(data, dict) and "install_path" in data:
            # 验证安装目录是否存在
            ip = Path(data["install_path"])
            if ip.exists() and (ip / ".anteumbra_install").exists():
                return data
            else:
                # 安装目录已被删除——清理注册表
                rp.unlink(missing_ok=True)
                return None
        return None
    except (json.JSONDecodeError, OSError):
        return None


def register_install(install_path: str, version: str) -> None:
    """写入全局安装注册表。"""
    rp = _registry_path()
    data = {
        "install_path": str(Path(install_path).resolve()),
        "version": version,
        "installed_at": datetime.now().isoformat(),
        "python": os.environ.get("ANTEUMBRA_PYTHON", ""),
    }
    _registry_dir()
    rp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def unregister_install() -> None:
    """删除全局安装注册表条目。"""
    _registry_path().unlink(missing_ok=True)


def is_installed() -> bool:
    """检查当前设备是否已安装 Anteumbra 实例。"""
    return get_install_info() is not None
