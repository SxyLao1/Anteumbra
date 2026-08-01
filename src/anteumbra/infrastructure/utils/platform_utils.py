# -*- coding: utf-8 -*-
"""
@Time: 1/9/2026 3:49 PM
@Auth: SxyLao1
@File: platform_utils.py
@IDE: PyCharm
@Motto: HACK THE REAL
"""
import platform

from watchdog.observers import Observer
from watchdog.observers.polling import PollingObserver


def get_optimal_observer():
    """根据平台选择最优Observer"""
    system = platform.system().lower()
    if system == "windows":
        return PollingObserver(timeout=0.2)
    elif system == "linux":
        # 延迟导入：仅在Linux平台加载InotifyObserver
        from watchdog.observers.inotify import InotifyObserver
        return InotifyObserver()  # 内核级通知，0延迟
    else:
        return Observer()  # 默认

def check_port_reachable(host: str, port: int, timeout: int = 3) -> bool:
    """
    v1.7.7: 通用端口可达性检测
    复用 core/scanner.py 的 check_port 函数，避免重复实现
    """
    try:
        from anteumbra.infrastructure.detection.scanner import check_port
        return check_port(host, port, timeout)
    except ImportError:
        # 如果 scanner 模块未初始化，使用基础实现
        import socket
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except Exception:
            return False