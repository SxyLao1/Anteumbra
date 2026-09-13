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

# Reading a file updates its last-access time, and watchdog's Windows observer
# asks ReadDirectoryChangesW to report that as a change.  Our own scans read
# every monitored file, so those two flags turn scanning into a feedback loop:
# measured on a live site, a tree nobody was touching produced 8.6 MODIFY
# events per second and the service never went idle.  Polling never had the bug
# because it compares modification time and size instead of listening.
ACCESS_ONLY_NOTIFY_FLAGS = (
    "FILE_NOTIFY_CHANGE_LAST_ACCESS",
    "FILE_NOTIFY_CHANGE_ATTRIBUTES",
)


def watch_content_changes_only() -> bool:
    """Drop access-time notifications from watchdog's Windows notify mask.

    Returns ``False`` when this watchdog build does not expose the mask, so the
    caller can fall back to polling rather than watch a tree that reports
    nothing.  The mask is read when each read is issued, so masking it here
    affects observers created afterwards.
    """
    try:
        from watchdog.observers import winapi
    except Exception:  # pragma: no cover - platform/version dependent
        return False

    flags = getattr(winapi, "WATCHDOG_FILE_NOTIFY_FLAGS", None)
    if flags is None:
        return False
    for name in ACCESS_ONLY_NOTIFY_FLAGS:
        value = getattr(winapi, name, None)
        if value is None:
            return False
        flags &= ~value
    winapi.WATCHDOG_FILE_NOTIFY_FLAGS = flags
    return True


def get_optimal_observer():
    """Create the watcher implementation best suited to the host OS."""
    system = platform.system().lower()
    if system == "windows":
        # Native events instead of a five-times-a-second walk of the whole tree
        # (measured: 80.7% of a core idle, against 3.3% natively), but only when
        # the access-time notifications can be masked out.
        if watch_content_changes_only():
            return Observer()
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
