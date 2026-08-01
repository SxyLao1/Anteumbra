"""Application-facing platform capabilities."""

from __future__ import annotations

import platform
import socket

from watchdog.observers import Observer
from watchdog.observers.polling import PollingObserver


def get_optimal_observer():
    """Create the watcher implementation best suited to the host OS."""
    system = platform.system().lower()
    if system == "windows":
        return PollingObserver(timeout=0.2)
    if system == "linux":
        from watchdog.observers.inotify import InotifyObserver

        return InotifyObserver()
    return Observer()


def check_port_reachable(host: str, port: int, timeout: int = 3) -> bool:
    """Return whether a TCP endpoint accepts a connection."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            return sock.connect_ex((host, port)) == 0
    except OSError:
        return False


__all__ = ["check_port_reachable", "get_optimal_observer"]
