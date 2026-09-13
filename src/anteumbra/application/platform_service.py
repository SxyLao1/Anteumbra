"""Application-facing platform capabilities."""

from __future__ import annotations

import socket

# Watcher selection lives in anteumbra.infrastructure.utils.platform_utils and
# nowhere else.  A second copy used to live here; it silently kept polling after
# the real factory changed, which is how the architecture docs ended up
# describing an observer that nothing used.


def check_port_reachable(host: str, port: int, timeout: int = 3) -> bool:
    """Return whether a TCP endpoint accepts a connection."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            return sock.connect_ex((host, port)) == 0
    except OSError:
        return False


__all__ = ["check_port_reachable"]
