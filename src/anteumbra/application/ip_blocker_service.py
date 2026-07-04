# -*- coding: utf-8 -*-
"""
v1.0.9: IP Blocker Application Service

Thin facade over infrastructure.ip_blocker.
Establishes the DDD dependency direction:
  Interface (blueprints) -> Application (here) -> Infrastructure
"""
from anteumbra.infrastructure.ip_blocker import (
    get_ip_blocker,
    BlockDecision,
    BlockResult,
    BlockDevice,
    IPBlocker,
)

__all__ = [
    "get_ip_blocker",
    "BlockDecision",
    "BlockResult",
    "BlockDevice",
    "IPBlocker",
]
