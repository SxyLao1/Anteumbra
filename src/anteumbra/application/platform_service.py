# -*- coding: utf-8 -*-
"""
Application Service: Platform Utilities

Thin facade over infrastructure/utils/platform_utils.py.
Fixes DDD dependency direction: Interfaces → Application → Infrastructure.
"""
from anteumbra.infrastructure.utils.platform_utils import (
    check_port_reachable,
    get_optimal_observer,
)

__all__ = [
    "check_port_reachable",
    "get_optimal_observer",
]
