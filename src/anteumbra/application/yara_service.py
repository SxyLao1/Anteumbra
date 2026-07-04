# -*- coding: utf-8 -*-
"""
v1.0.9: YARA Application Service

Thin facade over infrastructure.detection.yara_engine.
Establishes the DDD dependency direction:
  Interface (blueprints) -> Application (here) -> Infrastructure
"""
from anteumbra.infrastructure.detection.yara_engine import (
    get_yara_engine,
    YaraEngine,
    YaraMatch,
)

__all__ = [
    "get_yara_engine",
    "YaraEngine",
    "YaraMatch",
]
