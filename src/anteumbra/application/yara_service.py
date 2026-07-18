# -*- coding: utf-8 -*-
"""
v1.0.9: YARA Application Service

Thin facade over infrastructure.detection.yara_engine.
Establishes the DDD dependency direction:
  Interface (blueprints) -> Application (here) -> Infrastructure
"""
from anteumbra.infrastructure.detection.yara_engine import (
    get_bundled_rules_path,
    get_yara_engine,
    resolve_yara_rules_path,
    YaraEngine,
    YaraMatch,
)

__all__ = [
    "get_bundled_rules_path",
    "get_yara_engine",
    "resolve_yara_rules_path",
    "YaraEngine",
    "YaraMatch",
]
