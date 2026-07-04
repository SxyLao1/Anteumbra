# -*- coding: utf-8 -*-
"""
v1.0.9: Manual Scanner Application Service

Thin facade over infrastructure.detection.manual_scanner.
Establishes the DDD dependency direction:
  Interface (blueprints) -> Application (here) -> Infrastructure
"""
from anteumbra.infrastructure.detection.manual_scanner import (
    ManualScanner,
    ManualScanResult,
)

__all__ = [
    "ManualScanner",
    "ManualScanResult",
]
