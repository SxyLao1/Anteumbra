# -*- coding: utf-8 -*-
"""
v1.0.9: Metrics Application Service

Thin facade over infrastructure.monitoring.metrics.
Establishes the DDD dependency direction:
  Interface (blueprints) -> Application (here) -> Infrastructure
"""
from anteumbra.infrastructure.monitoring.metrics import (
    get_metrics,
    MetricsCollector,
)

__all__ = [
    "get_metrics",
    "MetricsCollector",
]
