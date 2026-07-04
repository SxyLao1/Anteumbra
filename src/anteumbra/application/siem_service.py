# -*- coding: utf-8 -*-
"""
v1.0.9: SIEM Application Service

Thin facade over infrastructure.monitoring.siem_exporter.
Establishes the DDD dependency direction:
  Interface (blueprints) -> Application (here) -> Infrastructure
"""
from anteumbra.infrastructure.monitoring.siem_exporter import (
    get_siem_exporter,
    SIEMExporter,
)

__all__ = [
    "get_siem_exporter",
    "SIEMExporter",
]
