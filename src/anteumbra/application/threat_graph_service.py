# -*- coding: utf-8 -*-
"""
v1.0.9: Threat Graph Application Service

Thin facade over infrastructure.threat_graph.
Establishes the DDD dependency direction:
  Interface (blueprints) -> Application (here) -> Infrastructure
"""
from anteumbra.infrastructure.threat_graph import (
    get_threat_graph,
    ThreatGraph,
    AttackerProfile,
    IPReputation,
)

__all__ = [
    "get_threat_graph",
    "ThreatGraph",
    "AttackerProfile",
    "IPReputation",
]
