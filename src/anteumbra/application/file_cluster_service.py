# -*- coding: utf-8 -*-
"""
v1.0.9: File Cluster Application Service

Thin facade over infrastructure.detection.file_cluster.
Establishes the DDD dependency direction:
  Interface (blueprints) -> Application (here) -> Infrastructure
"""
from anteumbra.infrastructure.detection.file_cluster import (
    get_file_cluster_engine,
    FileCluster,
    FileClusterEngine,
)

__all__ = [
    "get_file_cluster_engine",
    "FileCluster",
    "FileClusterEngine",
]
