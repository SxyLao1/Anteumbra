# Anteumbra v1.0: Application Services
#
# Each service module is a thin facade over its infrastructure counterpart,
# establishing the DDD dependency direction:
#   Interfaces -> Application -> Infrastructure
#
# Service modules:
#   registry_service      -> infrastructure.suspicious_registry
#   quarantine_service    -> infrastructure.quarantine
#   threat_graph_service  -> infrastructure.threat_graph
#   block_ledger_service  -> infrastructure.block_ledger
#   wal_service           -> infrastructure.wal_manager
#   ip_blocker_service    -> infrastructure.ip_blocker
#   yara_service          -> infrastructure.detection.yara_engine
#   file_cluster_service  -> infrastructure.detection.file_cluster
#   scanner_service       -> infrastructure.detection.manual_scanner
#   metrics_service       -> infrastructure.monitoring.metrics
#   siem_service          -> infrastructure.monitoring.siem_exporter

__all__ = [
    "block_ledger_service",
    "file_cluster_service",
    "ip_blocker_service",
    "metrics_service",
    "plugin_manager",
    "quarantine_service",
    "registry_service",
    "scanner_service",
    "siem_service",
    "threat_graph_service",
    "wal_service",
    "yara_service",
]
