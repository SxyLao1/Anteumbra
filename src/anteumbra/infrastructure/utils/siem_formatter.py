#!/usr/bin/env python3
"""
Anteumbra SIEM Event Formatter
Standardizes detection events into SIEM-friendly formats.

Supported formats:
- JSON Lines (default): Structured JSON, one event per line
- CEF (Common Event Format): ArcSight/QRadar compatible
- Syslog RFC 5424: Standard syslog format
- Raw JSON: Pretty-printed for human reading

Design Philosophy:
- 0 hardcoding: Format configurable via config.toml [siem] section
- Event taxonomy: All events follow MITRE ATT&CK-style tagging
- Backward compatible: Existing text logs continue to work
"""

import json
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class EventSeverity(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EventCategory(Enum):
    WEBSHELL_DETECTED = "webshell.detected"
    WEBSHELL_QUARANTINED = "webshell.quarantined"
    FILE_UPLOAD_SUSPICIOUS = "file.upload.suspicious"
    MEMORY_SHELL_DETECTED = "memory.shell.detected"
    IP_BLOCKED = "ip.blocked"
    IP_UNBLOCKED = "ip.unblocked"
    LOG_ANOMALY = "log.anomaly"
    CONFIG_CHANGED = "config.changed"
    SYSTEM_ERROR = "system.error"


class SIEMFormatter:
    """Centralized event formatter for all SIEM integrations."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.format_type = self.config.get("format", "json_lines")
        self.include_raw = self.config.get("include_raw_sample", False)
        self.vendor = "Anteumbra"
        self.product = "WebShellDetector"
        self.version = self._get_version()

    def _get_version(self) -> str:
        try:
            from anteumbra.infrastructure.config.version import get_version

            return get_version()
        except Exception:
            return "unknown"

    def format_event(self, event: Dict[str, Any]) -> str:
        """Format a single event based on configured output type."""
        if self.format_type == "cef":
            return self._to_cef(event)
        elif self.format_type == "syslog":
            return self._to_syslog(event)
        elif self.format_type == "json":
            return self._to_json(event)
        else:
            return self._to_json_lines(event)

    def _normalize_event(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize raw event into standardized schema."""
        now = datetime.now(timezone.utc).isoformat()

        # Build standardized event
        normalized = {
            # Core identity
            "event_id": raw.get("id") or raw.get("event_id") or str(uuid.uuid4()),
            "event_time": raw.get("detected_at") or raw.get("timestamp") or now,
            "ingest_time": now,
            # Taxonomy
            "event_category": raw.get("category", EventCategory.WEBSHELL_DETECTED.value),
            "event_type": raw.get("event_type", "detection"),
            "severity": raw.get("severity", "medium"),
            "confidence": raw.get("confidence", 80),
            # Source context
            "source": {
                "ip": raw.get("source_ip", "unknown"),
                "file_path": raw.get("file_path", ""),
                "file_name": raw.get("display_name", ""),
                "website": raw.get("website_name", "default"),
            },
            # Detection context
            "detection": {
                "rule_name": raw.get("rule_name", ""),
                "rule_description": raw.get("rule_description", ""),
                "engine": raw.get("engine", "YaraEngine"),
                "features": raw.get("features", []),
                "communication_count": raw.get("communication_count", 0),
                "false_positive": raw.get("false_positive", False),
            },
            # MITRE ATT&CK mapping (placeholder for v1.8)
            "mitre": {
                "technique_id": raw.get("mitre_tid", ""),
                "tactic": raw.get("mitre_tactic", ""),
            },
            # Enrichment (placeholder for v1.9)
            "enrichment": {
                "geo_ip": raw.get("geo_ip", {}),
                "threat_intel": raw.get("threat_intel", {}),
            },
            # System metadata
            "anteumbra": {
                "version": self.version,
                "hostname": raw.get("hostname", ""),
                "instance_id": raw.get("instance_id", ""),
            },
        }

        # Include raw sample if configured
        if self.include_raw and "raw_sample" in raw:
            normalized["raw_sample"] = raw["raw_sample"]

        return normalized

    def _to_json_lines(self, event: Dict[str, Any]) -> str:
        """JSON Lines format: one compact JSON per line."""
        normalized = self._normalize_event(event)
        return json.dumps(normalized, ensure_ascii=False, separators=(",", ":"))

    def _to_json(self, event: Dict[str, Any]) -> str:
        """Pretty-printed JSON for human reading."""
        normalized = self._normalize_event(event)
        return json.dumps(normalized, ensure_ascii=False, indent=2)

    def _to_cef(self, event: Dict[str, Any]) -> str:
        """CEF: Common Event Format (ArcSight, QRadar, Splunk compatible)."""
        normalized = self._normalize_event(event)

        # CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|Extensions
        severity_num = {"low": 1, "medium": 5, "high": 7, "critical": 10}.get(
            normalized["severity"], 5
        )

        extensions = (
            f"src={normalized['source']['ip']} "
            f"fname={normalized['source']['file_name']} "
            f"fpath={normalized['source']['file_path']} "
            f"cs1={normalized['detection']['rule_name']} "
            f"cs1Label=RuleName "
            f"cs2={','.join(normalized['detection']['features'])} "
            f"cs2Label=Features "
            f"cs3={normalized['anteumbra']['version']} "
            f"cs3Label=AnteumbraVersion "
            f"fp={normalized['detection']['false_positive']} "
            f"confidence={normalized['confidence']}"
        )

        cef = (
            f"CEF:0|{self.vendor}|{self.product}|{self.version}|"
            f"{normalized['event_category']}|{normalized['detection']['rule_description']}|"
            f"{severity_num}|{extensions}"
        )
        return cef

    def _to_syslog(self, event: Dict[str, Any]) -> str:
        """RFC 5424 Syslog format."""
        normalized = self._normalize_event(event)

        severity_num = {"low": 4, "medium": 5, "high": 6, "critical": 7}.get(
            normalized["severity"], 5
        )

        # PRI = facility * 8 + severity (facility 1 = user-level)
        pri = 1 * 8 + severity_num

        timestamp = normalized["event_time"]
        hostname = normalized["anteumbra"].get("hostname", "anteumbra")
        msg = json.dumps(normalized, ensure_ascii=False, separators=(",", ":"))

        return f"<{pri}>1 {timestamp} {hostname} anteumbra - - - {msg}"

    def format_batch(self, events: List[Dict[str, Any]]) -> str:
        """Format multiple events (for file export or HTTP bulk push)."""
        lines = [self.format_event(e) for e in events]
        return "\n".join(lines)


# ============================================================================
# Convenience functions (module-level API)
# ============================================================================


def format_event(event: Dict[str, Any], config: Optional[Dict[str, Any]] = None) -> str:
    """One-shot event formatting."""
    return SIEMFormatter(config).format_event(event)


def format_batch(events: List[Dict[str, Any]], config: Optional[Dict[str, Any]] = None) -> str:
    """One-shot batch formatting."""
    return SIEMFormatter(config).format_batch(events)
