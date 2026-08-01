# -*- coding: utf-8 -*-
"""
v1.9.5: SIEM Export Engine

Wraps utils/siem_formatter.py for production use:
  - File-based JSON Lines export (append-only, auto-rotate)
  - Syslog UDP streaming to SIEM collector
  - Pipeline hook: emits SIEM events on Registry add

Config:
  [siem]
  enabled = true
  format = "json_lines"    # json_lines | cef | syslog
  export_file = "data/siem/events.jsonl"
  rotate_mb = 100
  syslog_host = "siem.company.com"
  syslog_port = 514
  syslog_protocol = "udp"  # udp | tcp
"""
import logging
import os
import socket
import threading
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from anteumbra.infrastructure.utils.siem_formatter import SIEMFormatter

logger = logging.getLogger(__name__)

class SIEMExporter:
    """SIEM export engine — file and/or syslog output."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self._config = config or {}
        self._lock = threading.Lock()
        self._enabled = self._config.get("enabled", False)
        if not self._enabled:
            return

        self._format = self._config.get("format", "json_lines")
        self._export_path = Path(self._config.get("export_file", "data/siem/events.jsonl"))
        self._export_path.parent.mkdir(parents=True, exist_ok=True)
        self._rotate_mb = int(self._config.get("rotate_mb", 100))
        self._syslog_host = self._config.get("syslog_host", "")
        self._syslog_port = int(self._config.get("syslog_port", 514))
        self._syslog_protocol = self._config.get("syslog_protocol", "udp")

        self._formatter = SIEMFormatter(self._config)
        self._sock: Optional[socket.socket] = None
        self._total_exported = 0

        if self._syslog_host:
            self._connect_syslog()

        logger.info("SIEMExporter: enabled (format=%s, file=%s, syslog=%s)",
                    self._format, self._export_path,
                    f"{self._syslog_host}:{self._syslog_port}" if self._syslog_host else "disabled")

    @property
    def enabled(self) -> bool:
        return self._enabled

    def _connect_syslog(self) -> bool:
        try:
            sock_type = socket.SOCK_DGRAM if self._syslog_protocol == "udp" else socket.SOCK_STREAM
            self._sock = socket.socket(socket.AF_INET, sock_type)
            if sock_type == socket.SOCK_STREAM:
                self._sock.connect((self._syslog_host, self._syslog_port))
            return True
        except Exception as e:
            logger.warning("SIEMExporter: syslog connect failed: %s", e)
            self._sock = None
            return False

    def emit(self, raw_event: Dict[str, Any]) -> Optional[str]:
        """Emit a single event to configured outputs. Returns formatted line or None."""
        if not self._enabled:
            return None
        try:
            line = self._formatter.format_event(raw_event)
            with self._lock:
                # File output
                self._write_file(line)
                self._total_exported += 1
                # Syslog output
                if self._sock:
                    self._send_syslog(line)
                # Auto-rotate
                if self._total_exported % 1000 == 0:
                    self._check_rotate()
            return line
        except Exception as e:
            logger.error("SIEMExporter: emit failed: %s", e)
            return None

    def emit_batch(self, events: List[Dict[str, Any]]) -> int:
        """Emit multiple events. Returns count of successfully exported events."""
        count = 0
        for event in events:
            if self.emit(event):
                count += 1
        return count

    def _write_file(self, line: str) -> None:
        with open(self._export_path, "a", encoding="utf-8") as file_handle:
            file_handle.write(line + "\n")

    def _send_syslog(self, line: str) -> None:
        if not self._sock:
            return
        try:
            data = line.encode("utf-8")
            if self._syslog_protocol == "udp":
                self._sock.sendto(data, (self._syslog_host, self._syslog_port))
            else:
                self._sock.sendall(data + b"\n")
        except Exception:
            # Reconnect on failure
            logger.debug("SIEMExporter: syslog send failed, reconnecting...")
            try:
                self._sock.close()
            except Exception:
                logger.debug("Failed to close syslog socket during reconnect", exc_info=True)
            self._connect_syslog()

    def _check_rotate(self) -> None:
        try:
            if self._export_path.exists() and self._export_path.stat().st_size > self._rotate_mb * 1024 * 1024:
                backup = self._export_path.with_suffix(f".{datetime.now():%Y%m%d%H%M%S}.jsonl")
                os.rename(self._export_path, backup)
                logger.info("SIEMExporter: rotated %s -> %s", self._export_path, backup)
        except Exception as e:
            logger.error("SIEMExporter: rotate failed: %s", e)

    def get_stats(self) -> Dict[str, Any]:
        return {
            "enabled": self._enabled,
            "format": self._format,
            "total_exported": self._total_exported,
            "export_file": str(self._export_path),
            "syslog_active": self._sock is not None,
            "file_size_mb": round(self._export_path.stat().st_size / 1024 / 1024, 2) if self._export_path.exists() else 0,
        }
    @property
    def export_path(self) -> Path:
        """Return the configured file export path."""
        return self._export_path

    @property
    def format(self) -> str:
        """Return the active output format."""
        return self._format

    def set_format(self, output_format: str) -> None:
        """Switch to a supported format through a validated public API."""
        normalized = str(output_format).strip().lower()
        if normalized not in {"json", "json_lines", "cef", "syslog"}:
            raise ValueError(f"Unsupported SIEM format: {output_format}")
        self._format = normalized
        self._config = {**self._config, "format": normalized}
        self._formatter = SIEMFormatter(self._config)

    def export_existing(self, records: List[Dict], category: str = "webshell.detected") -> int:
        """Export existing detection records as SIEM events."""
        events = []
        for r in records:
            events.append({
                "id": r.get("id", ""),
                "detected_at": r.get("detected_at", ""),
                "file_path": r.get("file_path", ""),
                "display_name": r.get("display_name", ""),
                "features": r.get("features", []),
                "rule_name": r.get("features", ["unknown"])[0] if r.get("features") else "unknown",
                "category": category,
                "severity": "high",
                "source_ip": r.get("first_seen_ip", "unknown"),
            })
        return self.emit_batch(events)

    def emit_detection(
        self,
        record: Dict[str, Any],
        category: str = "webshell.detected",
    ) -> Optional[str]:
        """Export one Registry detection using the standard SIEM schema."""
        return self.emit({
            "id": record.get("id", ""),
            "detected_at": record.get("detected_at", ""),
            "file_path": record.get("file_path", ""),
            "display_name": (
                Path(record.get("file_path", "")).name
                if record.get("file_path")
                else "unknown"
            ),
            "features": record.get("features", []),
            "rule_name": (
                record.get("features", [None])[0]
                if record.get("features")
                else "unknown"
            ),
            "category": category,
            "severity": "high",
            "source_ip": record.get("first_seen_ip", "unknown"),
            "confidence": 85,
            "mitre_tid": "T1505.003",
            "mitre_tactic": "Persistence",
        })

    def close(self) -> None:
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                logger.debug("Failed to close syslog socket during exporter shutdown", exc_info=True)
            self._sock = None
