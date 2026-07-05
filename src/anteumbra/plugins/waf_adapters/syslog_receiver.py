# -*- coding: utf-8 -*-
"""
v1.9.4: Syslog WAF Receiver

Listens on a UDP port for syslog-formatted WAF events.
Implements Plugin + StreamEventSource interface.

Supports: ModSecurity syslog, Cloudflare syslog, generic CEF format.

Config:
  [plugins.syslog_waf]
  host = "0.0.0.0"
  port = 514
  format = "cef"   # cef | modsecurity | cloudflare
"""
import json
import logging
import re
import socket
import threading
from datetime import datetime
from typing import List, Optional, Dict, Any

from anteumbra.domain import StreamEventSource
from anteumbra.domain import Plugin, DomainEvent

logger = logging.getLogger(__name__)

# CEF header regex: CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity
_CEF_RE = re.compile(
    r"CEF:\d+\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|(\d+)"
)


class SyslogWAFReceiver(Plugin, StreamEventSource):
    """Syslog UDP receiver for WAF events"""

    def __init__(self):
        self._running = False
        self._socket: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._callback = None
        self._config: Dict[str, Any] = {}
        self._buffer = b""

    @property
    def name(self) -> str:
        return "syslog_waf"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def supported_events(self) -> List[str]:
        return ["waf.event", "waf.alert"]

    def activate(self, config: Dict[str, Any]) -> None:
        self._config = config
        self._host = config.get("host", "0.0.0.0")
        self._port = int(config.get("port", 514))
        self._format = config.get("format", "cef")
        logger.info("SyslogWAF: activated on %s:%d (format=%s)", self._host, self._port, self._format)

    def deactivate(self) -> None:
        self.stop()
        logger.info("SyslogWAF: deactivated")

    def on_event(self, event: DomainEvent) -> Optional[List[DomainEvent]]:
        return None

    def connect(self) -> bool:
        try:
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._socket.bind((self._host, self._port))
            self._socket.settimeout(2.0)
            return True
        except OSError as e:
            logger.error("SyslogWAF: bind failed: %s", e)
            return False

    def disconnect(self) -> None:
        if self._socket:
            try:
                self._socket.close()
            except Exception:
                pass
            self._socket = None

    def start(self) -> None:
        if self._running:
            return
        if not self.connect():
            return
        self._running = True
        self._thread = threading.Thread(target=self._recv_loop, daemon=True, name="SyslogWAF")
        self._thread.start()
        logger.info("SyslogWAF: listening on %s:%d", self._host, self._port)

    def stop(self) -> None:
        self._running = False
        self.disconnect()

    def is_running(self) -> bool:
        return self._running

    def _recv_loop(self):
        while self._running:
            try:
                data, addr = self._socket.recvfrom(4096)
                if not data:
                    continue
                msg = data.decode("utf-8", errors="replace").strip()
                event = self._parse(msg, addr[0])
                if event and self._callback:
                    self._callback(event)
            except socket.timeout:
                continue
            except Exception as e:
                logger.error("SyslogWAF: recv error: %s", e)

    def _parse(self, msg: str, src_addr: str) -> Optional[dict]:
        if self._format == "cef":
            m = _CEF_RE.search(msg)
            if m:
                return {
                    "src_ip": self._extract_ip(msg, src_addr),
                    "timestamp": datetime.now().isoformat(),
                    "http_method": "POST",
                    "url": self._extract_field(msg, "request"),
                    "user_agent": "",
                    "waf_rule_id": m.group(5),
                    "waf_score": self._severity_to_score(int(m.group(6))),
                    "attack_type": self._classify(msg),
                    "source": "syslog",
                    "raw": msg,
                }
        return None

    @staticmethod
    def _extract_ip(msg: str, fallback: str) -> str:
        m = re.search(r'src=(\d+\.\d+\.\d+\.\d+)', msg)
        if m: return m.group(1)
        m = re.search(r'dst=(\d+\.\d+\.\d+\.\d+)', msg)
        if m: return m.group(1)
        return fallback

    @staticmethod
    def _extract_field(msg: str, key: str) -> str:
        m = re.search(fr'{key}=(\S+)', msg)
        return m.group(1) if m else ""

    @staticmethod
    def _severity_to_score(severity: int) -> float:
        return min(1.0, max(0.1, severity / 10.0))

    @staticmethod
    def _classify(msg: str) -> str:
        low = msg.lower()
        if "webshell" in low or "php" in low: return "webshell"
        if "sqli" in low or "sql" in low: return "sqli"
        if "rce" in low or "exec" in low: return "rce"
        if "scanner" in low: return "scanner"
        return "unknown"
