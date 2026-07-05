# -*- coding: utf-8 -*-
"""
v1.9.4: ModSecurity JSON Audit Log Adapter

Consumes ModSecurity v2/v3 JSON audit logs.
Implements Plugin + PollableEventSource interface.

Config:
  [plugins.modsecurity]
  audit_log_path = "/var/log/modsec_audit.log"
  poll_interval = 5
  min_score = 5.0
"""
import json
import logging
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Dict, Any

from anteumbra.domain import PollableEventSource
from anteumbra.domain import Plugin, DomainEvent

logger = logging.getLogger(__name__)


class ModSecurityAdapter(Plugin, PollableEventSource):
    """ModSecurity JSON audit log adapter"""

    def __init__(self):
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._pos = 0
        self._callback = None
        self._config: Dict[str, Any] = {}

    @property
    def name(self) -> str:
        return "modsecurity"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def supported_events(self) -> List[str]:
        return ["waf.event"]

    def activate(self, config: Dict[str, Any]) -> None:
        self._config = config
        self._path = Path(config.get("audit_log_path", "/var/log/modsec_audit.log"))
        self._poll_interval = config.get("poll_interval", 5)
        self._min_score = config.get("min_score", 5.0)
        logger.info("ModSecurity: activated, watching %s (poll=%ds, min_score=%.1f)",
                    self._path, self._poll_interval, self._min_score)

    def deactivate(self) -> None:
        self.stop()
        logger.info("ModSecurity: deactivated")

    def on_event(self, event: DomainEvent) -> Optional[List[DomainEvent]]:
        return None

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._poll_loop, daemon=True, name="ModSecAdapter")
        self._thread.start()
        logger.info("ModSecurity: polling started")

    def stop(self) -> None:
        self._running = False

    def is_running(self) -> bool:
        return self._running

    def poll(self, start_time: datetime, end_time: datetime, limit: int = 100) -> List[dict]:
        events = []
        try:
            if not self._path.exists():
                return events
            with open(self._path, "r", encoding="utf-8") as f:
                f.seek(self._pos)
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                        tx = entry.get("transaction", {})
                        ts_str = tx.get("time_stamp", "")
                        if ts_str:
                            try:
                                ts = datetime.strptime(ts_str, "%Y-%m-%dT%H:%M:%S")
                                if ts < start_time or ts >= end_time:
                                    continue
                            except ValueError:
                                pass
                        score = float(entry.get("audit_data", {}).get("messages", [{}])[0].get("total_score", 0))
                        if score < self._min_score:
                            continue
                        req = entry.get("request", {})
                        events.append({
                            "src_ip": tx.get("client_ip", ""),
                            "timestamp": ts_str,
                            "http_method": req.get("method", ""),
                            "url": req.get("uri", ""),
                            "user_agent": req.get("headers", {}).get("User-Agent", ""),
                            "waf_rule_id": entry.get("audit_data", {}).get("messages", [{}])[0].get("rule_id", "modsec"),
                            "waf_score": score,
                            "attack_type": self._classify(entry),
                            "raw": entry,
                        })
                        if len(events) >= limit:
                            break
                    except json.JSONDecodeError:
                        continue
                self._pos = f.tell()
        except Exception as e:
            logger.error("ModSecurity: poll error: %s", e)
        return events

    def _poll_loop(self):
        while self._running:
            try:
                now = datetime.now()
                events = self.poll(
                    datetime.fromtimestamp(now.timestamp() - self._poll_interval),
                    now, limit=200)
                for evt in events:
                    if self._callback:
                        self._callback(evt)
            except Exception as e:
                logger.error("ModSecurity: poll loop error: %s", e)
            time.sleep(self._poll_interval)

    def _classify(self, entry: dict) -> str:
        request = entry.get("request", {})
        uri = request.get("uri", "").lower()
        if ".php" in uri or "eval" in str(entry).lower():
            return "webshell"
        if "select" in uri or "union" in uri:
            return "sqli"
        if "cmd" in uri or "exec" in uri:
            return "rce"
        return "unknown"
