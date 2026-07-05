# -*- coding: utf-8 -*-
"""
v1.9.4: Cloudflare WAF API Adapter

Polls Cloudflare GraphQL Analytics API for WAF events.
Implements Plugin + PollableEventSource.

Config:
  [plugins.cloudflare]
  zone_id = "${CLOUDFLARE_ZONE_ID:-}"
  api_token = "${CLOUDFLARE_API_TOKEN:-}"
  poll_interval = 60
  lookback_minutes = 5
"""
import json
import logging
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Dict, Any

from anteumbra.domain import PollableEventSource
from anteumbra.domain import Plugin, DomainEvent

logger = logging.getLogger(__name__)

# Cloudflare GraphQL endpoint
_CF_API = "https://api.cloudflare.com/client/v4/graphql"

_WAF_QUERY = """
query ($zoneTag: string!, $since: string!, $until: string!, $limit: int!) {
  viewer {
    zones(filter: {zoneTag: $zoneTag}) {
      firewallEventsAdaptive(
        filter: {datetime_gt: $since, datetime_lt: $until},
        limit: $limit, orderBy: [datetime_DESC]
      ) {
        action source clientIP clientRequestHTTPHost
        clientRequestHTTPMethodName clientRequestPath
        clientRequestHTTPProtocol userAgent ruleId
        datetime
      }
    }
  }
}
"""


class CloudflareAdapter(Plugin, PollableEventSource):
    """Cloudflare WAF GraphQL API adapter"""

    def __init__(self):
        self._running = False
        self._thread = None
        self._callback = None
        self._config: Dict[str, Any] = {}
        self._last_poll: Optional[datetime] = None

    @property
    def name(self) -> str:
        return "cloudflare"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def supported_events(self) -> List[str]:
        return ["waf.event"]

    def activate(self, config: Dict[str, Any]) -> None:
        self._config = config
        self._zone_id = config.get("zone_id", "")
        self._api_token = config.get("api_token", "")
        self._poll_interval = int(config.get("poll_interval", 60))
        self._lookback = int(config.get("lookback_minutes", 5))
        if not self._zone_id or not self._api_token:
            logger.warning("Cloudflare: zone_id or api_token not configured")
        logger.info("Cloudflare: activated (zone=%s, poll=%ds)", self._zone_id[:8] if self._zone_id else "???", self._poll_interval)

    def deactivate(self) -> None:
        self.stop()

    def on_event(self, event: DomainEvent) -> Optional[List[DomainEvent]]:
        return None

    def start(self) -> None:
        if self._running: return
        self._running = True
        self._last_poll = datetime.now(timezone.utc) - timedelta(minutes=self._lookback)
        self._thread = threading.Thread(target=self._poll_loop, daemon=True, name="CloudflareAdapter")
        self._thread.start()

    def stop(self) -> None:
        self._running = False

    def is_running(self) -> bool:
        return self._running

    def poll(self, start_time: datetime, end_time: datetime, limit: int = 100) -> List[dict]:
        if not self._zone_id or not self._api_token:
            return []
        try:
            import urllib.request
            body = json.dumps({
                "query": _WAF_QUERY,
                "variables": {
                    "zoneTag": self._zone_id,
                    "since": start_time.isoformat(),
                    "until": end_time.isoformat(),
                    "limit": min(limit, 10000),
                }
            }).encode("utf-8")
            req = urllib.request.Request(_CF_API, data=body, method="POST")
            req.add_header("Authorization", f"Bearer {self._api_token}")
            req.add_header("Content-Type", "application/json")
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read())
            events = []
            zones = data.get("data", {}).get("viewer", {}).get("zones", [])
            for zone in zones:
                for fe in zone.get("firewallEventsAdaptive", []):
                    events.append({
                        "src_ip": fe.get("clientIP", ""),
                        "timestamp": fe.get("datetime", ""),
                        "http_method": fe.get("clientRequestHTTPMethodName", "GET"),
                        "url": fe.get("clientRequestPath", ""),
                        "user_agent": fe.get("userAgent", ""),
                        "waf_rule_id": fe.get("ruleId", "cf-waf"),
                        "waf_score": 0.85 if fe.get("action") == "block" else 0.5,
                        "attack_type": self._classify(fe),
                        "source": "cloudflare",
                    })
            return events[:limit]
        except Exception as e:
            logger.error("Cloudflare: poll error: %s", e)
            return []

    def _poll_loop(self):
        while self._running:
            try:
                now = datetime.now(timezone.utc)
                events = self.poll(self._last_poll, now, limit=500)
                for evt in events:
                    if self._callback:
                        self._callback(evt)
                self._last_poll = now
            except Exception as e:
                logger.error("Cloudflare: poll loop error: %s", e)
            time.sleep(self._poll_interval)

    @staticmethod
    def _classify(fe: dict) -> str:
        path = fe.get("clientRequestPath", "").lower()
        if ".php" in path: return "webshell"
        if "wp-login" in path: return "bruteforce"
        if "select" in path: return "sqli"
        return "unknown"
