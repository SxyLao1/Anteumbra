# -*- coding: utf-8 -*-
"""
v1.9.4: AWS WAF Adapter

Polls AWS WAFv2 logs from CloudWatch or S3.
Implements Plugin + PollableEventSource.

Requires: boto3 (pip install boto3)

Config:
  [plugins.aws_waf]
  region = "us-east-1"
  web_acl_arn = "arn:aws:wafv2:..."
  log_source = "cloudwatch"   # cloudwatch | s3
  log_group = "/aws/waf/logs"
  poll_interval = 300
"""
import json
import logging
import os
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Dict, Any

from anteumbra.domain import PollableEventSource
from anteumbra.domain import Plugin, DomainEvent

logger = logging.getLogger(__name__)


class AWSWAFAdapter(Plugin, PollableEventSource):
    """AWS WAFv2 log adapter"""

    def __init__(self):
        self._running = False
        self._thread = None
        self._callback = None
        self._config: Dict[str, Any] = {}
        self._boto3 = None
        self._logs_client = None

    @property
    def name(self) -> str:
        return "aws_waf"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def supported_events(self) -> List[str]:
        return ["waf.event"]

    def activate(self, config: Dict[str, Any]) -> None:
        self._config = config
        self._region = config.get("region", "us-east-1")
        self._web_acl = config.get("web_acl_arn", "")
        self._log_source = config.get("log_source", "cloudwatch")
        self._log_group = config.get("log_group", "/aws/waf/logs")
        self._poll_interval = int(config.get("poll_interval", 300))
        self._init_client()
        logger.info("AWS WAF: activated (region=%s, source=%s)", self._region, self._log_source)

    def deactivate(self) -> None:
        self.stop()

    def on_event(self, event: DomainEvent) -> Optional[List[DomainEvent]]:
        return None

    def _init_client(self):
        try:
            import boto3
            self._boto3 = boto3
            self._logs_client = boto3.client("logs", region_name=self._region)
        except ImportError:
            logger.warning("AWS WAF: boto3 not installed, adapter will be inactive")
        except Exception as e:
            logger.error("AWS WAF: client init failed: %s", e)

    def start(self) -> None:
        if self._running: return
        self._running = True
        self._thread = threading.Thread(target=self._poll_loop, daemon=True, name="AWSWAFAdapter")
        self._thread.start()

    def stop(self) -> None:
        self._running = False

    def is_running(self) -> bool:
        return self._running

    def poll(self, start_time: datetime, end_time: datetime, limit: int = 100) -> List[dict]:
        if not self._logs_client:
            return []
        events = []
        try:
            start_ms = int(start_time.timestamp() * 1000)
            end_ms = int(end_time.timestamp() * 1000)
            kwargs = {
                "logGroupName": self._log_group,
                "startTime": start_ms,
                "endTime": end_ms,
                "limit": min(limit, 10000),
                "filterPattern": '{ $.action = "BLOCK" }',
            }
            response = self._logs_client.filter_log_events(**kwargs)
            for event in response.get("events", []):
                try:
                    entry = json.loads(event.get("message", "{}"))
                    http_req = entry.get("httpRequest", {})
                    events.append({
                        "src_ip": http_req.get("clientIp", ""),
                        "timestamp": datetime.fromtimestamp(event["timestamp"] / 1000, tz=timezone.utc).isoformat(),
                        "http_method": http_req.get("httpMethod", ""),
                        "url": http_req.get("uri", ""),
                        "user_agent": http_req.get("headers", [{}])[0].get("value", "") if http_req.get("headers") else "",
                        "waf_rule_id": entry.get("ruleGroupList", [{}])[0].get("ruleGroupId", "aws-waf"),
                        "waf_score": 0.85,
                        "attack_type": self._classify(http_req),
                        "source": "aws_waf",
                    })
                except json.JSONDecodeError:
                    continue
            return events[:limit]
        except Exception as e:
            logger.error("AWS WAF: poll error: %s", e)
            return []

    def _poll_loop(self):
        while self._running:
            try:
                now = datetime.now(timezone.utc)
                start = now - timedelta(seconds=self._poll_interval)
                events = self.poll(start, now, limit=500)
                for evt in events:
                    if self._callback:
                        self._callback(evt)
            except Exception as e:
                logger.error("AWS WAF: poll loop error: %s", e)
            time.sleep(self._poll_interval)

    @staticmethod
    def _classify(http_req: dict) -> str:
        uri = http_req.get("uri", "").lower()
        if "php" in uri: return "webshell"
        if "select" in uri: return "sqli"
        if "cmd" in uri: return "rce"
        return "unknown"
