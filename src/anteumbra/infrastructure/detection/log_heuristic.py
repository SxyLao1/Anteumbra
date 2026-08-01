# -*- coding: utf-8 -*-
"""
v1.9.5: Log Heuristic Engine — behavior-level detection from access logs.

Analyzes web server access logs for suspicious behavioral patterns:
  - Brute force: high-frequency requests to single file
  - Scanner detection: rapid probing of many paths from single IP
  - UA anomalies: tool signatures (sqlmap, nmap, etc.)
  - Path anomalies: requests to backup files, config files, shell upload paths

Supports: Nginx combined, Apache common, Tomcat AccessLogValve common, IIS W3C formats.

Design:
  - Sliding window analysis (configurable window_size)
  - Per-IP state tracking with TTL expiration
  - Outputs DetectionEvent list consumable by ThreatGraph
  - Zero external dependencies
"""

import logging
import re
import threading
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ── Log Format Parsers ──────────────────────────────────

# Nginx combined: $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"
_NGINX_RE = re.compile(
    r'(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+) \S+" (\d+) \d+ "([^"]*)" "([^"]*)"'
)

# Apache/Tomcat common: 127.0.0.1 - - [10/Oct/2000:13:55:36 -0700] "GET /app HTTP/1.1" 200 2326
_APACHE_RE = re.compile(r'(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+) \S+" (\d{3}) (?:\d+|-)')

# IIS W3C: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) sc-status
_IIS_RE = re.compile(r"(\S+) (\S+) \S+ \S+ (\S+) (\S+) \S+ \S+ (\S+) \S+ (\S+)")


def parse_log_line(line: str) -> Optional[Dict]:
    """Parse a single access log line. Returns dict with keys:
    ip, timestamp, method, path, status, user_agent, referer
    """
    for fmt_re, fmt_name in [(_NGINX_RE, "nginx"), (_APACHE_RE, "apache"), (_IIS_RE, "iis")]:
        m = fmt_re.match(line.strip())
        if m:
            if fmt_name == "nginx":
                ip, ts, method, path, status, referer, ua = m.groups()
                return {
                    "ip": ip,
                    "timestamp": ts,
                    "method": method,
                    "path": path,
                    "status": int(status),
                    "user_agent": ua,
                    "referer": referer,
                }
            elif fmt_name == "apache":
                ip, ts, method, path, status = m.groups()
                return {
                    "ip": ip,
                    "timestamp": ts,
                    "method": method,
                    "path": path,
                    "status": int(status),
                    "user_agent": "",
                    "referer": "",
                }
            elif fmt_name == "iis":
                date, time_str, method, path, ip, ua, status = m.groups()
                return {
                    "ip": ip,
                    "timestamp": f"{date} {time_str}",
                    "method": method,
                    "path": path,
                    "status": int(status),
                    "user_agent": ua,
                    "referer": "",
                }
    return None


# ── Suspicious Pattern Detectors ────────────────────────

# Known attacker tool signatures in User-Agent
_TOOL_SIGNATURES = {
    "sqlmap": re.compile(r"sqlmap", re.I),
    "nmap": re.compile(r"nmap|Nmap", re.I),
    "nikto": re.compile(r"nikto", re.I),
    "dirbuster": re.compile(r"dirbuster|DirBuster", re.I),
    "gobuster": re.compile(r"gobuster", re.I),
    "burp": re.compile(r"Burp Suite|burpsuite", re.I),
    "acunetix": re.compile(r"acunetix|Acunetix", re.I),
    "nessus": re.compile(r"nessus|Nessus", re.I),
    "zgrab": re.compile(r"zgrab|ZGrab", re.I),
    "masscan": re.compile(r"masscan", re.I),
    "curl": re.compile(r"curl/\d", re.I),
    "wget": re.compile(r"Wget/\d", re.I),
    "python": re.compile(r"python-requests|Python-urllib", re.I),
}

# Suspicious file extensions (backup, config, shell)
_SUSPICIOUS_EXTENSIONS = {
    ".sql",
    ".bak",
    ".backup",
    ".old",
    ".save",
    ".swp",
    ".swo",
    ".tar",
    ".gz",
    ".zip",
    ".rar",
    ".7z",
    ".env",
    ".ini",
    ".conf",
    ".config",
    ".yml",
    ".yaml",
    ".php5",
    ".phtml",
    ".php7",
    ".php8",
    ".asp",
    ".aspx",
    ".jsp",
}

# Suspicious path patterns (shell upload, config access, traversal)
_SUSPICIOUS_PATHS = [
    re.compile(r"/\.git/", re.I),
    re.compile(r"/\.svn/", re.I),
    re.compile(r"/\.env", re.I),
    re.compile(r"/wp-admin", re.I),
    re.compile(r"/wp-config", re.I),
    re.compile(r"/config\.php", re.I),
    re.compile(r"/phpmyadmin", re.I),
    re.compile(r"/\.\./", re.I),  # path traversal
    re.compile(r"/shell\.php", re.I),
    re.compile(r"/cmd\.asp", re.I),
    re.compile(r"/upload(ed)?s?/.*\.(php|asp|jsp|aspx)", re.I),
]


# ── IP State Tracking ───────────────────────────────────


class _IPState:
    """Per-IP sliding window state"""

    def __init__(self):
        self.requests: List[Tuple[float, str, int]] = []  # (timestamp, path, status)
        self.unique_paths: set = set()
        self.error_count: int = 0
        self.total_requests: int = 0
        self.tool_hits: List[str] = []
        self.last_seen: float = 0

    def prune(self, window: float):
        """Remove entries older than window (seconds)"""
        now = time.time()
        self.requests = [(t, p, s) for t, p, s in self.requests if now - t < window]
        self.unique_paths = {p for t, p, s in self.requests}


# ── Heuristic Engine ─────────────────────────────────────


class LogHeuristicEngine:
    """Behavior-level detection from web access logs"""

    def __init__(
        self,
        window_size: int = 300,
        brute_threshold: int = 50,
        scanner_threshold: int = 20,
        error_threshold: int = 30,
    ):
        """
        Args:
            window_size: sliding window in seconds (default 5 min)
            brute_threshold: max requests per path in window before flagging
            scanner_threshold: min unique paths in window before flagging scanner
            error_threshold: max 4xx/5xx errors in window before flagging
        """
        self.window_size = window_size
        self.brute_threshold = brute_threshold
        self.scanner_threshold = scanner_threshold
        self.error_threshold = error_threshold
        self._states: Dict[str, _IPState] = defaultdict(_IPState)
        self._lock = threading.Lock()
        self._total_analyzed = 0
        self._total_alerts = 0

    def feed_line(self, line: str) -> Optional[Dict]:
        """Feed a single log line. Returns detection event dict or None."""
        parsed = parse_log_line(line)
        if not parsed:
            return None
        return self.feed(parsed)

    def feed(self, entry: Dict) -> Optional[Dict]:
        """Feed a parsed log entry. Returns detection event dict or None."""
        ip = entry.get("ip", "")
        path = entry.get("path", "/")
        status = entry.get("status", 200)
        ua = entry.get("user_agent", "")
        ts = time.time()

        with self._lock:
            self._total_analyzed += 1
            state = self._states[ip]
            state.requests.append((ts, path, status))
            state.unique_paths.add(path)
            state.total_requests += 1
            state.last_seen = ts

            if status >= 400:
                state.error_count += 1

            # Check tool signatures
            for tool_name, pattern in _TOOL_SIGNATURES.items():
                if pattern.search(ua):
                    if tool_name not in state.tool_hits:
                        state.tool_hits.append(tool_name)

            # Prune old entries
            if len(state.requests) > 1000:
                state.prune(self.window_size)

            # Run detectors
            event = self._detect(ip, state, path, ua)
            if event:
                self._total_alerts += 1
            return event

    def _detect(self, ip: str, state: _IPState, current_path: str, ua: str) -> Optional[Dict]:
        """Run all detectors. Returns first matching event or None."""

        # Detector 1: Brute force — single path hit too many times
        path_counts = defaultdict(int)
        for _, p, _ in state.requests:
            path_counts[p] += 1
        for p, count in path_counts.items():
            if count >= self.brute_threshold:
                return {
                    "type": "brute_force",
                    "ip": ip,
                    "path": p,
                    "count": count,
                    "window_seconds": self.window_size,
                    "severity": "high" if count >= self.brute_threshold * 2 else "medium",
                    "timestamp": datetime.now().isoformat(),
                }

        # Detector 2: Scanner — too many unique paths
        if len(state.unique_paths) >= self.scanner_threshold:
            return {
                "type": "scanner",
                "ip": ip,
                "unique_paths": len(state.unique_paths),
                "total_requests": state.total_requests,
                "window_seconds": self.window_size,
                "severity": "medium",
                "timestamp": datetime.now().isoformat(),
            }

        # Detector 3: Error storm — too many 4xx/5xx
        if state.error_count >= self.error_threshold:
            return {
                "type": "error_storm",
                "ip": ip,
                "error_count": state.error_count,
                "window_seconds": self.window_size,
                "severity": "low",
                "timestamp": datetime.now().isoformat(),
            }

        # Detector 4: Known tool signature
        if state.tool_hits and state.total_requests > 3:
            return {
                "type": "known_tool",
                "ip": ip,
                "tools": list(state.tool_hits),
                "user_agent": ua[:200],
                "severity": "high",
                "timestamp": datetime.now().isoformat(),
            }

        # Detector 5: Suspicious path or extension
        ext = Path(current_path).suffix.lower()
        if ext in _SUSPICIOUS_EXTENSIONS:
            return {
                "type": "suspicious_path",
                "ip": ip,
                "path": current_path,
                "reason": f"Suspicious extension: {ext}",
                "severity": "medium",
                "timestamp": datetime.now().isoformat(),
            }

        for pattern in _SUSPICIOUS_PATHS:
            if pattern.search(current_path):
                return {
                    "type": "suspicious_path",
                    "ip": ip,
                    "path": current_path,
                    "reason": f"Matches pattern: {pattern.pattern}",
                    "severity": "medium",
                    "timestamp": datetime.now().isoformat(),
                }

        return None

    def feed_file(self, log_path: Path, tail: bool = False) -> List[Dict]:
        """Analyze an entire log file. Returns list of detection events."""
        events = []
        with open(log_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                event = self.feed_line(line)
                if event:
                    events.append(event)
        return events

    def get_stats(self) -> Dict:
        with self._lock:
            return {
                "ips_tracked": len(self._states),
                "total_analyzed": self._total_analyzed,
                "total_alerts": self._total_alerts,
                "window_size": self.window_size,
            }

    def cleanup(self):
        """Remove stale IP states"""
        with self._lock:
            stale = []
            now = time.time()
            for ip, state in list(self._states.items()):
                if now - state.last_seen > self.window_size * 4:
                    stale.append(ip)
            for ip in stale:
                del self._states[ip]
