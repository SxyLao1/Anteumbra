# -*- coding: utf-8 -*-
"""
v1.9.5: Memory Shell Tracer — Fixed code quality (v1.9.5.1)

When a memory shell is detected, trace back through access logs
to find the original WebShell file that deployed it.

Chain: memory shell detection -> access log analysis -> file match -> CRITICAL alert

Changes from audit (v1.9.5):
  - Replaced self -> s with proper self convention
  - Replaced bare except: pass with explicit Exception + logger.debug
  - Replaced single-letter variable names with descriptive names
  - Fixed timezone handling: normalize to UTC instead of strip tzinfo
  - Added docstrings to all methods
"""
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional, List, Dict

from anteumbra.infrastructure.detection.log_heuristic import parse_log_line

logger = logging.getLogger(__name__)

DEFAULT_LOOKBACK_HOURS = 24
WRITE_METHODS = {"POST", "PUT", "PATCH", "MKCOL"}
WEBSHELL_EXTENSIONS = {".php", ".php5", ".phtml", ".asp", ".aspx", ".ashx",
                       ".jsp", ".jspx", ".war", ".jar"}
SUSPICIOUS_DIRECTORIES = ["/uploads/", "/upload/", "/files/", "/images/",
                          "/wp-content/uploads/", "/wp-admin/", "/admin/",
                          "/tmp/", "/druid/"]


class MemoryShellTracer:
    """Trace memory shell detections back to origin via access logs."""

    def __init__(self, lookback_hours: int = DEFAULT_LOOKBACK_HOURS):
        self._lookback_hours = lookback_hours

    def trace(self, ip: str, detection_time: Optional[datetime] = None,
              log_paths: Optional[List[Path]] = None) -> Dict:
        """Trace an IP's activity before memory shell detection.

        Returns dict with keys: found, ip, time, lb, total, writes,
        candidates, matched, confidence, summary.
        """
        if detection_time is None:
            detection_time = datetime.now(timezone.utc)
        start_time = detection_time - timedelta(hours=self._lookback_hours)

        if log_paths is None:
            log_paths = self._default_log_paths()

        all_entries = []
        for log_path in log_paths:
            if not log_path.exists():
                continue
            entries = self._extract_entries(log_path, ip, start_time, detection_time)
            all_entries.extend(entries)

        write_entries = [e for e in all_entries
                         if e.get("method", "").upper() in WRITE_METHODS]
        candidates = self._rank_candidates(write_entries)
        matched = self._cross_reference(candidates)

        confidence = "high" if matched else ("medium" if candidates else "low")
        return {
            "found": len(candidates) > 0,
            "ip": ip,
            "time": detection_time.isoformat(),
            "lb": self._lookback_hours,
            "total": len(all_entries),
            "writes": len(write_entries),
            "candidates": candidates[:20],
            "matched": matched,
            "confidence": confidence,
            "summary": self._summarize(ip, len(candidates), matched),
        }

    def _extract_entries(self, log_path: Path, ip: str,
                         start: datetime, end: datetime) -> List[Dict]:
        """Extract all log entries for a specific IP within a time window."""
        entries = []
        try:
            with open(log_path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line or ip not in line:
                        continue
                    parsed = parse_log_line(line)
                    if not parsed or parsed.get("ip") != ip:
                        continue
                    try:
                        timestamp = self._parse_timestamp(parsed.get("timestamp", ""))
                        if timestamp and start <= timestamp <= end:
                            entries.append({**parsed, "_parsed_ts": timestamp})
                    except Exception as exc:
                        logger.debug("MemoryShellTracer: failed to parse line: %s...: %s",
                                    line[:100], exc)
        except OSError as exc:
            logger.warning("MemoryShellTracer: failed to read %s: %s", log_path, exc)
        entries.sort(key=lambda e: e.get("_parsed_ts", datetime.min))
        return entries

    def _rank_candidates(self, entries: List[Dict]) -> List[Dict]:
        """Score and rank entries by likelihood of being a WebShell upload."""
        scored = []
        seen_keys = set()
        for entry in entries:
            path = entry.get("path", "")
            ext = Path(path).suffix.lower()
            method = entry.get("method", "").upper()
            status = entry.get("status", 0)

            score = 0
            if ext in WEBSHELL_EXTENSIONS:
                score += 3
            if any(directory in path.lower() for directory in SUSPICIOUS_DIRECTORIES):
                score += 2
            if 200 <= status < 300:
                score += 1  # Successful HTTP response
            if status == 201:
                score += 2  # Resource created
            if method == "POST" and ext in WEBSHELL_EXTENSIONS:
                score += 2  # POST to executable extension = high confidence

            if score > 0:
                dedup_key = f"{path}|{method}"
                if dedup_key not in seen_keys:
                    seen_keys.add(dedup_key)
                    scored.append({
                        "path": path,
                        "method": method,
                        "timestamp": entry.get("timestamp", ""),
                        "status": status,
                        "score": score,
                        "user_agent": entry.get("user_agent", "")[:200],
                    })

        scored.sort(key=lambda x: x["score"], reverse=True)
        return scored

    def _cross_reference(self, candidates: List[Dict]) -> Optional[Dict]:
        """Cross-reference upload candidates with Anteumbra detection records."""
        if not candidates:
            return None
        try:
            from anteumbra.infrastructure.suspicious_registry import get_all
            records = get_all(include_deleted=False)
            known_paths = {r.get("file_path", ""): r for r in records}

            for candidate in candidates:
                path = candidate["path"]
                if path in known_paths:
                    rec = known_paths[path]
                    return {
                        "fp": path,
                        "detected": rec.get("detected_at", ""),
                        "feat": rec.get("features", []),
                        "qid": rec.get("quarantine_id", ""),
                        "match": "exact",
                    }
                # Try normalized path match (Windows backslash / Unix forward slash)
                normalized = path.replace("/", "\\")
                for known_path, record in known_paths.items():
                    if known_path.endswith(normalized) or normalized.endswith(
                        known_path.replace("/", "\\")):
                        return {
                            "fp": known_path,
                            "detected": record.get("detected_at", ""),
                            "feat": record.get("features", []),
                            "qid": record.get("quarantine_id", ""),
                            "match": "partial",
                        }
        except Exception as exc:
            logger.warning("MemoryShellTracer: cross-reference failed: %s", exc)
        return None

    def _default_log_paths(self) -> List[Path]:
        """Get default access log paths from config or common locations."""
        paths = []
        try:
            from anteumbra.infrastructure.config.registry import ConfigRegistry
            log_path = ConfigRegistry.get_raw_config().get(
                "website", {}).get("log_config", {}).get("access_log_path", "")
            if log_path:
                paths.append(Path(log_path))
        except Exception as exc:
            logger.debug("MemoryShellTracer: config lookup failed: %s", exc)
        for candidate in ["/var/log/nginx/access.log", "/var/log/apache2/access.log"]:
            p = Path(candidate)
            if p.exists() and p not in paths:
                paths.append(p)
        return paths

    @staticmethod
    def _parse_timestamp(timestamp_str: str) -> Optional[datetime]:
        """Parse common log timestamp formats, normalizing to UTC."""
        formats = [
            "%d/%b/%Y:%H:%M:%S %z",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S",
        ]
        for fmt in formats:
            try:
                dt = datetime.strptime(timestamp_str, fmt)
                # Normalize to UTC for consistent comparison
                if dt.tzinfo is not None:
                    dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
                return dt
            except ValueError:
                continue
        # Fallback: strip timezone and try ISO prefix
        try:
            return datetime.strptime(timestamp_str[:19], "%Y-%m-%dT%H:%M:%S")
        except ValueError:
            return None

    @staticmethod
    def _summarize(ip: str, candidate_count: int, matched: Optional[Dict]) -> str:
        if matched:
            return f"Memory shell traced to {matched['fp']} (detected {matched['detected']})"
        if candidate_count > 0:
            return f"{candidate_count} suspicious upload(s), none matched known records"
        return "No upload activity found in access logs"


def trace_memory_shell(ip: str, detection_time: Optional[datetime] = None,
                       log_paths: Optional[List[Path]] = None) -> Dict:
    """Convenience function: one-shot trace."""
    return MemoryShellTracer().trace(ip, detection_time, log_paths=log_paths)


def emit_critical_alert(trace_result: Dict) -> bool:
    """Emit a CRITICAL alert for a confirmed memory shell detection."""
    try:
        from anteumbra.infrastructure.monitoring.notifier import get_notifier
        import logging as _logging
        notifier = get_notifier(_logging.getLogger("monitor.notifier"))

        matched = trace_result.get("matched")
        title = "MEMORY SHELL: "
        if matched:
            title += Path(matched["fp"]).name
        else:
            title += trace_result["ip"]

        lines = [
            "IP: " + trace_result["ip"],
            "Time: " + trace_result["time"],
            "Confidence: " + trace_result["confidence"],
            "",
        ]
        if matched:
            lines += [
                "WebShell: " + matched["fp"],
                "Detected: " + matched["detected"],
                "Features: " + ", ".join(matched["feat"]),
                "Quarantined: " + ("Yes" if matched.get("qid") else "No"),
                "",
            ]
        if trace_result.get("candidates"):
            lines.append("Upload candidates:")
            for c in trace_result["candidates"][:5]:
                lines.append(
                    f"  {c['method']} {c['path']} -> {c['status']} (score: {c['score']})"
                )

        body = "\n".join(lines)

        # Emit to SIEM
        try:
            from anteumbra.infrastructure.monitoring.siem_exporter import emit_detection_event
            emit_detection_event({
                "id": "memshell-" + trace_result["ip"],
                "detected_at": trace_result["time"],
                "file_path": matched.get("fp", "") if matched else "",
                "features": matched.get("feat", []) if matched else [],
                "source_ip": trace_result["ip"],
            }, category="memory.shell.detected")
        except Exception as exc:
            logger.debug("MemoryShellTracer: SIEM emit failed: %s", exc)

        notifier.send_alert(title, body, level="critical")
        logger.critical("MemoryShellTracer: CRITICAL alert sent for %s", trace_result["ip"])
        return True
    except Exception as exc:
        logger.error("MemoryShellTracer: alert failed: %s", exc)
        return False
