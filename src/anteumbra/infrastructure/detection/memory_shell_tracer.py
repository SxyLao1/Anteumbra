"""Trace memory-shell detections back to likely webshell upload requests."""

from __future__ import annotations

import logging
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from anteumbra.domain.runtime import ConfigProviderPort
from anteumbra.infrastructure.detection.log_heuristic import parse_log_line


logger = logging.getLogger(__name__)

DEFAULT_LOOKBACK_HOURS = 24
WRITE_METHODS = {"POST", "PUT", "PATCH", "MKCOL"}
WEBSHELL_EXTENSIONS = {
    ".php",
    ".php5",
    ".phtml",
    ".asp",
    ".aspx",
    ".ashx",
    ".jsp",
    ".jspx",
    ".war",
    ".jar",
}
SUSPICIOUS_DIRECTORIES = {
    "/uploads/",
    "/upload/",
    "/files/",
    "/images/",
    "/wp-content/uploads/",
    "/wp-admin/",
    "/admin/",
    "/tmp/",
    "/druid/",
}

RegistryReader = Callable[..., list[dict[str, Any]]]


class MemoryShellTracer:
    """Correlate one source IP's writes with site-qualified Registry records."""

    def __init__(
        self,
        lookback_hours: int = DEFAULT_LOOKBACK_HOURS,
        *,
        registry_reader: RegistryReader | None = None,
        config_provider: ConfigProviderPort | None = None,
    ) -> None:
        if lookback_hours <= 0:
            raise ValueError("lookback_hours must be positive")
        self._lookback_hours = int(lookback_hours)
        self._registry_reader = registry_reader
        self._config = config_provider

    def trace(
        self,
        ip: str,
        detection_time: datetime | None = None,
        log_paths: list[Path] | None = None,
        *,
        site_id: str | None = None,
    ) -> dict[str, Any]:
        """Trace activity before detection within an optional site boundary."""
        end_time = self._as_utc(detection_time or datetime.now(timezone.utc))
        start_time = end_time - timedelta(hours=self._lookback_hours)
        selected_paths = (
            list(log_paths)
            if log_paths is not None
            else self._default_log_paths(site_id=site_id)
        )

        all_entries: list[dict[str, Any]] = []
        for log_path in selected_paths:
            if log_path.exists():
                all_entries.extend(
                    self._extract_entries(log_path, ip, start_time, end_time)
                )

        write_entries = [
            entry
            for entry in all_entries
            if str(entry.get("method", "")).upper() in WRITE_METHODS
        ]
        candidates = self._rank_candidates(write_entries)
        matched = self._cross_reference(candidates, site_id=site_id)
        confidence = "high" if matched else ("medium" if candidates else "low")
        return {
            "found": bool(candidates),
            "ip": ip,
            "time": end_time.isoformat(),
            "site_id": site_id,
            "lb": self._lookback_hours,
            "total": len(all_entries),
            "writes": len(write_entries),
            "candidates": candidates[:20],
            "matched": matched,
            "confidence": confidence,
            "summary": self._summarize(len(candidates), matched),
        }

    def _extract_entries(
        self,
        log_path: Path,
        ip: str,
        start: datetime,
        end: datetime,
    ) -> list[dict[str, Any]]:
        """Extract entries for one IP inside an inclusive UTC window."""
        entries: list[dict[str, Any]] = []
        try:
            with log_path.open("r", encoding="utf-8", errors="replace") as handle:
                for raw_line in handle:
                    line = raw_line.strip()
                    if not line or ip not in line:
                        continue
                    parsed = parse_log_line(line)
                    if not parsed or parsed.get("ip") != ip:
                        continue
                    timestamp = self._parse_timestamp(str(parsed.get("timestamp", "")))
                    if timestamp is not None and start <= timestamp <= end:
                        entries.append({**parsed, "_parsed_ts": timestamp})
        except OSError as exc:
            logger.warning("MemoryShellTracer could not read %s: %s", log_path, exc)
        entries.sort(
            key=lambda entry: entry.get(
                "_parsed_ts", datetime.min.replace(tzinfo=timezone.utc)
            )
        )
        return entries

    @staticmethod
    def _rank_candidates(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Score and deduplicate likely webshell upload requests."""
        scored: list[dict[str, Any]] = []
        seen: set[tuple[str, str]] = set()
        for entry in entries:
            path = str(entry.get("path", ""))
            extension = Path(path).suffix.lower()
            method = str(entry.get("method", "")).upper()
            try:
                status = int(entry.get("status", 0))
            except (TypeError, ValueError):
                status = 0

            score = 0
            if extension in WEBSHELL_EXTENSIONS:
                score += 3
            if any(directory in path.lower() for directory in SUSPICIOUS_DIRECTORIES):
                score += 2
            if 200 <= status < 300:
                score += 1
            if status == 201:
                score += 2
            if method == "POST" and extension in WEBSHELL_EXTENSIONS:
                score += 2

            key = (path, method)
            if score <= 0 or key in seen:
                continue
            seen.add(key)
            scored.append(
                {
                    "path": path,
                    "method": method,
                    "timestamp": entry.get("timestamp", ""),
                    "status": status,
                    "score": score,
                    "user_agent": str(entry.get("user_agent", ""))[:200],
                }
            )

        scored.sort(key=lambda item: item["score"], reverse=True)
        return scored

    def _cross_reference(
        self,
        candidates: list[dict[str, Any]],
        *,
        site_id: str | None,
    ) -> dict[str, Any] | None:
        """Match URL suffixes to Registry paths without crossing site boundaries."""
        if not candidates or self._registry_reader is None:
            return None
        try:
            records = self._registry_reader(
                include_deleted=True,
                include_false_positive=False,
                site_id=site_id,
            )
        except Exception:
            logger.warning("MemoryShellTracer Registry lookup failed", exc_info=True)
            return None

        known_paths = [
            (self._path_key(str(record.get("file_path", ""))), record)
            for record in records
            if record.get("file_path")
        ]
        for candidate in candidates:
            candidate_key = self._path_key(candidate["path"])
            for known_path, record in known_paths:
                if known_path == candidate_key:
                    return self._match_payload(record, "exact")
                if known_path.endswith(candidate_key):
                    return self._match_payload(record, "suffix")
        return None

    def _default_log_paths(self, *, site_id: str | None) -> list[Path]:
        """Return configured site logs, falling back to common server paths."""
        paths: list[Path] = []
        if self._config is not None:
            for website in self._config.get_enabled_websites():
                website_site_id = str(getattr(website, "site_id", "")).lower()
                if site_id and website_site_id != str(site_id).strip().lower():
                    continue
                log_config = getattr(website, "log_config", {}) or {}
                configured = log_config.get("access_log_path")
                if configured:
                    path = Path(configured)
                    if path not in paths:
                        paths.append(path)

        if not paths:
            for candidate in (
                Path("/var/log/nginx/access.log"),
                Path("/var/log/apache2/access.log"),
            ):
                if candidate.exists() and candidate not in paths:
                    paths.append(candidate)
        return paths

    @staticmethod
    def _parse_timestamp(value: str) -> datetime | None:
        """Parse supported access-log timestamps into aware UTC datetimes."""
        for format_string in (
            "%d/%b/%Y:%H:%M:%S %z",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S",
        ):
            try:
                return MemoryShellTracer._as_utc(
                    datetime.strptime(value, format_string)
                )
            except ValueError:
                continue
        try:
            return MemoryShellTracer._as_utc(datetime.fromisoformat(value))
        except ValueError:
            return None

    @staticmethod
    def _as_utc(value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    @staticmethod
    def _path_key(value: str) -> str:
        return value.replace("\\", "/").casefold()

    @staticmethod
    def _match_payload(record: dict[str, Any], match: str) -> dict[str, Any]:
        return {
            "fp": record.get("file_path", ""),
            "detected": record.get("detected_at", ""),
            "feat": record.get("features", []),
            "qid": record.get("quarantine_id", ""),
            "site_id": record.get("site_id"),
            "match": match,
        }

    @staticmethod
    def _summarize(
        candidate_count: int,
        matched: dict[str, Any] | None,
    ) -> str:
        if matched:
            return (
                f"Memory shell traced to {matched['fp']} "
                f"(detected {matched['detected']})"
            )
        if candidate_count:
            return f"{candidate_count} suspicious upload(s), none matched known records"
        return "No upload activity found in access logs"


def trace_memory_shell(
    ip: str,
    detection_time: datetime | None = None,
    log_paths: list[Path] | None = None,
    *,
    site_id: str | None = None,
    registry_reader: RegistryReader | None = None,
    config_provider: ConfigProviderPort | None = None,
) -> dict[str, Any]:
    """Run a one-shot trace with explicitly supplied runtime dependencies."""
    tracer = MemoryShellTracer(
        registry_reader=registry_reader,
        config_provider=config_provider,
    )
    return tracer.trace(
        ip,
        detection_time,
        log_paths=log_paths,
        site_id=site_id,
    )


def emit_critical_alert(
    trace_result: dict[str, Any],
    *,
    notifier: Any,
    siem_exporter: Any,
) -> bool:
    """Emit SIEM and notification output for a memory-shell detection."""
    try:
        matched = trace_result.get("matched")
        title = "MEMORY SHELL: " + (
            Path(matched["fp"]).name if matched else trace_result["ip"]
        )
        lines = [
            "IP: " + trace_result["ip"],
            "Time: " + trace_result["time"],
            "Confidence: " + trace_result["confidence"],
            "",
        ]
        if matched:
            lines.extend(
                [
                    "WebShell: " + matched["fp"],
                    "Detected: " + matched["detected"],
                    "Features: " + ", ".join(matched["feat"]),
                    "Quarantined: " + ("Yes" if matched.get("qid") else "No"),
                    "",
                ]
            )
        if trace_result.get("candidates"):
            lines.append("Upload candidates:")
            for candidate in trace_result["candidates"][:5]:
                lines.append(
                    f"  {candidate['method']} {candidate['path']} -> "
                    f"{candidate['status']} (score: {candidate['score']})"
                )

        try:
            siem_exporter.emit_detection(
                {
                    "id": "memshell-" + trace_result["ip"],
                    "detected_at": trace_result["time"],
                    "file_path": matched.get("fp", "") if matched else "",
                    "features": matched.get("feat", []) if matched else [],
                    "source_ip": trace_result["ip"],
                    "site_id": trace_result.get("site_id"),
                },
                category="memory.shell.detected",
            )
        except Exception:
            logger.debug("MemoryShellTracer SIEM emit failed", exc_info=True)

        body = "\n".join(lines)
        notifier.send_alert(f"{title}\n{body}", level="CRITICAL")
        logger.critical(
            "MemoryShellTracer sent a critical alert for %s", trace_result["ip"]
        )
        return True
    except Exception:
        logger.error("MemoryShellTracer alert failed", exc_info=True)
        return False
