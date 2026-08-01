"""JSON codec and best-effort SQLite shadow persistence for threat profiles."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Iterator, Mapping

from anteumbra.domain.service_ports import ThreatProfileRepositoryPort
from anteumbra.domain.site import SiteIdentity
from anteumbra.infrastructure.models import (
    AttackerProfile,
    AttackEvent,
    FileReputation,
    IPReputation,
)


@dataclass(slots=True)
class ThreatGraphSnapshot:
    profiles: dict[str, AttackerProfile]
    ip_table: dict[tuple[str, str], IPReputation]
    file_table: dict[tuple[str, str], FileReputation]


class ThreatGraphStore:
    """Persist a JSON source of truth with profile-only shadow recovery."""

    def __init__(
        self,
        shadow_repository: ThreatProfileRepositoryPort | None,
        logger: logging.Logger,
    ) -> None:
        self._shadow = shadow_repository
        self._logger = logger

    def persist(self, path: Path, snapshot: ThreatGraphSnapshot) -> None:
        data = encode_snapshot(snapshot)
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(".tmp")
        with temporary.open("w", encoding="utf-8") as handle:
            json.dump(data, handle, ensure_ascii=False, indent=2)
        temporary.replace(path)
        self._shadow_persist(data)

    def _shadow_persist(self, data: dict[str, Any]) -> None:
        if self._shadow is None:
            return
        for profile_id, profile_data in data.get("profiles", {}).items():
            try:
                self._shadow.save(profile_id, dict(profile_data))
            except Exception:
                self._logger.warning(
                    "Threat profile SQLite shadow write failed for %s",
                    profile_id,
                    exc_info=True,
                )

    def load(self, path: Path | None) -> ThreatGraphSnapshot | None:
        data: dict[str, Any] | None = None
        if path and path.exists():
            try:
                with path.open("r", encoding="utf-8") as handle:
                    data = json.load(handle)
            except Exception:
                self._logger.warning(
                    "[THREAT_GRAPH] Failed to load persisted JSON from %s",
                    path,
                    exc_info=True,
                )

        if data is None and self._shadow is not None:
            try:
                profile_records = self._shadow.list_all(limit=999999)
                if profile_records:
                    profiles = {
                        record["profile_id"]: record
                        for record in profile_records
                        if record.get("profile_id")
                    }
                    data = {
                        "schema_version": 2,
                        "profiles": profiles,
                        "ip_table": {},
                        "file_table": {},
                    }
                    self._logger.warning(
                        "[THREAT_GRAPH] Recovered profiles from SQLite shadow; "
                        "IP reputation data requires the JSON backup"
                    )
            except Exception:
                self._logger.debug("SQLite shadow load failed", exc_info=True)

        return decode_snapshot(data, self._logger) if data is not None else None

    def close(self) -> None:
        close = getattr(self._shadow, "close", None)
        if callable(close):
            close()


def encode_snapshot(snapshot: ThreatGraphSnapshot) -> dict[str, Any]:
    ip_table: dict[str, dict[str, dict[str, Any]]] = {}
    for reputation in snapshot.ip_table.values():
        ip_table.setdefault(reputation.site_id, {})[reputation.ip] = ip_to_data(
            reputation
        )

    file_table: dict[str, dict[str, dict[str, Any]]] = {}
    for reputation in snapshot.file_table.values():
        file_table.setdefault(reputation.site_id, {})[
            path_key(reputation.path)
        ] = file_to_data(reputation)

    return {
        "schema_version": 2,
        "profiles": {
            profile_id: profile_to_data(profile)
            for profile_id, profile in snapshot.profiles.items()
        },
        "ip_table": ip_table,
        "file_table": file_table,
    }


def decode_snapshot(
    data: Mapping[str, Any],
    logger: logging.Logger,
) -> ThreatGraphSnapshot:
    profiles: dict[str, AttackerProfile] = {}
    raw_profiles = data.get("profiles", {})
    if isinstance(raw_profiles, Mapping):
        for profile_id, raw_profile in raw_profiles.items():
            if not isinstance(raw_profile, Mapping):
                continue
            try:
                profile = profile_from_data(str(profile_id), raw_profile)
                profiles[profile.profile_id] = profile
            except Exception:
                logger.warning(
                    "[THREAT_GRAPH] Skipping invalid profile %s",
                    profile_id,
                    exc_info=True,
                )

    ip_table: dict[tuple[str, str], IPReputation] = {}
    for site_id, ip, raw_reputation in persisted_records(
        data.get("ip_table", {}), identity_field="ip"
    ):
        try:
            reputation = ip_from_data(
                ip, with_site_defaults(raw_reputation, site_id)
            )
            ip_table[(reputation.site_id, reputation.ip)] = reputation
        except Exception:
            logger.warning(
                "[THREAT_GRAPH] Skipping invalid IP reputation %s/%s",
                site_id,
                ip,
                exc_info=True,
            )

    file_table: dict[tuple[str, str], FileReputation] = {}
    for site_id, record_path, raw_reputation in persisted_records(
        data.get("file_table", {}), identity_field="path"
    ):
        try:
            reputation = file_from_data(
                record_path, with_site_defaults(raw_reputation, site_id)
            )
            file_table[(reputation.site_id, path_key(reputation.path))] = reputation
        except Exception:
            logger.warning(
                "[THREAT_GRAPH] Skipping invalid file reputation %s/%s",
                site_id,
                record_path,
                exc_info=True,
            )
    return ThreatGraphSnapshot(profiles, ip_table, file_table)


def site_identity(record: Mapping[str, Any]) -> SiteIdentity:
    site_id = str(record.get("site_id") or "").strip()
    site_name = str(record.get("site_name") or "").strip()
    if not site_id and not site_name:
        return SiteIdentity.legacy()
    return SiteIdentity.from_values(site_id or None, site_name or site_id)


def path_key(path: str) -> str:
    return str(path).replace("\\", "/").casefold()


def with_site_defaults(
    record: Mapping[str, Any],
    site_id: str,
) -> dict[str, Any]:
    payload = dict(record)
    payload.setdefault("site_id", site_id)
    payload.setdefault(
        "site_name",
        SiteIdentity.legacy().site_name if site_id == "legacy" else site_id,
    )
    return payload


def parse_datetime(
    value: Any,
    *,
    default: datetime | None = None,
) -> datetime | None:
    if isinstance(value, datetime):
        return value
    if value:
        return datetime.fromisoformat(str(value))
    return default


def event_to_data(event: AttackEvent) -> dict[str, Any]:
    return {
        "timestamp": event.timestamp.isoformat(),
        "site_id": event.site_id,
        "site_name": event.site_name,
        "event_type": event.event_type,
        "src_ip": event.src_ip,
        "user_agent": event.user_agent,
        "url": event.url,
        "file_path": event.file_path,
        "waf_rule_id": event.waf_rule_id,
        "waf_score": event.waf_score,
    }


def event_from_data(data: Mapping[str, Any]) -> AttackEvent:
    site = site_identity(data)
    return AttackEvent(
        timestamp=parse_datetime(data.get("timestamp"), default=datetime.now()),
        site_id=site.site_id,
        site_name=site.site_name,
        event_type=str(data.get("event_type", "")),
        src_ip=str(data.get("src_ip", "")),
        user_agent=str(data.get("user_agent", "")),
        url=str(data.get("url", "")),
        file_path=str(data.get("file_path", "")),
        waf_rule_id=str(data.get("waf_rule_id", "")),
        waf_score=float(data.get("waf_score", 0)),
    )


def profile_to_data(profile: AttackerProfile) -> dict[str, Any]:
    return {
        "profile_id": profile.profile_id,
        "site_id": profile.site_id,
        "site_name": profile.site_name,
        "created_at": profile.created_at.isoformat(),
        "updated_at": profile.updated_at.isoformat(),
        "ip_pool": sorted(profile.ip_pool),
        "target_files": sorted(profile.target_files),
        "target_urls": sorted(profile.target_urls),
        "ua_fingerprint": profile.ua_fingerprint,
        "tool_signature": profile.tool_signature,
        "file_pattern": profile.file_pattern,
        "attack_chain": [event_to_data(event) for event in profile.attack_chain],
        "risk_score": profile.risk_score,
        "raw_score": profile.raw_score,
        "decay_factor": profile.decay_factor,
        "last_decayed": (
            profile.last_decayed.isoformat() if profile.last_decayed else None
        ),
        "last_seen": profile.last_seen.isoformat() if profile.last_seen else None,
        "status": profile.status,
        "last_alert_sent": (
            profile.last_alert_sent.isoformat() if profile.last_alert_sent else None
        ),
        "alert_cooldown_seconds": profile.alert_cooldown_seconds,
    }


def profile_from_data(
    profile_id: str,
    data: Mapping[str, Any],
) -> AttackerProfile:
    site = site_identity(data)
    created_at = parse_datetime(data.get("created_at"), default=datetime.now())
    updated_at = parse_datetime(data.get("updated_at"), default=created_at)
    return AttackerProfile(
        profile_id=str(data.get("profile_id") or profile_id),
        created_at=created_at,
        updated_at=updated_at,
        site_id=site.site_id,
        site_name=site.site_name,
        ip_pool=set(data.get("ip_pool", [])),
        target_files=set(data.get("target_files", [])),
        target_urls=set(data.get("target_urls", [])),
        ua_fingerprint=str(data.get("ua_fingerprint", "")),
        tool_signature=str(data.get("tool_signature", "")),
        file_pattern=str(data.get("file_pattern", "")),
        attack_chain=[
            event_from_data(event)
            for event in data.get("attack_chain", [])
            if isinstance(event, Mapping)
        ],
        risk_score=float(data.get("risk_score", 0)),
        raw_score=float(data.get("raw_score", data.get("risk_score", 0))),
        decay_factor=float(data.get("decay_factor", 1.0)),
        last_decayed=parse_datetime(data.get("last_decayed")),
        last_seen=parse_datetime(data.get("last_seen")),
        status=str(data.get("status", "active")),
        last_alert_sent=parse_datetime(data.get("last_alert_sent")),
        alert_cooldown_seconds=int(data.get("alert_cooldown_seconds", 60)),
    )


def ip_to_data(reputation: IPReputation) -> dict[str, Any]:
    return {
        "ip": reputation.ip,
        "site_id": reputation.site_id,
        "site_name": reputation.site_name,
        "first_seen": reputation.first_seen.isoformat(),
        "last_seen": reputation.last_seen.isoformat(),
        "event_count": reputation.event_count,
        "unique_files": sorted(reputation.unique_files),
        "unique_urls": sorted(reputation.unique_urls),
        "waf_score_avg": reputation.waf_score_avg,
        "reputation_score": reputation.reputation_score,
        "cluster_level": reputation.cluster_level,
        "profile_ids": sorted(reputation.profile_ids),
    }


def ip_from_data(ip: str, data: Mapping[str, Any]) -> IPReputation:
    site = site_identity(data)
    return IPReputation(
        ip=str(data.get("ip") or ip),
        first_seen=parse_datetime(data.get("first_seen"), default=datetime.now()),
        last_seen=parse_datetime(data.get("last_seen"), default=datetime.now()),
        site_id=site.site_id,
        site_name=site.site_name,
        event_count=int(data.get("event_count", 0)),
        unique_files=set(data.get("unique_files", [])),
        unique_urls=set(data.get("unique_urls", [])),
        waf_score_avg=float(data.get("waf_score_avg", 0)),
        reputation_score=float(data.get("reputation_score", 0)),
        cluster_level=int(data.get("cluster_level", 0)),
        profile_ids=set(data.get("profile_ids", [])),
    )


def file_to_data(reputation: FileReputation) -> dict[str, Any]:
    return {
        "path": reputation.path,
        "site_id": reputation.site_id,
        "site_name": reputation.site_name,
        "first_seen": reputation.first_seen.isoformat(),
        "last_seen": reputation.last_seen.isoformat(),
        "detection_count": reputation.detection_count,
        "unique_ips": sorted(reputation.unique_ips),
        "yara_rules": list(reputation.yara_rules),
        "file_exists": reputation.file_exists,
        "quarantine_id": reputation.quarantine_id,
        "cluster_id": reputation.cluster_id,
        "profile_ids": sorted(reputation.profile_ids),
    }


def file_from_data(path: str, data: Mapping[str, Any]) -> FileReputation:
    site = site_identity(data)
    return FileReputation(
        path=str(data.get("path") or path),
        first_seen=parse_datetime(data.get("first_seen"), default=datetime.now()),
        last_seen=parse_datetime(data.get("last_seen"), default=datetime.now()),
        site_id=site.site_id,
        site_name=site.site_name,
        detection_count=int(data.get("detection_count", 0)),
        unique_ips=set(data.get("unique_ips", [])),
        yara_rules=list(data.get("yara_rules", [])),
        file_exists=bool(data.get("file_exists", True)),
        quarantine_id=data.get("quarantine_id"),
        cluster_id=data.get("cluster_id"),
        profile_ids=set(data.get("profile_ids", [])),
    )


def persisted_records(
    table: Any,
    *,
    identity_field: str,
) -> Iterator[tuple[str, str, Mapping[str, Any]]]:
    """Yield schema-v2 nested records and legacy flat records uniformly."""
    if not isinstance(table, Mapping):
        return
    for outer_key, outer_value in table.items():
        if not isinstance(outer_value, Mapping):
            continue
        if identity_field in outer_value and (
            "first_seen" in outer_value or "last_seen" in outer_value
        ):
            yield "legacy", str(outer_key), outer_value
            continue
        for record_key, record in outer_value.items():
            if isinstance(record, Mapping):
                yield str(outer_key), str(record_key), record
