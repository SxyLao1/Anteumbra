"""Domain values and ports for IP blocking and its audit ledger."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Collection, Mapping, Protocol, Sequence

from anteumbra.domain.site import SiteIdentity


def canonical_ip(value: str) -> str:
    """Validate and return the canonical text form of an IPv4 or IPv6 address."""
    try:
        return ipaddress.ip_address(str(value).strip()).compressed
    except ValueError as exc:
        raise ValueError(f"invalid IP address: {value!r}") from exc


@dataclass(frozen=True)
class BlockDecision:
    """One site-owned request to block an address."""

    ip: str
    reason: str
    site: SiteIdentity
    profile_id: str = ""
    risk_score: float = 0.0
    duration_seconds: int = 86400
    permanent: bool = False
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def __post_init__(self) -> None:
        object.__setattr__(self, "ip", canonical_ip(self.ip))
        object.__setattr__(self, "reason", str(self.reason).strip())
        if self.duration_seconds < 0:
            raise ValueError("duration_seconds must not be negative")
        if not 0.0 <= float(self.risk_score) <= 1.0:
            raise ValueError("risk_score must be between 0 and 1")


@dataclass(frozen=True)
class BlockResult:
    """The outcome returned by one blocking device."""

    device_name: str
    success: bool
    message: str
    ip: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def __post_init__(self) -> None:
        object.__setattr__(self, "ip", canonical_ip(self.ip))


@dataclass(frozen=True)
class BlockLedgerEntry:
    """Site-qualified audit record for the latest state of one blocked IP."""

    ip: str
    site: SiteIdentity
    blocked_at: str
    source: str = "manual"
    reason: str = ""
    notes: str = ""
    blocked_by: str = "admin"
    profile_id: str = ""
    broadcast_devices: tuple[str, ...] = ()
    broadcast_status: str = "pending"
    status: str = "blocked"
    unblocked_at: str | None = None
    unblocked_by: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "ip", canonical_ip(self.ip))
        if self.status not in {"blocked", "unblocked"}:
            raise ValueError(f"invalid block ledger status: {self.status!r}")

    @property
    def record_id(self) -> str:
        """Return the stable persistence identity for this site/IP pair."""
        return f"{self.site.site_id}|{self.ip}"

    def as_dict(self) -> dict[str, object]:
        """Return the transport and persistence representation."""
        return {
            "record_id": self.record_id,
            "ip": self.ip,
            **self.site.as_dict(),
            "blocked_at": self.blocked_at,
            "source": self.source,
            "reason": self.reason,
            "notes": self.notes,
            "blocked_by": self.blocked_by,
            "profile_id": self.profile_id,
            "broadcast_devices": list(self.broadcast_devices),
            "broadcast_status": self.broadcast_status,
            "status": self.status,
            "unblocked_at": self.unblocked_at,
            "unblocked_by": self.unblocked_by,
        }

    @classmethod
    def from_mapping(cls, data: Mapping[str, object]) -> "BlockLedgerEntry":
        """Normalize one current or legacy persisted record."""
        site_id = str(data.get("site_id") or "").strip()
        site_name = str(data.get("site_name") or "").strip()
        site = (
            SiteIdentity.from_values(site_id, site_name or site_id)
            if site_id
            else SiteIdentity.legacy()
        )
        raw_devices = data.get("broadcast_devices", ())
        devices = (
            tuple(str(item) for item in raw_devices)
            if isinstance(raw_devices, (list, tuple, set))
            else ()
        )
        return cls(
            ip=str(data.get("ip", "")),
            site=site,
            blocked_at=str(data.get("blocked_at") or datetime.now(timezone.utc).isoformat()),
            source=str(data.get("source") or "manual"),
            reason=str(data.get("reason") or ""),
            notes=str(data.get("notes") or ""),
            blocked_by=str(data.get("blocked_by") or "admin"),
            profile_id=str(data.get("profile_id") or ""),
            broadcast_devices=devices,
            broadcast_status=str(data.get("broadcast_status") or "pending"),
            status=str(data.get("status") or "blocked"),
            unblocked_at=(str(data["unblocked_at"]) if data.get("unblocked_at") else None),
            unblocked_by=(str(data["unblocked_by"]) if data.get("unblocked_by") else None),
        )


class IPBlockerPort(Protocol):
    """Broadcast block decisions without exposing device implementations."""

    @property
    def enabled(self) -> bool:
        """Return whether blocking is enabled for this runtime."""

    @property
    def auto_block_enabled(self) -> bool:
        """Return whether score-driven automatic blocking is enabled."""

    @property
    def auto_block_min_score(self) -> float:
        """Return the configured automatic blocking threshold."""

    @property
    def device_count(self) -> int:
        """Return the configured device count."""

    @property
    def device_names(self) -> tuple[str, ...]:
        """Return configured device names in broadcast order."""

    @property
    def is_running(self) -> bool:
        """Return whether the retry worker is alive."""

    def start(self) -> None:
        """Start owned background resources."""

    def stop(self) -> None:
        """Stop owned background resources."""

    def block(
        self,
        ips: Sequence[str],
        *,
        reason: str,
        site: SiteIdentity,
        profile_id: str = "",
        risk_score: float = 0.0,
        permanent: bool = False,
        device_names: Collection[str] | None = None,
    ) -> list[BlockResult]:
        """Block addresses on all or selected devices."""

    def unblock(
        self,
        ips: Sequence[str],
        *,
        device_names: Collection[str] | None = None,
    ) -> list[BlockResult]:
        """Unblock addresses on all or selected devices."""

    def get_blocklist(self) -> list[dict[str, str]]:
        """Return addresses exposed by devices that support enumeration."""

    def get_history(self, limit: int = 50) -> list[dict[str, object]]:
        """Return recent device outcomes."""

    def get_retry_queue_status(self) -> dict[str, object]:
        """Return retry worker state."""

    def device_status(self) -> list[dict[str, object]]:
        """Return configured device availability."""


class BlockLedgerPort(Protocol):
    """Persist and query site-qualified IP blocking audit records."""

    def add_entry(
        self,
        ip: str,
        *,
        site: SiteIdentity,
        source: str = "manual",
        reason: str = "",
        profile_id: str = "",
        blocked_by: str = "admin",
        broadcast_results: Sequence[Mapping[str, object]] | None = None,
    ) -> dict[str, object]:
        """Create or replace the current record for one site/IP pair."""

    def mark_unblocked(
        self,
        ip: str,
        *,
        site_id: str,
        unblocked_by: str = "admin",
    ) -> bool:
        """Mark a retained record unblocked."""

    def update_notes(self, ip: str, notes: str, *, site_id: str) -> bool:
        """Update one site-qualified record's notes."""

    def remove_entry(self, ip: str, *, site_id: str) -> bool:
        """Permanently delete one site-qualified record."""

    def get_by_ip(self, ip: str, *, site_id: str) -> dict[str, object] | None:
        """Return one unambiguous site/IP record."""

    def get_entries(
        self,
        *,
        limit: int = 50,
        offset: int = 0,
        source_filter: str = "",
        search: str = "",
        site_id: str | None = None,
        status: str | None = None,
    ) -> tuple[list[dict[str, object]], int]:
        """Return a filtered page of records."""

    def get_stats(self, *, site_id: str | None = None) -> dict[str, int]:
        """Return aggregate or site-scoped counters."""

    def export_ledger(self, fmt: str = "json", *, site_id: str | None = None) -> str:
        """Export aggregate or site-scoped records."""

    def reload(self) -> None:
        """Reload authoritative persistence."""

    def close(self) -> None:
        """Release owned persistence resources."""
