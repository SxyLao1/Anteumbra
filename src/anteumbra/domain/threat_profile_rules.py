"""Pure attacker-profile identity, scoring, merge, and decay rules."""

from __future__ import annotations

import hashlib
import re
from datetime import datetime
from typing import Any, Protocol

from anteumbra.domain.site import SiteIdentity


class MutableThreatProfile(Protocol):
    site_id: str
    ip_pool: set[str]
    target_files: set[str]
    target_urls: set[str]
    attack_chain: list[Any]
    risk_score: float
    raw_score: float
    updated_at: datetime
    last_seen: datetime | None
    last_decayed: datetime | None
    decay_factor: float
    status: str


def normalize_user_agent(user_agent: str) -> str:
    if not user_agent:
        return "empty"
    normalized = user_agent.lower()
    signatures = [
        ("antsword", "antsword"),
        ("behinder", "behinder"),
        ("godzilla", "godzilla"),
        ("sqlmap", "sqlmap"),
        ("python-requests", "python-requests"),
        ("nmap", "nmap"),
        ("burp", "burpsuite"),
        ("chrome", "browser"),
        ("firefox", "browser"),
    ]
    for tool, signature in signatures:
        if tool in normalized:
            return signature
    stripped = re.sub(r"\d+\.\d+(\.\d+)?", "", normalized)
    return stripped.strip().split("/")[0][:20] or "unknown"


def normalize_url_pattern(url: str) -> str:
    if not url:
        return "/"
    path = url.split("?")[0]
    path = re.sub(r"_\d+\.", "_{id}.", path)
    path = re.sub(r"/\d+/", "/{id}/", path)
    path = re.sub(r"/\d+$", "/{id}", path)
    return re.sub(r"\.(php|jsp|asp|aspx|jspx)", ".{script}", path)


def generate_profile_id(
    user_agent: str,
    time_window_hours: int,
    *,
    site_id: str,
    site_name: str,
    observed_at: datetime,
) -> str:
    if time_window_hours <= 0:
        raise ValueError("time_window_hours must be positive")
    identity = SiteIdentity.from_values(site_id, site_name or site_id)
    hour_block = observed_at.hour // time_window_hours
    time_bucket = observed_at.strftime(f"%Y%m%d{hour_block:02d}")
    features = f"{identity.site_id}|{normalize_user_agent(user_agent)}|{time_bucket}"
    return hashlib.sha256(features.encode()).hexdigest()[:16]


def calculate_risk_score(raw_score: float, ip_count: int, url_count: int) -> float:
    ip_diversity_bonus = min(ip_count * 0.005, 0.5)
    url_diversity_bonus = min(url_count * 0.02, 0.3)
    return min(raw_score + ip_diversity_bonus + url_diversity_bonus, 1.0)


def cluster_level(event_count: int) -> int:
    if event_count > 100:
        return 3
    if event_count > 10:
        return 2
    if event_count > 1:
        return 1
    return 0


def merge_profile_into(
    primary: MutableThreatProfile,
    secondary: MutableThreatProfile,
    *,
    merged_at: datetime,
) -> None:
    primary.ip_pool |= secondary.ip_pool
    primary.target_files |= secondary.target_files
    primary.target_urls |= secondary.target_urls
    primary.attack_chain.extend(secondary.attack_chain)
    primary.attack_chain.sort(key=lambda event: event.timestamp)
    primary.risk_score = max(primary.risk_score, secondary.risk_score)
    primary.raw_score = max(primary.raw_score, secondary.raw_score)
    primary.updated_at = merged_at


def decay_profile(profile: MutableThreatProfile, now: datetime) -> bool:
    """Apply inactivity decay and return whether the profile expired."""
    if not profile.last_seen:
        return False
    delta_hours = (now - profile.last_seen).total_seconds() / 3600
    if delta_hours >= 72:
        profile.risk_score = profile.raw_score * 0.1
        profile.decay_factor = 0.1
        profile.status = "dormant"
    elif delta_hours >= 24:
        profile.risk_score = profile.raw_score * 0.5
        profile.decay_factor = 0.5
    profile.last_decayed = now
    return delta_hours >= 168
