"""Stable site identity and path-to-site resolution contracts.

The monitoring pipeline must never infer a site from a display name at the
point where it persists or emits security data. This module keeps that
identity explicit and is deliberately independent of Flask, configuration,
and filesystem access.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable

_SITE_ID_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,62})?$")


def derive_site_id(name: str) -> str:
    """Derive a stable compatibility ID for a site without an explicit ID."""
    normalized = re.sub(r"[^a-z0-9]+", "-", str(name).strip().lower())
    normalized = normalized.strip("-")[:63].rstrip("-")
    return normalized or "site"


@dataclass(frozen=True)
class SiteIdentity:
    """The stable identifier and human-readable name of one monitored site."""

    site_id: str
    site_name: str

    def __post_init__(self) -> None:
        site_id = str(self.site_id).strip().lower()
        site_name = str(self.site_name).strip()
        if not _SITE_ID_PATTERN.fullmatch(site_id):
            raise ValueError(
                "site_id must use lowercase letters, digits, and hyphens "
                "and be at most 63 characters"
            )
        if not site_name:
            raise ValueError("site_name must not be empty")
        object.__setattr__(self, "site_id", site_id)
        object.__setattr__(self, "site_name", site_name)

    @classmethod
    def from_values(cls, site_id: str | None, site_name: str) -> "SiteIdentity":
        """Create an identity, deriving an ID only for legacy configurations."""
        return cls(site_id or derive_site_id(site_name), site_name)

    @classmethod
    def legacy(cls) -> "SiteIdentity":
        """Return the explicit bucket used for records outside configured roots."""
        return cls("legacy", "Legacy / unassigned")

    def as_dict(self) -> dict[str, str]:
        """Return the transport representation used by events and persistence."""
        return {"site_id": self.site_id, "site_name": self.site_name}


def _path_key(path: str) -> str:
    return str(path).replace("\\", "/").rstrip("/").casefold()


@dataclass(frozen=True)
class SiteRoot:
    """A configured filesystem root bound to one site identity."""

    identity: SiteIdentity
    root_path: str

    def __post_init__(self) -> None:
        root_path = _path_key(self.root_path)
        if not root_path:
            raise ValueError("site root_path must not be empty")
        object.__setattr__(self, "root_path", root_path)


class SiteResolver:
    """Resolve a file path to its most-specific configured site root."""

    def __init__(self, roots: Iterable[SiteRoot] = ()) -> None:
        by_id: dict[str, SiteRoot] = {}
        for root in roots:
            existing = by_id.get(root.identity.site_id)
            if existing is not None:
                raise ValueError(f"duplicate site_id: {root.identity.site_id}")
            by_id[root.identity.site_id] = root
        self._roots = tuple(
            sorted(by_id.values(), key=lambda item: len(item.root_path), reverse=True)
        )
        self._by_id = by_id

    @classmethod
    def from_websites(cls, websites: Iterable[object]) -> "SiteResolver":
        """Build a resolver from website-like objects without importing infrastructure."""
        roots: list[SiteRoot] = []
        for website in websites:
            name = str(getattr(website, "name", ""))
            path = getattr(website, "path", None)
            if not name or path is None:
                continue
            identity = SiteIdentity.from_values(getattr(website, "site_id", None), name)
            roots.append(SiteRoot(identity=identity, root_path=str(path)))
        return cls(roots)

    @property
    def identities(self) -> tuple[SiteIdentity, ...]:
        """Return configured identities in stable resolver order."""
        return tuple(root.identity for root in self._roots)

    def get(self, site_id: str) -> SiteIdentity | None:
        """Return one configured identity by ID."""
        root = self._by_id.get(str(site_id).strip().lower())
        return root.identity if root else None

    def resolve(self, file_path: str) -> SiteIdentity:
        """Resolve a path without touching the filesystem; unknown paths are legacy."""
        target = _path_key(file_path)
        for root in self._roots:
            prefix = root.root_path
            if target == prefix or target.startswith(f"{prefix}/"):
                return root.identity
        return SiteIdentity.legacy()
