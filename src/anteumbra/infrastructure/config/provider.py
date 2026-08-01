"""Instance-owned TOML configuration and site resolution."""

from __future__ import annotations

import copy
import logging
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping

from anteumbra.domain.site import SiteIdentity, SiteResolver
from anteumbra.infrastructure.config.install_registry import get_install_info
from anteumbra.infrastructure.config.loader import load_toml_config
from anteumbra.infrastructure.models import ScanOptions, Website
from anteumbra.infrastructure.utils.path_utils import normalize_path

logger = logging.getLogger(__name__)
_RESERVED_CONFIG_SITE_IDS = {"legacy"}


@dataclass(frozen=True)
class ConfigSnapshot:
    """One atomically published configuration generation."""

    path: Path
    values: dict[str, Any]
    websites: tuple[Website, ...]
    resolver: SiteResolver
    generation: int


def resolve_config_path(config_path: str | Path | None = None) -> Path:
    """Resolve one config path without silently replacing an explicit path."""
    if config_path is not None:
        explicit = normalize_path(config_path).resolve()
        if not explicit.is_file():
            raise FileNotFoundError(f"Configuration file does not exist: {explicit}")
        return explicit

    candidates: list[Path] = [Path.cwd() / "config.toml"]
    try:
        install_info = get_install_info()
    except (OSError, ValueError, TypeError, KeyError):
        logger.debug("Installation registry lookup failed", exc_info=True)
    else:
        if install_info and install_info.get("install_path"):
            candidates.append(Path(install_info["install_path"]) / "config.toml")

    import anteumbra

    package_dir = Path(anteumbra.__file__).resolve().parent
    candidates.extend(
        (
            package_dir.parent.parent / "config.toml",
            package_dir / "config.toml",
        )
    )
    for candidate in candidates:
        resolved = candidate.resolve()
        if resolved.is_file():
            return resolved

    attempted = ", ".join(str(path.resolve()) for path in candidates)
    raise FileNotFoundError(
        "No config.toml was found. Run 'anteumbra init' or pass an explicit "
        f"configuration path. Attempted: {attempted}"
    )


def parse_websites(config: Mapping[str, Any]) -> tuple[Website, ...]:
    """Parse every configured site and reject ambiguous stable identities."""
    raw_sites = config.get("website")
    if isinstance(raw_sites, Mapping):
        entries = [raw_sites]
    elif isinstance(raw_sites, list):
        entries = raw_sites
    else:
        raise ValueError("[website] must be a table or an array of tables")

    websites: list[Website] = []
    site_ids: set[str] = set()
    for entry in entries:
        if not isinstance(entry, Mapping):
            raise ValueError("Every [[website]] entry must be a table")
        website = _create_website(entry)
        if website.site_id in _RESERVED_CONFIG_SITE_IDS:
            raise ValueError(f"website.id {website.site_id!r} is reserved for unassigned records")
        if website.site_id in site_ids:
            raise ValueError(f"Duplicate website.id: {website.site_id}")
        site_ids.add(website.site_id)
        websites.append(website)
    return tuple(websites)


def _create_website(data: Mapping[str, Any]) -> Website:
    try:
        name = str(data["name"]).strip()
        if not name or name in {".", ".."} or "/" in name or "\\" in name:
            raise ValueError("website.name must not contain path separators")

        scan_options_data = dict(data.get("scan_options", {}))
        log_config = dict(data.get("log_config", {}))
        access_log_path = log_config.get("access_log_path")
        if access_log_path and not scan_options_data.get("access_log_path"):
            scan_options_data["access_log_path"] = access_log_path

        return Website(
            name=name,
            path=normalize_path(data["path"]),
            port=int(data["port"]),
            site_id=str(data.get("id", data.get("site_id", ""))),
            enabled=bool(data.get("enabled", True)),
            scan_options=ScanOptions(**scan_options_data),
            log_config=log_config,
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError(
            f"Invalid website configuration for {data.get('name', 'unknown')!r}: {exc}"
        ) from exc


class TomlConfigProvider:
    """Thread-safe, reloadable configuration owned by one application runtime."""

    def __init__(
        self,
        config_path: str | Path | None = None,
        *,
        loader: Callable[[str], dict[str, Any]] = load_toml_config,
    ) -> None:
        self._lock = threading.RLock()
        self._loader = loader
        self._snapshot: ConfigSnapshot | None = None
        self.reload(config_path)

    @property
    def path(self) -> Path:
        """Return the active source path."""
        with self._lock:
            return self._require_snapshot().path

    @property
    def generation(self) -> int:
        """Return the monotonically increasing successful reload generation."""
        with self._lock:
            return self._require_snapshot().generation

    def get(self) -> dict[str, Any]:
        """Return a defensive copy of the current resolved configuration."""
        with self._lock:
            return copy.deepcopy(self._require_snapshot().values)

    def get_websites(self) -> list[Website]:
        """Return defensive copies of all configured sites, including disabled ones."""
        with self._lock:
            return copy.deepcopy(list(self._require_snapshot().websites))

    def get_enabled_websites(self) -> list[Website]:
        """Return defensive copies of enabled configured sites."""
        return [site for site in self.get_websites() if site.enabled]

    def get_website(self, site_id: str) -> Website | None:
        """Return one site by stable ID."""
        normalized_id = str(site_id).strip().lower()
        for website in self.get_websites():
            if website.site_id == normalized_id:
                return website
        return None

    def resolve_site_identity(
        self,
        file_path: str | Path,
        site_id: str | None = None,
        site_name: str | None = None,
    ) -> SiteIdentity:
        """Resolve explicit or path-derived site ownership from one snapshot."""
        with self._lock:
            snapshot = self._require_snapshot()
            if site_id:
                identity = snapshot.resolver.get(site_id)
                return SiteIdentity.from_values(
                    site_id,
                    identity.site_name if identity else (site_name or str(site_id)),
                )
            return snapshot.resolver.resolve(str(file_path))

    def reload(self, config_path: str | Path | None = None) -> dict[str, Any]:
        """Load and atomically publish a valid snapshot.

        Parsing happens before the lock is acquired. A failed reload therefore
        leaves the last valid snapshot and generation untouched.
        """
        if config_path is None and self._snapshot is not None:
            target = self.path
        else:
            target = resolve_config_path(config_path)

        values = self._loader(str(target))
        if not isinstance(values, dict) or not values:
            raise ValueError(f"Configuration loader returned invalid data: {type(values)}")
        normalized = copy.deepcopy(values)
        logging_config = normalized.setdefault("logging", {})
        logging_config.setdefault(
            "symbols",
            {
                "success": "[MONITOR][DEFAULT][SUCCESS]",
                "scan_hit": "[MONITOR][DEFAULT][HIT]",
                "error": "[MONITOR][DEFAULT][ERROR]",
            },
        )
        websites = parse_websites(normalized)
        resolver = SiteResolver.from_websites(site for site in websites if site.enabled)

        with self._lock:
            generation = 1 if self._snapshot is None else self._snapshot.generation + 1
            self._snapshot = ConfigSnapshot(
                path=target,
                values=normalized,
                websites=websites,
                resolver=resolver,
                generation=generation,
            )
            return copy.deepcopy(normalized)

    def _require_snapshot(self) -> ConfigSnapshot:
        if self._snapshot is None:
            raise RuntimeError("Configuration provider has not been initialized")
        return self._snapshot


def safe_int(value: Any, default: int = 0) -> int:
    """Convert a configuration value to int, tolerating legacy inline comments."""
    try:
        if isinstance(value, (int, float)):
            return int(value)
        return int(str(value).split("#", 1)[0].strip())
    except (TypeError, ValueError):
        return default
