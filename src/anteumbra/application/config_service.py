# -*- coding: utf-8 -*-
"""Application-facing configuration operations."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from anteumbra.domain.site import SiteIdentity
from anteumbra.infrastructure.config.loader import (
    load_toml_config,
    load_config,
)
from anteumbra.infrastructure.config.registry import ConfigRegistry
from anteumbra.infrastructure.config.version import (
    get_version,
    get_release_date,
)


def initialize_config(config_path: str | None = None, *, force: bool = False) -> None:
    """Initialize the process configuration at an explicit application boundary."""
    ConfigRegistry.initialize(config_path, force=force)


def reload_config(config_path: str | None = None) -> dict[str, Any]:
    """Reload configuration and return the resolved snapshot."""
    ConfigRegistry.initialize(config_path, force=True)
    return ConfigRegistry.get_raw_config()


def get_runtime_config() -> dict[str, Any]:
    """Return the current resolved configuration snapshot."""
    return ConfigRegistry.get_raw_config()


def get_config_path() -> Path | None:
    """Return the active config.toml path without exposing registry internals."""
    try:
        return ConfigRegistry.get_config_path()
    except RuntimeError:
        return None


def get_websites():
    """Return configured websites."""
    return ConfigRegistry.get_websites()


def get_enabled_websites():
    """Return enabled websites."""
    return ConfigRegistry.get_enabled_websites()


def get_website(site_id: str):
    """Return one configured website by stable identity."""
    return ConfigRegistry.get_website(site_id)


def resolve_site_identity(
    file_path: str,
    site_id: str | None = None,
    site_name: str | None = None,
) -> SiteIdentity:
    """Resolve explicit or path-derived site ownership."""
    return ConfigRegistry.resolve_site_identity(file_path, site_id, site_name)


__all__ = [
    "load_toml_config",
    "load_config",
    "get_version",
    "get_release_date",
    "initialize_config",
    "reload_config",
    "get_runtime_config",
    "get_config_path",
    "get_websites",
    "get_enabled_websites",
    "get_website",
    "resolve_site_identity",
]
