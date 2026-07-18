"""Temporary compatibility facade for the instance-owned config provider.

Runtime code is being migrated to receive :class:`TomlConfigProvider`
explicitly. New code must not depend on this process-wide facade.
"""

from __future__ import annotations

import threading
from pathlib import Path
from typing import Any

from anteumbra.domain.site import SiteIdentity
from anteumbra.infrastructure.config.provider import (
    TomlConfigProvider,
    _create_website,
    parse_websites,
    safe_int,
)
from anteumbra.infrastructure.models import Website


class ConfigRegistry:
    """Compatibility facade retained only while callers move to injection."""

    _lock = threading.RLock()
    _provider: TomlConfigProvider | None = None

    @classmethod
    def bind(cls, provider: TomlConfigProvider) -> None:
        """Temporarily expose a composition-root-owned provider to legacy callers."""
        with cls._lock:
            cls._provider = provider

    @classmethod
    def initialize(
        cls,
        config_path: str | Path | None = None,
        force: bool = False,
    ) -> None:
        with cls._lock:
            if cls._provider is None:
                cls._provider = TomlConfigProvider(config_path)
                return
            if force:
                cls._provider.reload(config_path)
                return
            if config_path is not None:
                requested = Path(config_path).resolve()
                if requested != cls._provider.path:
                    cls._provider = TomlConfigProvider(requested)

    @classmethod
    def reset(cls) -> None:
        """Discard the compatibility provider for legacy test isolation."""
        with cls._lock:
            cls._provider = None

    @classmethod
    def get_raw_config(cls) -> dict[str, Any]:
        return cls._require_provider().get()

    @classmethod
    def get_config_path(cls) -> Path:
        return cls._require_provider().path

    @classmethod
    def get_websites(cls) -> list[Website]:
        return cls._require_provider().get_websites()

    @classmethod
    def get_enabled_websites(cls) -> list[Website]:
        return cls._require_provider().get_enabled_websites()

    @classmethod
    def get_website(cls, site_id: str) -> Website | None:
        return cls._require_provider().get_website(site_id)

    @classmethod
    def resolve_site_identity(
        cls,
        file_path: str | Path,
        site_id: str | None = None,
        site_name: str | None = None,
    ) -> SiteIdentity:
        return cls._require_provider().resolve_site_identity(
            file_path,
            site_id,
            site_name,
        )

    @staticmethod
    def safe_int(value: Any, default: int = 0) -> int:
        return safe_int(value, default)

    @classmethod
    def _parse_websites(cls, config: dict[str, Any]) -> list[Website]:
        """Compatibility hook for callers not yet using ``parse_websites``."""
        return list(parse_websites(config))

    @classmethod
    def _create_website(cls, data: dict[str, Any]) -> Website:
        """Compatibility hook for callers not yet using the provider parser."""
        return _create_website(data)

    @classmethod
    def _require_provider(cls) -> TomlConfigProvider:
        with cls._lock:
            if cls._provider is None:
                raise RuntimeError(
                    "Configuration is not initialized. The composition root must "
                    "create a TomlConfigProvider first."
                )
            return cls._provider
