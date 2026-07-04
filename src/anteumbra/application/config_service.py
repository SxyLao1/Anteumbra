# -*- coding: utf-8 -*-
"""
Application Service: Config Loader & Version

Thin facade over infrastructure/config/loader.py and config/version.py.
Fixes DDD dependency direction: Interfaces → Application → Infrastructure.
"""
from anteumbra.infrastructure.config.loader import (
    load_toml_config,
    load_config,
)
from anteumbra.infrastructure.config.version import (
    get_version,
    get_release_date,
)

__all__ = [
    "load_toml_config",
    "load_config",
    "get_version",
    "get_release_date",
]
