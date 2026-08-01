"""Compatibility exports for application-owned release metadata."""

from anteumbra.application.config_service import (
    ANTEUMBRA_RELEASE_DATE,
    ANTEUMBRA_VERSION,
    get_release_date,
    get_version,
)

__all__ = [
    "ANTEUMBRA_RELEASE_DATE",
    "ANTEUMBRA_VERSION",
    "get_release_date",
    "get_version",
]
