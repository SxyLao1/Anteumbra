"""Application-facing YARA rule path resolution."""

from __future__ import annotations

import logging
from pathlib import Path

from anteumbra.domain.paths import normalize_path


def get_bundled_rules_path() -> Path:
    """Return the package-owned YARA directory."""
    import anteumbra

    return Path(anteumbra.__file__).resolve().parent / "rules" / "webshell"


def _contains_yara_rules(path: Path) -> bool:
    try:
        return path.is_dir() and next(path.glob("*.yar"), None) is not None
    except OSError:
        return False


def resolve_yara_rules_path(
    configured_path: str | Path,
    logger: logging.Logger | None = None,
) -> Path:
    """Use bundled rules when the configured runtime directory is absent or empty."""
    configured = normalize_path(configured_path).resolve()
    if _contains_yara_rules(configured):
        return configured

    bundled = get_bundled_rules_path().resolve()
    if configured != bundled and _contains_yara_rules(bundled):
        if logger is not None:
            reason = "empty" if configured.is_dir() else "missing"
            logger.warning(
                "[YARA] Configured rules directory is %s (%s); using bundled rules: %s",
                reason,
                configured,
                bundled,
            )
        return bundled
    return configured


__all__ = ["get_bundled_rules_path", "resolve_yara_rules_path"]
