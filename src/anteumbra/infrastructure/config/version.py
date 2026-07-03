"""Anteumbra version manager — reads from package __version__ (single source of truth).

Version is defined in ``anteumbra.__init__.__version__``.
pyproject.toml reads it dynamically via ``attr`` directive at build time.
"""
import os
import sys

_ANTEUMBRA_VERSION = None
_ANTEUMBRA_RELEASE_DATE = None


def _find_config():
    """Find config.toml for release_date only (version comes from package)."""
    cwd_config = os.path.join(os.getcwd(), "config.toml")
    if os.path.exists(cwd_config):
        return cwd_config
    file_dir = os.path.dirname(os.path.abspath(__file__))
    root_config = os.path.join(file_dir, "..", "..", "..", "..", "config.toml")
    root_config = os.path.normpath(root_config)
    if os.path.exists(root_config):
        return root_config
    return None


def _load_version():
    global _ANTEUMBRA_VERSION, _ANTEUMBRA_RELEASE_DATE
    if _ANTEUMBRA_VERSION is not None:
        return
    # Version: single source of truth from anteumbra.__version__
    try:
        from anteumbra import __version__
        _ANTEUMBRA_VERSION = __version__
    except Exception:
        _ANTEUMBRA_VERSION = "unknown"

    # Release date: still read from config.toml [system] if available
    try:
        if sys.version_info >= (3, 11):
            import tomllib
        else:
            import tomli as tomllib
        config_path = _find_config()
        if config_path:
            with open(config_path, "rb") as f:
                cfg = tomllib.load(f)
            system = cfg.get("system", {})
            _ANTEUMBRA_RELEASE_DATE = system.get("release_date", "TBD")
        else:
            _ANTEUMBRA_RELEASE_DATE = "TBD"
    except Exception:
        _ANTEUMBRA_RELEASE_DATE = "TBD"


def get_version():
    _load_version()
    return _ANTEUMBRA_VERSION


def get_release_date():
    _load_version()
    return _ANTEUMBRA_RELEASE_DATE


_load_version()
ANTEUMBRA_VERSION = _ANTEUMBRA_VERSION
ANTEUMBRA_RELEASE_DATE = _ANTEUMBRA_RELEASE_DATE
