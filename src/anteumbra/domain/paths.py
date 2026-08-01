"""Pure path normalization shared across application services."""

from pathlib import Path


def normalize_path(path: str | Path) -> Path:
    """Resolve a path while accepting Windows-style separators."""
    if isinstance(path, str):
        path = path.replace("\\", "/")
    return Path(path).resolve()


def path_to_key(path: str | Path) -> str:
    """Return a stable, case-insensitive key even for missing paths."""
    try:
        return str(normalize_path(path).resolve()).lower()
    except Exception:
        return str(path).replace("\\", "/").lower()
