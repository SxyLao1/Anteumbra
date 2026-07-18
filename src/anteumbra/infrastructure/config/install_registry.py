"""Persist the single Anteumbra runtime registered on this host."""

from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any


def _registry_dir() -> Path:
    directory = Path.home() / ".anteumbra"
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def _registry_path() -> Path:
    return _registry_dir() / "installs.json"


def get_install_info() -> dict[str, Any] | None:
    """Return the registered runtime when its installation marker still exists."""
    try:
        registry_path = _registry_path()
        if not registry_path.exists():
            return None
        data = json.loads(registry_path.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or "install_path" not in data:
            return None
        install_path = Path(data["install_path"])
        if install_path.exists() and (install_path / ".anteumbra_install").exists():
            return data
        registry_path.unlink(missing_ok=True)
    except (json.JSONDecodeError, OSError, TypeError):
        return None
    return None


def register_install(install_path: str, version: str) -> None:
    """Register one runtime directory for CLI discovery."""
    data = {
        "install_path": str(Path(install_path).resolve()),
        "version": version,
        "installed_at": datetime.now().isoformat(),
        "python": os.environ.get("ANTEUMBRA_PYTHON", ""),
    }
    _registry_path().write_text(
        json.dumps(data, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


def unregister_install() -> None:
    """Remove the host runtime registration."""
    _registry_path().unlink(missing_ok=True)


def is_installed() -> bool:
    """Return whether a valid runtime is registered."""
    return get_install_info() is not None
