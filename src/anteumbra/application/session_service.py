"""Session maintenance service."""

from __future__ import annotations

import time
from pathlib import Path

from anteumbra.infrastructure.utils.path_utils import normalize_path


def cleanup_sessions(session_dir: str | Path | None = None, days: int = 7) -> int:
    """Delete session files older than the configured age threshold."""
    session_path = normalize_path(session_dir if session_dir is not None else "flask_session")
    if not session_path.exists():
        return 0

    cutoff = time.time() - (days * 86400)
    deleted = 0

    for sess_file in session_path.iterdir():
        if sess_file.is_dir():
            continue
        try:
            if sess_file.stat().st_mtime < cutoff:
                sess_file.unlink()
                deleted += 1
        except OSError:
            continue

    return deleted
