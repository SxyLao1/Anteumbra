# -*- coding: utf-8 -*-
"""
Session cleanup utility.

Cleans up expired Flask session files from the session directory.
"""
import sys
import os
import time
from pathlib import Path

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


def cleanup_sessions(session_dir: str = None, days: int = 7) -> int:
    """Delete session files older than `days` days.

    Args:
        session_dir: Path to Flask session file directory.
                     If None, defaults to <project_root>/flask_session.
        days: Age threshold in days. Files older than this are deleted.

    Returns:
        Number of session files deleted.
    """
    if session_dir is None:
        session_dir = os.path.join(PROJECT_ROOT, "flask_session")

    session_path = Path(session_dir)
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
            pass

    return deleted
