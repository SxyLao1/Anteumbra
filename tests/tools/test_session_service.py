import os
import time

from anteumbra.application.session_service import cleanup_sessions


def test_cleanup_sessions_uses_configured_directory(tmp_path):
    old_session = tmp_path / "old-session"
    new_session = tmp_path / "new-session"
    nested = tmp_path / "nested"

    old_session.write_text("old", encoding="utf-8")
    new_session.write_text("new", encoding="utf-8")
    nested.mkdir()

    old_mtime = time.time() - (8 * 86400)
    os.utime(old_session, (old_mtime, old_mtime))

    deleted = cleanup_sessions(tmp_path, days=7)

    assert deleted == 1
    assert not old_session.exists()
    assert new_session.exists()
    assert nested.exists()
