import os
import time

from flask import Flask

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


def test_cleanup_sessions_honors_lifetime_in_seconds(tmp_path):
    expired = tmp_path / "expired-session"
    retained = tmp_path / "retained-session"
    expired.write_text("expired", encoding="utf-8")
    retained.write_text("retained", encoding="utf-8")

    now = time.time()
    os.utime(expired, (now - 120, now - 120))
    os.utime(retained, (now - 30, now - 30))

    deleted = cleanup_sessions(tmp_path, lifetime_seconds=60)

    assert deleted == 1
    assert not expired.exists()
    assert retained.exists()


def test_monitor_cleanup_route_passes_configured_directory_and_lifetime(monkeypatch, tmp_path):
    from anteumbra.interfaces.web.blueprints import monitor_admin_routes

    calls = []
    monkeypatch.setattr(
        monitor_admin_routes,
        "cleanup_sessions",
        lambda *args, **kwargs: calls.append((args, kwargs)) or 2,
    )
    app = Flask(__name__)
    app.config.update(
        SESSION_FILE_DIR=str(tmp_path),
        SESSION_LIFETIME_SECONDS=90,
    )

    with app.test_request_context("/admin/session/cleanup", method="POST"):
        response = monitor_admin_routes.session_cleanup.__wrapped__()

    assert response.get_json() == {"success": True, "deleted": 2}
    assert calls == [
        ((str(tmp_path),), {"lifetime_seconds": 90}),
    ]


def test_system_cleanup_route_passes_configured_directory_and_lifetime(monkeypatch, tmp_path):
    from anteumbra.interfaces.web.blueprints import system_bp

    calls = []
    class _Config:
        @staticmethod
        def get():
            return {"web_admin": {}}

    class _Runtime:
        config = _Config()

    monkeypatch.setattr(
        system_bp,
        "cleanup_sessions",
        lambda *args, **kwargs: calls.append((args, kwargs)) or 0,
    )
    monkeypatch.setattr(system_bp, "get_runtime", lambda: _Runtime())
    monkeypatch.setattr(system_bp, "render_template", lambda *args, **kwargs: "panel")
    app = Flask(__name__)
    app.config.update(
        SESSION_FILE_DIR=str(tmp_path),
        SESSION_LIFETIME_SECONDS=45,
    )

    with app.test_request_context("/admin/system/session/cleanup", method="POST"):
        response = system_bp.system_session_cleanup.__wrapped__()

    assert response == "panel"
    assert calls == [
        ((str(tmp_path),), {"lifetime_seconds": 45}),
    ]
