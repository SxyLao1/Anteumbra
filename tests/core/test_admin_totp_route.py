"""Route-level coverage for the single-admin TOTP login challenge."""

from types import SimpleNamespace

from flask import Flask
from werkzeug.security import generate_password_hash


class _Limiter:
    def check_and_record(self, _ip):
        return SimpleNamespace(allowed=True, retry_after_seconds=0)

    def reset(self, _ip):
        return None


def test_password_login_stops_at_totp_then_completes(monkeypatch):
    import anteumbra.interfaces.web.blueprints.admin_bp as module
    import anteumbra.interfaces.web.blueprints.admin_totp_bp as totp_module

    totp = SimpleNamespace(
        enabled=True,
        verify=lambda code: code == "123456",
        consume_recovery_code=lambda code: False,
    )
    runtime = SimpleNamespace(login_rate_limiter=_Limiter(), totp=totp)
    monkeypatch.setattr(module, "get_runtime", lambda: runtime)
    monkeypatch.setattr(totp_module, "get_runtime", lambda: runtime)
    monkeypatch.setattr(
        module,
        "get_admin_credentials",
        lambda: ("admin", generate_password_hash("Password!9"), ["127.0.0.1"]),
    )

    app = Flask(__name__)
    app.secret_key = "test-secret"
    app.register_blueprint(module.admin_bp)
    app.register_blueprint(totp_module.admin_totp_bp)
    client = app.test_client()

    first = client.post(
        "/admin/login",
        data={"username": "admin", "password": "Password!9"},
    )
    assert first.status_code == 302
    assert first.headers["Location"].endswith("/admin/login/totp")
    with client.session_transaction() as state:
        assert state["totp_pending_username"] == "admin"
        assert "authenticated" not in state

    challenge = client.post("/admin/login/totp", data={"totp_code": "123456"})
    assert challenge.status_code == 302
    assert challenge.headers["Location"].endswith("/admin/")
    with client.session_transaction() as state:
        assert state["authenticated"] is True
        assert state["username"] == "admin"
        assert "totp_pending_username" not in state
