"""Administrator password route integration with the runtime service."""

import importlib
from types import SimpleNamespace

from flask import Flask, session
from werkzeug.security import generate_password_hash


def test_password_route_uses_runtime_service_and_invalidates_session(monkeypatch):
    module = importlib.import_module("anteumbra.interfaces.web.blueprints.admin_bp")
    calls: list[str] = []

    def set_password(password: str) -> tuple[bool, str]:
        calls.append(password)
        return True, "updated"

    passwords = SimpleNamespace(
        check_strength=lambda password: (password == "N3w!RuntimePass", "strength"),
        set_password=set_password,
    )
    monkeypatch.setattr(
        module,
        "get_runtime",
        lambda: SimpleNamespace(passwords=passwords),
    )
    monkeypatch.setattr(
        module,
        "get_admin_credentials",
        lambda: (
            "admin",
            generate_password_hash("Current!Pass9"),
            ["127.0.0.1"],
        ),
    )
    app = Flask(__name__)
    app.secret_key = "test-secret"

    with app.test_request_context(
        "/admin/account/password",
        method="POST",
        json={
            "current_password": "Current!Pass9",
            "new_password": "N3w!RuntimePass",
        },
    ):
        session["authenticated"] = True
        session["username"] = "admin"
        response = module.change_password.__wrapped__()

        assert response.status_code == 200
        assert response.get_json() == {"success": True, "message": "updated"}
        assert "authenticated" not in session
        assert calls == ["N3w!RuntimePass"]
