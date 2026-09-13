# -*- coding: utf-8 -*-
"""The re-arm action must exist, stay authenticated, and clear only alert state."""

from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import quote

import pytest

from anteumbra.domain.site import SiteIdentity
from anteumbra.infrastructure.suspicious_registry import SuspiciousRegistry
from anteumbra.infrastructure.wal_manager import WalManager


class ConfigStub:
    def get(self):
        return {"filesizes": {"registry_compact_days": 30}}

    def resolve_site_identity(self, file_path, site_id=None, site_name=None):
        return SiteIdentity("alpha", "Alpha")


class _Events:
    def publish(self, *_args, **_kwargs):
        return None


class _Runtime:
    class _Sse:
        def trigger_registry_update(self):
            return None

    sse = _Sse()


def _probe_path(tmp_path: Path) -> Path:
    """A record path whose URL form works on both Windows and POSIX.

    A leading slash would have to be percent-encoded, and Werkzeug answers that
    with a 308 merge redirect, so the test keeps the path relative in exactly the
    same way the handler will normalise it back.
    """
    return Path(tmp_path.as_posix().lstrip("/"))


def _url(path: Path) -> str:
    """Encode a path the way the admin UI does (encoded separators, one segment)."""
    return "/admin/records/rearm_alert/" + quote(path.as_posix(), safe="/:")


@pytest.fixture
def registry(tmp_path):
    return SuspiciousRegistry(
        tmp_path / "suspicious_registry.json",
        config=ConfigStub(),
        wal=WalManager(tmp_path / "registry_wal.log"),
        event_publisher=_Events(),
    )


@pytest.fixture
def client(monkeypatch, registry):
    import os

    os.environ.setdefault("ANTEUMBRA_TOOL_MODE", "true")
    from anteumbra.interfaces.web.blueprints import records_bp as module
    from anteumbra.interfaces.web.factory import create_app

    app = create_app()
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False
    monkeypatch.setattr(module, "_registry", lambda: registry)
    monkeypatch.setattr(module, "get_runtime", lambda: _Runtime())
    with app.test_client() as test_client:
        yield test_client, registry


def _authenticated(client):
    with client.session_transaction() as session:
        session["authenticated"] = True
        session["username"] = "admin"


def test_rearm_clears_the_standing_alert_state(client, tmp_path):
    test_client, registry = client
    path = _probe_path(tmp_path) / "shell.php"
    registry.add(path, ["rule"], None, "passive", content_hash="hash-one", alert_emitted=True)
    _authenticated(test_client)

    response = test_client.post(_url(path))

    assert response.status_code == 200
    assert json.loads(response.get_data(as_text=True))["status"] == "ok"
    record = registry.get(path, site_id="alpha")
    assert record["alerted"] is False
    assert record["alerted_hash"] == ""
    # clearing the alert must not delete or hide the record
    assert record["file_exists"] is True
    assert record["content_hash"] == "hash-one"


def test_rearm_reports_a_missing_record(client, tmp_path):
    test_client, _registry = client
    _authenticated(test_client)

    response = test_client.post(_url(_probe_path(tmp_path) / "absent.php"))

    assert response.status_code == 404
    assert json.loads(response.get_data(as_text=True))["status"] == "error"


def test_rearm_requires_authentication(client, tmp_path):
    test_client, registry = client
    path = _probe_path(tmp_path) / "shell.php"
    registry.add(path, ["rule"], None, "passive", content_hash="hash-one", alert_emitted=True)

    response = test_client.post(_url(path))

    assert response.status_code in (301, 302, 401, 403)
    assert registry.get(path, site_id="alpha")["alerted"] is True
