# -*- coding: utf-8 -*-
"""
E2E Test: Settings config editor round-trip safety (v1.0.36 regression)

Covers the corruption chain where the line-based editor truncated
multi-line arrays to "[" and the save endpoint stored the fragment
verbatim, silently corrupting every list value in config.toml (notably
web_admin.allowed_ips, which locked admins out of the UI).
"""

import html
import os
import re
from pathlib import Path

import pytest
import tomli_w

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10
    import tomli as tomllib

from anteumbra.interfaces.web.runtime import get_runtime

_EDITOR_ARRAY_INPUT_RE = re.compile(
    r'type="text" value="([^"]*)" data-key="web_admin\.allowed_ips"'
)


# ── Flask test client fixtures ──────────────────────────────────────────────


@pytest.fixture(scope="module")
def _isolated_config(isolate_environment):
    """Seed an isolated config.toml so tests never touch the host install.

    ``resolve_config_path`` (infrastructure/config/provider.py) resolves
    ``<cwd>/config.toml`` FIRST and falls back to the host install registry
    (~/.anteumbra/installs.json) — it does not honor ANTEUMBRA_HOME. The
    session-isolated runtime root has no config.toml, so without this seed
    every mutating e2e test would silently hit the registered production
    instance. Created for this module only and removed afterwards so later
    modules keep their historical resolution behavior.
    """
    import anteumbra

    template = Path(anteumbra.__file__).parent / "config.toml"
    target = Path.cwd() / "config.toml"
    created = not target.exists()
    if created:
        target.write_text(template.read_text(encoding="utf-8"), encoding="utf-8")
    yield target
    if created:
        target.unlink(missing_ok=True)


@pytest.fixture(scope="module")
def _app(_isolated_config):
    """Create the Flask app once per test module."""
    os.environ.setdefault("ANTEUMBRA_TOOL_MODE", "true")

    from anteumbra.interfaces.web.factory import create_app

    app = create_app()
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False
    return app


@pytest.fixture
def client(_app):
    """Flask test client — each test gets a fresh client context."""
    with _app.test_client() as c:
        yield c


# ── Helpers ─────────────────────────────────────────────────────────────────


def _login(client):
    with client.session_transaction() as flask_session:
        flask_session["authenticated"] = True
        flask_session["username"] = "admin"


def _config_path(app) -> Path:
    with app.app_context():
        return Path(get_runtime().config.path)


def _reload_config(app):
    with app.app_context():
        get_runtime().config.reload()


def _read_config(app) -> dict:
    return tomllib.loads(_config_path(app).read_text(encoding="utf-8"))


def _persist_config(app, data: dict) -> None:
    """Write config data through tomli_w (multi-line arrays) and reload."""
    path = _config_path(app)
    path.write_text(tomli_w.dumps(data), encoding="utf-8")
    _reload_config(app)


def _rewrite_config_multiline(app) -> None:
    """Rewrite the current config so arrays are stored as multi-line blocks.

    This reproduces the on-disk state after any UI save (tomli_w always
    writes arrays multi-line), which is what triggered the legacy parser's
    truncation-to-"[" bug. Keys asserted below are ensured to exist.
    """
    data = _read_config(app)
    data.setdefault("web_admin", {}).setdefault("allowed_ips", ["127.0.0.1"])
    data.setdefault("ip_blocker", {}).setdefault(
        "devices", [{"name": "Stdout Logger", "type": "stdout"}]
    )
    _persist_config(app, data)


def _extract_allowed_ips_input(page: str) -> str:
    match = _EDITOR_ARRAY_INPUT_RE.search(page)
    assert match, "allowed_ips array input missing from config editor page"
    return html.unescape(match.group(1))


# ═════════════════════════════════════════════════════════════════════════════
# Editor rendering must show complete array values
# ═════════════════════════════════════════════════════════════════════════════


class TestConfigEditorRendering:
    def test_editor_shows_complete_multiline_array(self, client, _app):
        """A multi-line array must render as one complete single-line value.

        The legacy line-based parser rendered only the "[" opening line, and
        the array then round-tripped as the literal string "[".
        """
        _rewrite_config_multiline(_app)
        _login(client)
        resp = client.get("/admin/settings/config/editor")
        assert resp.status_code == 200, resp.get_data(as_text=True)
        value = _extract_allowed_ips_input(resp.get_data(as_text=True))
        assert value.startswith("[") and value.endswith("]")
        assert value != "["
        assert "127.0.0.1" in value

    def test_editor_data_endpoint_reports_list_type(self, client, _app):
        _rewrite_config_multiline(_app)
        _login(client)
        resp = client.get("/admin/settings/config/data")
        assert resp.status_code == 200, resp.get_data(as_text=True)
        field = resp.get_json()["sections"]["web_admin"]["fields"]["allowed_ips"]
        assert field["type"] == "array"
        assert "127.0.0.1" in field["value"]


# ═════════════════════════════════════════════════════════════════════════════
# Save endpoint must round-trip, parse, or reject — never store fragments
# ═════════════════════════════════════════════════════════════════════════════


class TestConfigSaveRoundTrip:
    def test_editor_roundtrip_preserves_array(self, client, _app):
        """Save → re-render → save again must not corrupt array values.

        This replays the exact UI flow that corrupted configs before the
        fix: tomli_w writes a multi-line array, the editor shows the value,
        and the frontend posts every field back on save.
        """
        _rewrite_config_multiline(_app)
        before = _read_config(_app)["web_admin"]["allowed_ips"]
        _login(client)

        page = client.get("/admin/settings/config/editor").get_data(as_text=True)
        extracted = _extract_allowed_ips_input(page)
        assert tomllib.loads(f"v = {extracted}")["v"] == before

        resp = client.post(
            "/admin/settings/config/save",
            json={"changes": {"web_admin.allowed_ips": extracted}},
        )
        assert resp.status_code == 200, resp.get_data(as_text=True)
        assert _read_config(_app)["web_admin"]["allowed_ips"] == before

    def test_save_parses_array_text_to_list(self, client, _app):
        _login(client)
        resp = client.post(
            "/admin/settings/config/save",
            json={"changes": {"web_admin.allowed_ips": '["127.0.0.1", "10.0.0.0/8"]'}},
        )
        assert resp.status_code == 200, resp.get_data(as_text=True)
        assert _read_config(_app)["web_admin"]["allowed_ips"] == ["127.0.0.1", "10.0.0.0/8"]

    def test_save_roundtrips_array_of_tables(self, client, _app):
        _login(client)
        resp = client.post(
            "/admin/settings/config/save",
            json={
                "changes": {"ip_blocker.devices": '[{ name = "Stdout Logger", type = "stdout" }]'}
            },
        )
        assert resp.status_code == 200, resp.get_data(as_text=True)
        assert _read_config(_app)["ip_blocker"]["devices"] == [
            {"name": "Stdout Logger", "type": "stdout"}
        ]

    def test_save_rejects_truncated_array(self, client, _app):
        """The literal fragment "[" must be rejected, not stored verbatim."""
        _rewrite_config_multiline(_app)
        before = _read_config(_app)["web_admin"]["allowed_ips"]
        _login(client)
        resp = client.post(
            "/admin/settings/config/save",
            json={"changes": {"web_admin.allowed_ips": "["}},
        )
        assert resp.status_code == 400
        body = resp.get_json()
        assert body["success"] is False
        assert _read_config(_app)["web_admin"]["allowed_ips"] == before

    def test_save_rejects_malformed_key(self, client, _app):
        """Junk keys produced by the legacy parser must not enter the config."""
        _login(client)
        resp = client.post(
            "/admin/settings/config/save",
            json={"changes": {"web_admin.{ name": "x"}},
        )
        assert resp.status_code == 400
        assert resp.get_json()["success"] is False
        # The junk fragment must not become a config KEY (the literal text
        # "{ name" legitimately appears inside inline-table array values).
        assert "{ name" not in _read_config(_app).get("web_admin", {})

    def test_save_rejects_semantically_invalid_value(self, client, _app):
        """Delta validation must block a save that breaks allowed_ips."""
        _login(client)
        before = _read_config(_app)["web_admin"]["allowed_ips"]
        resp = client.post(
            "/admin/settings/config/save",
            json={"changes": {"web_admin.allowed_ips": '["999.999.0.1"]'}},
        )
        assert resp.status_code == 400
        body = resp.get_json()
        assert body["success"] is False
        assert "allowed_ips" in body["error"]
        assert _read_config(_app)["web_admin"]["allowed_ips"] == before

    def test_save_rejects_non_object_body(self, client, _app):
        _login(client)
        resp = client.post(
            "/admin/settings/config/save",
            data="not json",
            content_type="application/json",
        )
        assert resp.status_code == 400

    def test_save_keeps_bracket_strings_as_strings(self, client, _app):
        """A string value that merely looks like an array must stay a string.

        ``logging.symbols.success = "[MONITOR][START][SUCCESS]"`` is a plain
        string; treating every "[...]" as TOML made the whole editor save fail
        with 400 whenever such a symbol existed.
        """
        _login(client)
        config = _read_config(_app)
        config.setdefault("logging", {}).setdefault("symbols", {})["success"] = (
            "[MONITOR][START][SUCCESS]"
        )
        _persist_config(_app, config)

        resp = client.post(
            "/admin/settings/config/save",
            json={
                "changes": {
                    "logging.symbols.success": "[MONITOR][START][SUCCESS]",
                    "system.release_date": config.get("system", {}).get(
                        "release_date", "2026-07-19"
                    ),
                }
            },
        )
        assert resp.status_code == 200, resp.get_data(as_text=True)
        stored = _read_config(_app)["logging"]["symbols"]["success"]
        assert stored == "[MONITOR][START][SUCCESS]"
        assert isinstance(stored, str)

    def test_save_still_accepts_real_arrays(self, client, _app):
        """Array fields keep round-tripping through the same endpoint."""
        _rewrite_config_multiline(_app)
        _login(client)
        resp = client.post(
            "/admin/settings/config/save",
            json={"changes": {"web_admin.allowed_ips": '["127.0.0.1", "10.1.0.0/16"]'}},
        )
        assert resp.status_code == 200, resp.get_data(as_text=True)
        assert _read_config(_app)["web_admin"]["allowed_ips"] == ["127.0.0.1", "10.1.0.0/16"]
        # restore the single-address default for the remaining assertions
        _persist_config(
            _app,
            {
                **_read_config(_app),
                "web_admin": {**_read_config(_app)["web_admin"], "allowed_ips": ["127.0.0.1"]},
            },
        )

    def test_save_rejects_scalar_replacing_array(self, client, _app):
        """Turning an array field into bare text stays an error, not a silent edit."""
        _rewrite_config_multiline(_app)
        before = _read_config(_app)["web_admin"]["allowed_ips"]
        _login(client)
        resp = client.post(
            "/admin/settings/config/save",
            json={"changes": {"web_admin.allowed_ips": "127.0.0.1"}},
        )
        assert resp.status_code == 400
        assert _read_config(_app)["web_admin"]["allowed_ips"] == before
