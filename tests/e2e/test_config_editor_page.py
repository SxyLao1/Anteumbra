# -*- coding: utf-8 -*-
"""E2E: the advanced config editor page, its fragments and one full round trip.

This drives the assembled application (``create_app``) with the real runtime
attached, against the ``config.toml`` of the session-isolated working directory,
and walks the operator's whole path: render the page and every fragment it is
built from, edit one value, preview the diff, confirm, look the write up in the
version history, then restore the backup and check the file came back byte for
byte.

The working directory of this suite is a temporary root (``isolate_environment``
in ``tests/e2e/conftest.py``), so no assertion here can reach an installed
``config.toml``; the module refuses to run if the resolved path is not the file
it seeded.
"""

from __future__ import annotations

import html
import os
import re
from pathlib import Path

import pytest

from anteumbra.interfaces.web.runtime import get_runtime

PAGE = "/admin/config"
_HIDDEN_INPUT = re.compile(r'<input type="hidden" name="([^"]+)" value="([^"]*)"')
_FORM_ACTION = re.compile(r'<form hx-post="([^"]+)"')


@pytest.fixture(scope="module")
def _editor_config(isolate_environment):
    """Seed ``<cwd>/config.toml`` from the shipped template, and clean up after.

    ``resolve_config_path`` prefers ``<cwd>/config.toml``; without a file here it
    would fall through to the installation registry, which on a developer machine
    is the live instance.  The fixture therefore creates the file *before* the app
    is built and hands it to the tests.
    """
    import anteumbra

    template = Path(anteumbra.__file__).resolve().parent / "config.toml"
    target = Path.cwd() / "config.toml"
    original = target.read_bytes() if target.is_file() else None
    target.write_bytes(template.read_bytes())
    yield target
    if original is None:
        target.unlink(missing_ok=True)
    else:  # pragma: no cover - only when a previous module left a file behind
        target.write_bytes(original)


@pytest.fixture(scope="module")
def _app(_editor_config):
    os.environ.setdefault("ANTEUMBRA_TOOL_MODE", "true")

    from anteumbra.interfaces.web.factory import create_app

    app = create_app()
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False
    return app


@pytest.fixture
def client(_app):
    created = _app.test_client()
    with created.session_transaction() as flask_session:
        flask_session["authenticated"] = True
        flask_session["username"] = "admin"
    return created


def _config_path(app) -> Path:
    with app.app_context():
        return Path(get_runtime().config.path).resolve()


def _body(response) -> str:
    text = response.get_data(as_text=True)
    assert response.status_code == 200, text[:2000]
    return text


def _confirm(client, preview: str):
    action = _FORM_ACTION.search(preview)
    assert action, "the preview rendered no confirm form"
    fields = {name: html.unescape(value) for name, value in _HIDDEN_INPUT.findall(preview)}
    assert fields.get("confirm") == "1"
    return client.post(action.group(1), data=fields)


def _changed_lines(before: str, after: str) -> list[tuple[str, str]]:
    old = before.splitlines(keepends=True)
    new = after.splitlines(keepends=True)
    assert len(old) == len(new), "the edit changed the number of lines"
    return [(left, right) for left, right in zip(old, new, strict=True) if left != right]


def test_the_editor_is_wired_to_the_isolated_config(_app, _editor_config) -> None:
    """Guard: everything below writes this file, and only this file."""
    resolved = _config_path(_app)

    assert resolved == _editor_config.resolve()
    assert resolved.parent == Path.cwd().resolve()


def test_every_url_the_page_is_built_from_renders(client) -> None:
    expectations = {
        PAGE: "Configuration editor",
        f"{PAGE}?view=tree": "Tree view",
        f"{PAGE}?view=raw": "Raw view",
        f"{PAGE}?tab=secrets": "Secrets and credentials",
        f"{PAGE}?tab=history": "Version history",
        "/admin/config/editor/panel": 'id="ce-list"',
        "/admin/config/editor/history": 'id="ce-history"',
        "/admin/config/editor/validate": "Validated",
        "/admin/config/watcher": "card-header",
    }
    for url, marker in expectations.items():
        body = _body(client.get(url))
        assert marker in body, f"{url} did not render {marker!r}"


def test_edit_preview_save_and_restore_round_trip(client, _app) -> None:
    path = _config_path(_app)
    before = path.read_bytes().decode("utf-8")

    # 1. Preview: the diff names the key and its two values, and nothing is written.
    preview = _body(
        client.post(
            "/admin/config/editor/value", data={"ce.web_admin.port": "12000", "confirm": "0"}
        )
    )
    assert "web_admin.port" in preview and "12000" in preview
    assert "restart required" in preview
    assert path.read_bytes().decode("utf-8") == before

    # 2. Confirm: exactly one line moved, and the previous file was kept.
    written = _body(_confirm(client, preview))
    assert "Saved: config.toml written and reloaded." in written
    edited = path.read_bytes().decode("utf-8")
    changed = _changed_lines(before, edited)
    assert len(changed) == 1
    assert changed[0][1].strip().startswith("port = 12000")
    assert changed[0][0].strip().startswith("port = 8080")

    backups = sorted(path.parent.glob(f"{path.name}.*.bak"))
    assert [item.name for item in backups if item.read_bytes().decode("utf-8") == before]

    # 3. The write is in the version history, with its changed key.
    history = _body(client.get(f"{PAGE}?tab=history"))
    assert "backup of the file" in history
    assert "web_admin.port" in history

    revision = next(
        item for item in backups if item.read_bytes().decode("utf-8") == before
    ).name
    diff = _body(client.get(f"/admin/config/editor/revision/diff?revision=backup:{revision}"))
    assert "12000" in diff and "8080" in diff

    # 4. Restore it: the file comes back byte for byte, and the edited file is kept.
    restored = _body(_confirm(client, diff))
    assert "Saved: config.toml written and reloaded." in restored
    assert path.read_bytes().decode("utf-8") == before
    assert [
        item.name
        for item in sorted(path.parent.glob(f"{path.name}.*.bak"))
        if item.read_bytes().decode("utf-8") == edited
    ]
