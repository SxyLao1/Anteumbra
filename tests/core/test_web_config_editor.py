# -*- coding: utf-8 -*-
"""The advanced config editor (``/admin/config``) over HTTP.

Everything here drives the real Flask application the way the page does: the
template renders, the confirm form a preview produced is posted back, and the
bytes of the ``config.toml`` on disk are asserted at every step.  The rules the
editor promises are pinned as tests:

* a surgical edit rewrites one line and copies every other byte - comments, blank
  lines, line endings included;
* a save goes through the CLI validator and is refused when *this change* would
  introduce an error, while pre-existing warnings never block it;
* the file is backed up, timestamped, before it is ever replaced;
* a restore writes a previous revision back, backs the current file up first,
  revalidates and reports which keys need a restart;
* no secret leaves the server, in a page, a fragment or a download.

No test in this module touches the repository's own ``config.toml``: the
blueprint is pointed at a ``tmp_path`` copy through its runtime accessor, and the
module fails if the repository file changes while these tests run.
"""

from __future__ import annotations

import hashlib
import html
import re
from pathlib import Path
from types import SimpleNamespace

import pytest

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10
    import tomli as tomllib

from anteumbra.application.config_history_service import ConfigHistoryLogger
from anteumbra.interfaces.web.blueprints import config_editor_bp as bp

#: The literal secrets the config files carry; none of them may appear in a
#: response body, whichever view or fragment produced it.
CONFIG_SECRET = "scrypt:32768:8:1$abcdefgh$CONFIGLITERALSECRET"
ENV_SECRET = "wechat-token-ENVSECRET"
ENV_PASSWORD_HASH = "scrypt:32768:8:1$ijklmnop$ENVHASHSECRET"

CONFIG = f"""\
# Anteumbra test config
# a second comment line

[[website]]
name = "alpha"
path = "site"
port = 8080          # the site port

# The admin surface.  These keys are read once, at startup.
[web_admin]
host = "127.0.0.1"
port = 11174         # listen port
allowed_ips = ["127.0.0.1"]
password_hash = "{CONFIG_SECRET}"

[notifier]
enabled = false
unused_placeholder = "${{ANTEUMBRA_NOT_SET_AT_ALL:-}}"

[notifier.wechat]
enabled = false
send_key = "${{ANTEUMBRA_WECHAT_API_KEY:?}}"
"""

ENV = f"ANTEUMBRA_WECHAT_API_KEY={ENV_SECRET}\nANTEUMBRA_PASSWORD_HASH={ENV_PASSWORD_HASH}\n"

PAGE = "/admin/config"
PANEL = "/admin/config/editor/panel"
HISTORY = "/admin/config/editor/history"
REFUSED = "Not saved"

_HIDDEN_INPUT = re.compile(r'<input type="hidden" name="([^"]+)" value="([^"]*)"')
_FORM_ACTION = re.compile(r'<form hx-post="([^"]+)"')
_CODE_CELL = re.compile(r"<td><code[^>]*>(.*?)</code></td>", re.S)


# ── fixtures ────────────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def _app():
    import os

    os.environ.setdefault("ANTEUMBRA_TOOL_MODE", "true")

    from anteumbra.interfaces.web.factory import create_app

    app = create_app()
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False
    return app


@pytest.fixture(scope="module", autouse=True)
def _repo_config_is_never_written():
    """Fail the module if the repository's own config.toml moved."""
    import anteumbra

    path = Path(anteumbra.__file__).resolve().parents[2] / "config.toml"
    before = path.read_bytes()
    yield
    assert path.read_bytes() == before, "these tests wrote the repository config.toml"


class _Config:
    """The slice of the config provider the editor uses."""

    def __init__(self, path: Path, data: dict):
        self.path = str(path)
        self._data = data
        self.reloads = 0

    def get(self) -> dict:
        return self._data

    def reload(self) -> dict:
        self.reloads += 1
        return self._data


@pytest.fixture
def editor(tmp_path, monkeypatch, _app):
    """An isolated config.toml + .env + history file, and a signed-in client."""
    (tmp_path / "site").mkdir()
    config_path = tmp_path / "config.toml"
    config_path.write_bytes(CONFIG.encode("utf-8"))
    env_path = tmp_path / ".env"
    env_path.write_text(ENV, encoding="utf-8")

    history = ConfigHistoryLogger(tmp_path / "config_history.json")
    config = _Config(config_path, tomllib.loads(CONFIG))
    runtime = SimpleNamespace(config=config, config_history=history)
    monkeypatch.setattr(bp, "get_runtime", lambda: runtime)

    client = _app.test_client()
    with client.session_transaction() as flask_session:
        flask_session["authenticated"] = True
        flask_session["username"] = "admin"
    return SimpleNamespace(
        client=client,
        app=_app,
        config_path=config_path,
        env_path=env_path,
        history=history,
        runtime=runtime,
        config=config,
        text=lambda: config_path.read_bytes().decode("utf-8"),
        backups=lambda: sorted(config_path.parent.glob(f"{config_path.name}.*.bak")),
    )


# ── helpers ─────────────────────────────────────────────────────────────────


def _login_free(app):
    """A client with no session, for the auth gate."""
    return app.test_client()


def _body(response) -> str:
    text = response.get_data(as_text=True)
    assert response.status_code < 400, text[:2000]
    return text


def _confirm(client, preview: str):
    """Click the confirm button a preview rendered, as a browser would.

    The form is parsed out of the response instead of being rebuilt by hand, so
    the test fails if the rendered form would not actually round-trip its own
    payload (escaped quotes in a raw document, a missing fingerprint, ...).
    """
    action = _FORM_ACTION.search(preview)
    assert action, "the preview rendered no confirm form"
    fields = {
        name: html.unescape(value) for name, value in _HIDDEN_INPUT.findall(preview)
    }
    assert fields.get("confirm") == "1"
    return client.post(action.group(1), data=fields)


def _diff_cells(body: str) -> list[str]:
    return [html.unescape(cell).strip() for cell in _CODE_CELL.findall(body)]


def _backup_holding(editor, text: str) -> Path:
    """The backup whose content is exactly ``text``.

    Backups are matched by content rather than by name order: two writes inside
    the same second (which is every test here) get ``.bak`` and ``-1.bak``, and
    ``shutil.copy2`` preserves the source's mtime, so neither the name sort nor
    the mtime sort is a reliable "newest" order.
    """
    matches = [path for path in editor.backups() if path.read_bytes().decode("utf-8") == text]
    assert len(matches) == 1, f"expected one backup of that revision, got {matches}"
    return matches[0]


def _visible_paths(body: str) -> list[str]:
    return re.findall(r'<div class="ce-row" data-path="([^"]+)"', body)


def _preview_value(editor, path: str, value: str) -> str:
    return _body(
        editor.client.post(
            "/admin/config/editor/value", data={f"ce.{path}": value, "confirm": "0"}
        )
    )


# ═════════════════════════════════════════════════════════════════════════════
# The page and every fragment it is built from
# ═════════════════════════════════════════════════════════════════════════════


def test_the_page_and_every_fragment_render(editor) -> None:
    """Every URL the blueprint serves answers with its own content."""
    expectations = {
        PAGE: "Configuration editor",
        f"{PAGE}?view=tree": "Tree view",
        f"{PAGE}?view=raw": "Raw view",
        f"{PAGE}?tab=secrets": "Secrets and credentials",
        f"{PAGE}?tab=history": "Version history",
        PANEL: 'id="ce-list"',
        f"{PANEL}?view=tree": "[web_admin]",
        HISTORY: "Version history",
        "/admin/config/editor/validate": "Validated",
        "/admin/config/watcher": "Config",
    }
    for url, marker in expectations.items():
        body = _body(editor.client.get(url))
        assert marker in body, f"{url} did not render {marker!r}"


def test_a_browser_navigation_is_served_inside_the_shell(editor) -> None:
    body = _body(editor.client.get(PAGE, headers={"Sec-Fetch-Dest": "document"}))

    assert 'id="config-editor-root"' in body
    assert "<html" in body.lower()


def test_the_tree_view_shows_root_keys_and_tables(editor) -> None:
    """Regression: ``node.keys`` in Jinja resolved to the dict method, and the
    tree view raised ``TypeError: object of type 'builtin_function_or_method'
    has no len()``.  Root-level keys were dropped by the same node walk."""
    body = _body(editor.client.get(f"{PAGE}?view=tree"))

    assert "[web_admin]" in body
    assert "web_admin.port" in body
    assert "notifier.wechat.send_key" in body


def test_an_unauthenticated_request_is_refused(_app) -> None:
    response = _login_free(_app).get(PAGE)

    assert response.status_code != 200


# ═════════════════════════════════════════════════════════════════════════════
# The gated save
# ═════════════════════════════════════════════════════════════════════════════


def test_a_value_edit_previews_then_writes_one_line(editor) -> None:
    """The whole flow, asserted on the bytes of the file at every step."""
    before = editor.text()

    preview = _preview_value(editor, "web_admin.port", "12000")

    assert editor.text() == before, "a preview must not write anything"
    assert editor.backups() == []
    assert _diff_cells(preview) == ["web_admin.port", "11174", "12000"]
    assert "badge-info\">changed" in preview
    assert "restart required" in preview
    assert "Read once at startup: web_admin.port" in preview

    written = _body(_confirm(editor.client, preview))

    assert "Saved: config.toml written and reloaded." in written
    assert written.count("restart required") == 1
    assert editor.text() == before.replace(
        "port = 11174         # listen port", "port = 12000         # listen port"
    )
    # Comments, blank lines, the inline comment and the other keys are untouched.
    assert "# The admin surface.  These keys are read once, at startup." in editor.text()
    assert editor.runtime.config.reloads == 1
    assert len(editor.backups()) == 1
    assert editor.backups()[0].read_bytes() == before.encode("utf-8")


def test_the_diff_lists_only_the_keys_that_changed(editor) -> None:
    preview = _preview_value(editor, "web_admin.port", "12000")

    assert _diff_cells(preview) == ["web_admin.port", "11174", "12000"]
    assert "web_admin.host" not in preview


def test_a_batch_save_of_an_untouched_form_writes_nothing(editor) -> None:
    """Regression: a string field holds TOML text, so posting the form back
    unchanged added a second layer of quotes to every string key."""
    body = _body(editor.client.get(PAGE))
    fields = {
        name: html.unescape(value)
        for name, value in re.findall(
            r'<input class="form-input ce-value"[^>]*name="([^"]+)"[^>]*value="([^"]*)"', body
        )
    }
    assert "ce.web_admin.password_hash" not in fields  # secrets are not posted back
    assert fields["ce.web_admin.host"] == '"127.0.0.1"'  # the field shows TOML text
    before = editor.text()

    response = _body(editor.client.post("/admin/config/editor/batch", data=fields))

    assert "No changes: nothing to save." in response
    assert editor.text() == before
    assert editor.backups() == []


def test_a_save_that_introduces_an_error_is_refused(editor) -> None:
    before = editor.text()

    preview = _preview_value(editor, "web_admin.port", "99999")

    assert REFUSED in preview
    assert "[web_admin].port must be an integer between 1 and 65535." in preview
    assert editor.text() == before
    assert editor.backups() == []

    # And confirming cannot sneak it through: the gate runs before the write.
    forced = editor.client.post(
        "/admin/config/editor/value",
        data={"ce.web_admin.port": "99999", "confirm": "1", "base": ""},
    )
    assert REFUSED in _body(forced)
    assert editor.text() == before


def test_a_pre_existing_error_does_not_block_an_unrelated_save(editor) -> None:
    """Delta validation: only errors this change introduces block the save."""
    broken = editor.text().replace('name = "alpha"', 'name = "alpha/beta"')
    editor.config_path.write_bytes(broken.encode("utf-8"))
    before = editor.text()

    preview = _preview_value(editor, "web_admin.host", '"0.0.0.0"')

    # The config is already invalid (the site name has a path separator), and
    # this edit neither causes nor reports that error.
    assert "[website].name is required and must not contain path separators." in _body(
        editor.client.get("/admin/config/editor/validate")
    )
    assert REFUSED not in preview
    written = _body(_confirm(editor.client, preview))
    assert "Saved: config.toml written and reloaded." in written
    assert editor.text() == before.replace('host = "127.0.0.1"', 'host = "0.0.0.0"')


def test_a_structural_edit_is_flagged_and_still_writes_a_valid_file(editor) -> None:
    """The one kind of edit that re-serializes says so before it writes.

    Regression: an *empty* new table changes no key value, so the diff found
    nothing and the tree view's "add table or block" button could never write.
    """
    preview = _body(
        editor.client.post("/admin/config/editor/table/add", data={"table": "siem", "confirm": "0"})
    )

    assert "Structural change: config.toml is re-serialized with the project writer" in preview
    assert "Saving an empty table" in preview
    assert editor.text() == CONFIG, "a preview must not write anything"
    assert editor.backups() == []

    written = _body(_confirm(editor.client, preview))

    assert "Saved: config.toml written and reloaded." in written
    data = tomllib.loads(editor.text())
    assert data["siem"] == {}
    assert data["web_admin"]["port"] == 11174  # nothing else was lost
    assert data["website"][0]["name"] == "alpha"
    assert editor.backups()[0].read_bytes().decode("utf-8") == CONFIG


def test_removing_a_table_reports_the_keys_it_takes_away(editor) -> None:
    preview = _body(
        editor.client.post(
            "/admin/config/editor/table/remove", data={"table": "notifier.wechat", "confirm": "0"}
        )
    )

    assert "Structural change" in preview
    assert "notifier.wechat.send_key" in preview
    assert "badge-danger\">removed" in preview

    written = _body(_confirm(editor.client, preview))

    assert "Saved: config.toml written and reloaded." in written
    data = tomllib.loads(editor.text())
    assert "wechat" not in data["notifier"]
    assert data["notifier"]["enabled"] is False


def test_warnings_do_not_block_a_save(editor) -> None:
    preview = _preview_value(editor, "notifier.enabled", "true")

    assert "warnings (they do not block)" in preview
    written = _body(_confirm(editor.client, preview))

    assert "Saved: config.toml written and reloaded." in written
    assert "warnings (they do not block)" in written
    assert "enabled = true" in editor.text()


def test_a_stale_confirm_is_refused(editor) -> None:
    """The file moved between preview and confirm (another editor, the CLI)."""
    preview = _preview_value(editor, "web_admin.port", "12000")
    moved = editor.text().replace("port = 8080", "port = 8090")
    editor.config_path.write_bytes(moved.encode("utf-8"))

    refused = _body(_confirm(editor.client, preview))

    assert "Not saved: the file moved under us." in refused
    assert editor.text() == moved


def test_every_write_keeps_a_timestamped_backup(editor) -> None:
    first = editor.text()
    _confirm(editor.client, _preview_value(editor, "web_admin.port", "12000"))
    second = editor.text()
    _confirm(editor.client, _preview_value(editor, "web_admin.host", '"0.0.0.0"'))

    backups = editor.backups()

    assert len(backups) == 2
    assert sorted(path.read_bytes() for path in backups) == sorted(
        [first.encode("utf-8"), second.encode("utf-8")]
    )
    assert all(re.search(r"\.\d{8}-\d{6}(?:-\d+)?\.bak$", path.name) for path in backups)


# ── the raw view ────────────────────────────────────────────────────────────


def test_a_raw_save_of_an_unmodified_document_round_trips(editor) -> None:
    """The textarea holds the redacted file; saving it unchanged must be a no-op."""
    before = editor.config_path.read_bytes()
    raw = _raw_textarea(editor)

    assert "***REDACTED***" in raw
    response = _body(
        editor.client.post(
            "/admin/config/editor/raw",
            data={"raw_text": raw, "confirm": "1", "base": _fingerprint(editor)},
        )
    )

    assert "No changes: nothing to save." in response
    assert editor.config_path.read_bytes() == before
    assert editor.backups() == []


def test_a_raw_save_writes_a_comment_edit_verbatim(editor) -> None:
    before = editor.text()
    raw = _raw_textarea(editor).replace("# a second comment line", "# edited comment")

    preview = _body(
        editor.client.post(
            "/admin/config/editor/raw",
            data={"raw_text": raw, "confirm": "0", "base": _fingerprint(editor)},
        )
    )

    assert "Only comments or formatting changed" in preview
    assert "No key value changed." in preview
    assert editor.text() == before

    written = _body(_confirm(editor.client, preview))

    assert "Saved: config.toml written and reloaded." in written
    assert editor.text() == before.replace("# a second comment line", "# edited comment")


def test_a_raw_save_cannot_change_a_secret_line(editor) -> None:
    before = editor.text()
    raw = _raw_textarea(editor).replace(
        'password_hash = "***REDACTED***"', 'password_hash = "hunter2"'
    )

    refused = _body(
        editor.client.post(
            "/admin/config/editor/raw",
            data={"raw_text": raw, "confirm": "1", "base": _fingerprint(editor)},
        )
    )

    assert "Secret values are not editable here" in refused
    assert "hunter2" not in refused
    assert editor.text() == before


def _raw_textarea(editor) -> str:
    body = _body(editor.client.get(f"{PAGE}?view=raw"))
    match = re.search(r'<textarea class="ce-raw-edit"[^>]*>(.*?)</textarea>', body, re.S)
    assert match, "the raw view rendered no textarea"
    return html.unescape(match.group(1))


def _fingerprint(editor) -> str:
    return hashlib.sha256(editor.config_path.read_bytes()).hexdigest()[:16]


# ═════════════════════════════════════════════════════════════════════════════
# Version history, diff, restore, download
# ═════════════════════════════════════════════════════════════════════════════


def _make_revision(editor, path: str = "web_admin.port", value: str = "12000") -> str:
    """Save one value and return the backup name of the file it replaced."""
    before = editor.text()
    _confirm(editor.client, _preview_value(editor, path, value))
    return _backup_holding(editor, before).name


def test_a_crlf_config_survives_a_save_and_a_restore(editor) -> None:
    """The repository's own ``config.toml`` is CRLF; a save must not fold it.

    Regression: the document and the revision store both read with
    ``read_text``, whose universal-newline translation turned a CRLF file into
    LF, so one value edit rewrote all 649 line endings.
    """
    crlf = CONFIG.replace("\n", "\r\n")
    editor.config_path.write_bytes(crlf.encode("utf-8"))
    revision = _make_revision(editor)

    assert editor.text() == crlf.replace(
        "port = 11174         # listen port", "port = 12000         # listen port"
    )
    assert editor.text().count("\n") == editor.text().count("\r\n")

    preview = _body(
        editor.client.get(f"/admin/config/editor/revision/diff?revision=backup:{revision}")
    )
    _confirm(editor.client, preview)

    assert editor.text() == crlf


def test_the_history_lists_time_source_and_changed_keys(editor) -> None:
    _make_revision(editor)
    _make_revision(editor, "web_admin.host", '"0.0.0.0"')

    body = _body(editor.client.get(f"{PAGE}?tab=history"))

    assert "Version history" in body
    assert body.count("backup of the file") == 2
    # The changed-key count is computed from the backup's content, not stored.
    assert "1 key(s)" in body
    assert "web_admin.host" in body
    assert re.search(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}", body), "no timestamp shown"
    assert "View diff" in body and "Restore" in body and "Download" in body


def test_the_history_fragment_refreshes_on_its_own(editor) -> None:
    _make_revision(editor)

    body = _body(editor.client.get(HISTORY))

    assert 'id="ce-history"' in body
    assert "backup of the file" in body


def test_viewing_a_revision_diff_reports_only_the_changed_keys(editor) -> None:
    before = editor.text()
    revision = _make_revision(editor)

    body = _body(editor.client.get(f"/admin/config/editor/revision/diff?revision=backup:{revision}"))

    assert _diff_cells(body) == ["web_admin.port", "12000", "11174"]
    # It reads as "what restoring this would change", and only previews: the
    # file on disk is untouched until the confirm button is pressed.
    assert "Restoring this backup applies the changes below" in body
    assert "restart required" in body
    assert "Confirm save" in body
    assert editor.text() != before


def test_restore_writes_the_previous_revision_back(editor) -> None:
    original = editor.text()
    revision = _make_revision(editor)
    edited = editor.text()
    assert edited != original

    preview = _body(
        editor.client.get(f"/admin/config/editor/revision/diff?revision=backup:{revision}")
    )
    written = _body(_confirm(editor.client, preview))

    assert "Saved: config.toml written and reloaded." in written
    assert editor.text() == original, "the restore did not reproduce the file byte for byte"
    assert "restart required" in written
    assert "Read once at startup: web_admin.port" in written
    # The current file was backed up before it was replaced.
    assert _backup_holding(editor, edited).read_bytes().decode("utf-8") == edited


def test_restore_of_a_comment_only_backup_still_writes(editor) -> None:
    """A backup that differs only in comments is still a restore target."""
    before = editor.text()
    raw = _raw_textarea(editor).replace("# a second comment line", "# renamed comment")
    _confirm(
        editor.client,
        _body(
            editor.client.post(
                "/admin/config/editor/raw",
                data={"raw_text": raw, "confirm": "0", "base": _fingerprint(editor)},
            )
        ),
    )
    revision = _backup_holding(editor, before).name

    preview = _body(
        editor.client.get(f"/admin/config/editor/revision/diff?revision=backup:{revision}")
    )
    written = _body(_confirm(editor.client, preview))

    assert "Only comments or formatting changed" in written
    assert editor.text() == before


def test_restore_refuses_a_backup_that_introduces_errors(editor) -> None:
    before = editor.text()
    bad = editor.config_path.with_name("config.toml.20200101-000000.bak")
    bad.write_bytes(before.replace("port = 11174", "port = 99999").encode("utf-8"))

    preview = _body(
        editor.client.get("/admin/config/editor/revision/diff?revision=backup:config.toml.20200101-000000.bak")
    )
    refused = _body(_confirm(editor.client, preview))

    assert REFUSED in refused
    assert "[web_admin].port must be an integer between 1 and 65535." in refused
    assert editor.text() == before
    assert [path.name for path in editor.backups()] == [bad.name]


def test_restore_refuses_a_stale_base(editor) -> None:
    revision = _make_revision(editor)
    moved = editor.text().replace("port = 8080", "port = 8090")
    editor.config_path.write_bytes(moved.encode("utf-8"))

    response = _body(
        editor.client.post(
            "/admin/config/editor/revision/restore",
            data={"revision": f"backup:{revision}", "base": "0000000000000000"},
        )
    )

    assert "changed on disk since the preview" in response
    assert editor.text() == moved


def test_a_recorded_change_is_read_only(editor) -> None:
    """It stores no content, so it must not offer an action it cannot complete."""
    _make_revision(editor)
    records = [
        row for row in editor.history.get_history(limit=10) if row.get("user_triggered")
    ]
    assert records, "the save recorded no history entry"

    body = _body(
        editor.client.get(f"/admin/config/editor/revision/diff?revision=change:{records[0]['id']}")
    )

    assert "it can be read but not restored or downloaded" in body
    assert "Confirm save" not in body
    assert "read-only record" in _body(editor.client.get(f"{PAGE}?tab=history"))


def test_a_revision_download_redacts_the_secrets(editor) -> None:
    revision = _make_revision(editor)

    response = editor.client.get(
        f"/admin/config/editor/revision/download?revision=backup:{revision}"
    )

    assert response.status_code == 200
    assert response.mimetype == "text/plain"
    body = response.get_data(as_text=True)
    assert CONFIG_SECRET not in body
    assert "***REDACTED***" in body
    assert "attachment" in response.headers["Content-Disposition"]
    assert response.headers["Content-Disposition"].endswith(f'filename="{revision}"')


@pytest.mark.parametrize(
    "revision",
    [
        "",
        "backup:",
        "backup:../../config.toml",
        "backup:..\\..\\config.toml",
        "backup:/etc/passwd",
        "backup:config.toml.tmp",
        "change:2026-01-01T00:00:00",
    ],
)
def test_a_download_only_ever_serves_a_known_backup(editor, revision) -> None:
    response = editor.client.get(f"/admin/config/editor/revision/download?revision={revision}")

    assert response.status_code == 200  # answered inline, never a 500
    body = response.get_data(as_text=True)
    assert "no stored content to download" in body
    assert "attachment" not in response.headers.get("Content-Disposition", "")
    assert "web_admin" not in body


# ═════════════════════════════════════════════════════════════════════════════
# Secrets never travel back to a browser
# ═════════════════════════════════════════════════════════════════════════════


def test_no_secret_reaches_any_rendered_page(editor) -> None:
    """Sweep every GET the blueprint serves, then every mutation result."""
    _make_revision(editor)
    revision = editor.backups()[-1].name
    urls = [
        PAGE,
        f"{PAGE}?tab=secrets",
        f"{PAGE}?tab=history",
        f"{PAGE}?view=tree",
        f"{PAGE}?view=raw",
        PANEL,
        HISTORY,
        "/admin/config/editor/validate",
        f"/admin/config/editor/revision/diff?revision=backup:{revision}",
    ]
    for url in urls:
        body = _body(editor.client.get(url))
        for secret in (CONFIG_SECRET, ENV_SECRET, ENV_PASSWORD_HASH):
            assert secret not in body, f"{url} leaked a secret"
    assert _body(editor.client.get(f"{PAGE}?view=raw")).count("***REDACTED***") >= 1


def test_a_secret_key_is_never_editable_in_the_form_view(editor) -> None:
    body = _body(editor.client.get(PAGE))

    assert 'name="ce.web_admin.password_hash"' not in body
    assert 'name="ce.notifier.wechat.send_key"' not in body
    # Shown as a disabled control with the reason, never as an input field.
    assert 'value="***REDACTED***" disabled' in body
    assert "Set a new password instead of editing this hash." in body
    assert "Secret: set it in .env, never here." in body


def test_the_env_tab_is_write_only(editor) -> None:
    before = _body(editor.client.get(f"{PAGE}?tab=secrets"))

    assert "write-only: values are never shown" in before
    assert ENV_SECRET not in before
    assert ENV_PASSWORD_HASH not in before
    assert "ANTEUMBRA_WECHAT_API_KEY" in before
    assert "ANTEUMBRA_SECRET_KEY" in before  # named only to explain why it is not editable

    written = _body(
        editor.client.post(
            "/admin/config/editor/env",
            data={"key": "ANTEUMBRA_EMAIL_PASSWORD", "value": "mail-secret-NEW"},
        )
    )

    assert "written to .env; the value is never shown again." in written
    assert "mail-secret-NEW" not in written
    assert "ANTEUMBRA_EMAIL_PASSWORD=mail-secret-NEW" in editor.env_path.read_text("utf-8")
    assert ENV_SECRET in editor.env_path.read_text("utf-8")  # the others survived


def test_the_password_flow_hashes_and_never_echoes(editor) -> None:
    response = _body(
        editor.client.post(
            "/admin/config/editor/password",
            data={"password": "Str0ngPassw0rd!", "password_confirm": "Str0ngPassw0rd!"},
        )
    )

    assert "The new password is active for the next sign-in." in response
    assert "Str0ngPassw0rd!" not in response
    stored = dict(
        line.split("=", 1)
        for line in editor.env_path.read_text("utf-8").splitlines()
        if "=" in line
    )["ANTEUMBRA_PASSWORD_HASH"]

    from werkzeug.security import check_password_hash

    assert stored != "Str0ngPassw0rd!"
    assert check_password_hash(stored, "Str0ngPassw0rd!")
    assert not check_password_hash(stored, "wrong-password")


def test_the_password_flow_refuses_a_short_or_mismatched_password(editor) -> None:
    before = editor.env_path.read_text("utf-8")

    short = _body(editor.client.post("/admin/config/editor/password", data={"password": "abc"}))
    mismatched = _body(
        editor.client.post(
            "/admin/config/editor/password",
            data={"password": "Str0ngPassw0rd!", "password_confirm": "other"},
        )
    )

    assert "at least 8 characters" in short
    assert "do not match" in mismatched
    assert editor.env_path.read_text("utf-8") == before


# ═════════════════════════════════════════════════════════════════════════════
# Search and the readability filters
# ═════════════════════════════════════════════════════════════════════════════


def test_search_matches_key_paths(editor) -> None:
    body = _body(editor.client.get(f"{PAGE}?q=send_key"))

    assert _visible_paths(body) == ["notifier.wechat.send_key"]


def test_search_matches_values(editor) -> None:
    body = _body(editor.client.get(f"{PAGE}?q=127.0.0.1"))

    assert _visible_paths(body) == ["web_admin.host", "web_admin.allowed_ips"]
    assert "11174" not in _visible_paths(body)


def test_search_reports_nothing_for_a_query_that_matches_nothing(editor) -> None:
    body = _body(editor.client.get(f"{PAGE}?q=nothing-matches-this"))

    assert _visible_paths(body) == []
    assert "No key matches the current filters." in body


def test_the_only_values_set_here_filter_hides_unset_placeholders(editor) -> None:
    assert "notifier.unused_placeholder" in _visible_paths(_body(editor.client.get(PAGE)))

    filtered = _visible_paths(_body(editor.client.get(f"{PAGE}?set_only=1")))

    assert "notifier.unused_placeholder" not in filtered
    assert "web_admin.port" in filtered


def test_the_changed_from_defaults_filter_uses_the_shipped_document(editor, monkeypatch) -> None:
    """A key identical to the reference document is hidden by the filter."""
    from anteumbra.application import config_document as cd

    monkeypatch.setattr(
        bp,
        "_reference_document",
        lambda: cd.ConfigDocument(CONFIG.replace("port = 11174", "port = 8080")),
    )

    assert "web_admin.host" in _visible_paths(_body(editor.client.get(PAGE)))

    filtered = _visible_paths(_body(editor.client.get(f"{PAGE}?non_default=1")))

    assert filtered == ["web_admin.port"]
    assert "1 changed from defaults" in _body(editor.client.get(f"{PAGE}?non_default=1"))


def test_filters_and_search_survive_a_panel_refresh(editor) -> None:
    body = _body(editor.client.get(f"{PANEL}?view=tree&q=web_admin&set_only=1"))

    assert 'id="ce-list"' in body
    assert "web_admin.port" in body
    assert "notifier.unused_placeholder" not in body
