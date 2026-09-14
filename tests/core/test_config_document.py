# -*- coding: utf-8 -*-
"""The document model behind the config editor.

``application.config_document`` is the whole reason the advanced editor can
promise not to ruin a documented file, so its contract is pinned here: a leaf
edit rewrites one line and copies every other byte through, a structural edit is
the *only* thing that re-serializes, the diff is semantic (changed keys only),
search reaches key paths, values and comments without ever reading a secret, and
secret literals are redacted in every direction.
"""

from __future__ import annotations

import pytest

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10
    import tomli as tomllib

from anteumbra.application.config_document import (
    REDACTION,
    ConfigDocument,
    ConfigDocumentError,
    KeyNotFound,
    StructuralEditRequired,
    coerce_value,
    flatten,
    format_value,
    is_secret_path,
    split_lines,
)

#: A miniature of the real file: comments above keys and above headers, inline
#: trailing comments, blank lines, mixed spacing.  Every one of them has to
#: survive a value edit.
DOCUMENT = """\
# Anteumbra probe config
# second comment line, still part of the documentation

system = "probe"          # the release name
debug = false

[paths]
monitor_paths = ["/srv/a", "/srv/b"]

# The admin surface.  These keys are read once, at startup.
[web_admin]
host = "127.0.0.1"
port = 11174              # listen port
allowed_ips = ["127.0.0.1"]
password_hash = "${ANTEUMBRA_PASSWORD_HASH:?}"

[notifier]
enabled = false
"""


def _doc(text: str = DOCUMENT, **env: str) -> ConfigDocument:
    return ConfigDocument(text, env=env, dotenv_names=env)


#: An array of tables, for the structural controls the tree view offers per block.
BLOCKS = """\
[[website]]
name = "alpha"
port = 8080

[[website]]
name = "beta"
port = 8081
"""


def _blocks_doc() -> ConfigDocument:
    return ConfigDocument(BLOCKS, path="config.toml")


# ── leaf edits: byte fidelity ────────────────────────────────────────────────


def test_surgical_edit_replaces_exactly_one_line() -> None:
    """The load-bearing promise: whole-file equality with one line swapped.

    Not "the comments are still there" - every byte outside the edited line is
    asserted, which is what an operator with a documented ``config.toml`` in git
    is actually relying on.
    """
    edited = _doc().set_leaf("web_admin.port", 12000)

    assert edited.text == DOCUMENT.replace(
        "port = 11174              # listen port",
        "port = 12000              # listen port",
    )
    # Equivalently: the edit is reversible by undoing only the new value.
    assert edited.text.replace("12000", "11174") == DOCUMENT
    assert edited.text.count("12000") == 1


def test_surgical_edits_leave_comments_and_blank_lines_alone() -> None:
    doc = _doc()
    edited = doc.set_leaf("system", "release").set_leaf("notifier.enabled", True)

    assert "# second comment line, still part of the documentation" in edited.text
    assert "# The admin surface.  These keys are read once, at startup." in edited.text
    assert "# listen port" in edited.text
    assert edited.text.count("\n\n") == DOCUMENT.count("\n\n")
    assert len(edited.lines) == len(doc.lines)


def test_surgical_edit_keeps_a_crlf_document_crlf() -> None:
    """A Windows checkout must not become half CRLF, half LF."""
    crlf = DOCUMENT.replace("\n", "\r\n")
    edited = _doc(crlf).set_leaf("web_admin.port", 12000)

    assert edited.text == crlf.replace(
        "port = 11174              # listen port",
        "port = 12000              # listen port",
    )
    assert edited.text.count("\n") == edited.text.count("\r\n")


def test_surgical_edit_retypes_every_scalar_kind() -> None:
    doc = _doc()
    edited = (
        doc.set_leaf("debug", True)
        .set_leaf("paths.monitor_paths", ["/srv/c"])
        .set_leaf("web_admin.host", "0.0.0.0")
    )
    data = edited.data()

    assert data["debug"] is True
    assert data["paths"]["monitor_paths"] == ["/srv/c"]
    assert data["web_admin"]["host"] == "0.0.0.0"


def test_adding_a_leaf_touches_only_the_end_of_its_table() -> None:
    """A new key lands at the end of its table's body, before the next header."""
    edited = _doc().add_leaf("web_admin.session_timeout", 3600)

    assert edited.text == DOCUMENT.replace(
        'password_hash = "${ANTEUMBRA_PASSWORD_HASH:?}"\n',
        'password_hash = "${ANTEUMBRA_PASSWORD_HASH:?}"\nsession_timeout = 3600\n',
    )
    assert edited.data()["web_admin"]["session_timeout"] == 3600
    # It stayed inside [web_admin]: after the comment that documents it, and
    # before the next header.
    assert edited.text.index("# The admin surface") < edited.text.index("session_timeout")
    assert edited.text.index("session_timeout") < edited.text.index("[notifier]")


def test_removing_a_leaf_keeps_its_siblings_and_comments() -> None:
    edited = _doc().remove_leaf("web_admin.port")

    assert "port = 11174" not in edited.text
    assert "# listen port" not in edited.text  # it lived on the removed line
    assert edited.text == DOCUMENT.replace("port = 11174              # listen port\n", "")
    assert edited.data()["web_admin"]["host"] == "127.0.0.1"


def test_editing_a_missing_key_is_refused() -> None:
    with pytest.raises(KeyNotFound):
        _doc().set_leaf("web_admin.nope", 1)


# ── submitted text -> typed value ───────────────────────────────────────────


def test_a_string_field_round_trips_through_its_own_rendering() -> None:
    """The form shows TOML text, so re-posting it must yield the same value.

    Regression: a string field holds ``"probe"`` (quotes included), and reading
    that literally stored a second layer of quotes - every string key drifted on
    each pass through the form, including an untouched one.
    """
    doc = _doc()
    ref = doc.find("system")
    assert ref is not None

    field = format_value(ref.value)
    assert field == '"probe"'
    assert coerce_value(field, ref.value) == "probe"


def test_an_unquoted_string_field_is_taken_literally() -> None:
    """What an operator types is what they mean - including bracket-ish text."""
    assert coerce_value("nginx", "old") == "nginx"
    assert coerce_value("[MONITOR][START][SUCCESS]", "[MONITOR][START][SUCCESS]") == (
        "[MONITOR][START][SUCCESS]"
    )
    assert coerce_value('"quoted"', "old") == "quoted"
    assert coerce_value('"unbalanced', "old") == '"unbalanced'


def test_typed_fields_keep_the_type_on_disk() -> None:
    doc = _doc()
    assert coerce_value("8080", doc.key_value("web_admin.port")) == 8080
    assert coerce_value("yes", doc.key_value("debug")) is True
    assert coerce_value('["10.0.0.0/8"]', doc.key_value("web_admin.allowed_ips")) == [
        "10.0.0.0/8"
    ]
    with pytest.raises(ConfigDocumentError):
        coerce_value("not-a-port", doc.key_value("web_admin.port"))
    with pytest.raises(ConfigDocumentError):
        coerce_value("maybe", doc.key_value("debug"))


# ── structural edits ────────────────────────────────────────────────────────


def test_a_structural_edit_is_a_reformat_the_caller_must_flag() -> None:
    """Only a structural edit re-serializes - and it says so by its result.

    The editor marks these candidates ``structural`` and warns that comments may
    move (``admin/config_editor_result.html``); the model's half of that contract
    is that the output is still a valid document.
    """
    doc = _doc()
    edited = doc.add_table("siem", {"enabled": False})

    assert edited.text != doc.text
    assert "documentation" not in edited.text  # comments really are reformatted
    data = tomllib.loads(edited.text)
    assert data["siem"] == {"enabled": False}
    # Everything that was there is still there.
    assert data["web_admin"]["port"] == 11174
    assert data["paths"]["monitor_paths"] == ["/srv/a", "/srv/b"]


def test_structural_edits_keep_the_documents_own_line_ending() -> None:
    crlf = DOCUMENT.replace("\n", "\r\n")
    edited = _doc(crlf).add_array_item("paths.monitor_paths", "/srv/c")

    assert edited.data()["paths"]["monitor_paths"] == ["/srv/a", "/srv/b", "/srv/c"]
    assert "\r\n" in edited.text
    assert edited.text.count("\n") == edited.text.count("\r\n")


def test_a_table_value_cannot_be_written_as_one_key() -> None:
    """An inline table is still a container: editing it is structural."""
    doc = ConfigDocument('x = { a = 1 }\nweb_admin.port = 1\n')

    with pytest.raises(StructuralEditRequired):
        doc.set_leaf("x", {"a": 2})


def test_removing_one_block_of_an_array_of_tables_keeps_the_others() -> None:
    """The tree view's "remove this block" must remove one block.

    Regression: the index was stripped before the delete, so removing
    ``website[0]`` removed *every* ``[[website]]`` block.
    """
    doc = _blocks_doc()

    edited = doc.remove_table("website[0]")

    assert tomllib.loads(edited.text)["website"] == [{"name": "beta", "port": 8081}]


def test_appending_to_an_indexed_array_table_path_adds_a_block() -> None:
    """The tree node for a block posts its indexed path."""
    edited = _blocks_doc().add_array_item("website[0]", {"name": "gamma"})

    assert [item["name"] for item in tomllib.loads(edited.text)["website"]] == [
        "alpha",
        "beta",
        "gamma",
    ]


def test_a_new_table_is_a_plain_table_not_an_array_of_one() -> None:
    """``[[siem]]`` is a list where every consumer expects a mapping."""
    data = tomllib.loads(_doc().add_table("siem", {"enabled": False}).text)

    assert data["siem"] == {"enabled": False}


def test_adding_to_an_existing_single_table_makes_it_an_array_of_tables() -> None:
    """That is what "add a second site" means in TOML."""
    data = tomllib.loads(_doc().add_table("notifier", {"enabled": True}).text)

    assert data["notifier"] == [{"enabled": False}, {"enabled": True}]


def test_a_comment_inside_a_multi_line_value_blocks_a_leaf_edit() -> None:
    """Refused rather than silently dropping the comment."""
    text = 'x = [\n    1,  # keep me\n    2,\n]\n'
    with pytest.raises(StructuralEditRequired):
        ConfigDocument(text).set_leaf("x", [3])


# ── diffs ───────────────────────────────────────────────────────────────────


def test_the_diff_lists_only_the_keys_that_changed() -> None:
    before = _doc()
    after = before.set_leaf("web_admin.port", 12000).add_leaf("web_admin.session_timeout", 60)

    changes = before.diff(after)

    assert [(change.path, change.kind) for change in changes] == [
        ("web_admin.port", "changed"),
        ("web_admin.session_timeout", "added"),
    ]
    assert changes[0].old == 11174 and changes[0].new == 12000


def test_the_diff_reports_a_removed_key() -> None:
    changes = _doc().diff(_doc().remove_leaf("debug"))

    assert [(change.path, change.kind) for change in changes] == [("debug", "removed")]
    assert changes[0].old is False and changes[0].new is None


def test_a_comment_only_change_is_not_a_key_change() -> None:
    """The raw view needs this: the text moved, no key did."""
    before = _doc()
    after = before.with_text(before.text.replace("# listen port", "# listening port"))

    assert before.diff(after) == []
    assert before.text != after.text


def test_reference_diff_reads_as_what_we_changed() -> None:
    reference = _doc(DOCUMENT.replace("port = 11174", "port = 8080"))

    changes = reference.diff(_doc())

    assert [change.path for change in changes] == ["web_admin.port"]
    assert _doc().reference_diff(reference) == changes


# ── search and filters ──────────────────────────────────────────────────────


def test_search_matches_key_paths_values_and_comments() -> None:
    doc = _doc()

    assert [hit.path for hit in doc.search("monitor_paths")] == ["paths.monitor_paths"]
    assert [hit.field for hit in doc.search("monitor_paths")] == ["key"]
    assert [hit.path for hit in doc.search("127.0.0.1")] == [
        "web_admin.host",
        "web_admin.allowed_ips",
    ]
    assert {hit.field for hit in doc.search("127.0.0.1")} == {"value"}
    assert [hit.path for hit in doc.search("listen port")] == ["web_admin.port"]
    assert doc.search("nothing-matches-this") == []
    assert doc.search("   ") == []


def test_search_never_reads_a_secret_value() -> None:
    """A hit on a secret key reports the path; the value is not even searched."""
    doc = ConfigDocument('web_admin.password_hash = "scrtopsecret"\n', path="config.toml")

    assert doc.search("password_hash")[0].path == "web_admin.password_hash"
    assert doc.search("password_hash")[0].value_display == REDACTION
    assert doc.search("scrtopsecret") == []


def test_flatten_keeps_a_scalar_array_as_one_leaf() -> None:
    """Editing one element of an array is a new array, not a value edit."""
    flat = flatten({"paths": {"monitor_paths": ["a", "b"], "nested": [{"k": 1}, {"k": 2}]}})

    assert flat["paths.monitor_paths"] == ["a", "b"]
    assert flat["paths.nested[0].k"] == 1
    assert flat["paths.nested[1].k"] == 2


# ── secrets ─────────────────────────────────────────────────────────────────


def test_only_literal_secret_values_are_spanned() -> None:
    """A ``${...}`` placeholder is documentation; a typed-in hash is a secret."""
    doc = ConfigDocument(
        'web_admin.password_hash = "scrypt$real"\n'
        'notifier.token = "${ANTEUMBRA_WECHAT_API_KEY:?}"\n'
        'notifier.enabled = false\n'
    )

    spans = doc.secret_spans()

    assert [span.path for span in spans] == ["web_admin.password_hash"]
    assert spans[0].original == '"scrypt$real"'
    assert "scrypt$real" not in doc.redacted_text()
    assert "${ANTEUMBRA_WECHAT_API_KEY:?}" in doc.redacted_text()


def test_redacted_text_is_still_valid_toml() -> None:
    doc = ConfigDocument(
        'title = "probe"\nweb_admin.password_hash = "scrypt$real"\n',
        path="config.toml",
    )

    redacted = doc.redacted_text()

    assert tomllib.loads(redacted)["web_admin"]["password_hash"] == REDACTION
    # Redacting an already redacted file is a no-op, so the raw view can be
    # rendered, saved and rendered again without drifting.
    assert ConfigDocument(redacted).redacted_text() == redacted
    assert "scrypt$real" not in redacted


def test_secret_names_are_matched_on_the_last_segment() -> None:
    assert is_secret_path("web_admin.password_hash")
    assert is_secret_path("notifier.email.password")
    assert is_secret_path("website[0].api_key")
    assert not is_secret_path("web_admin.password_hash_hint")
    assert not is_secret_path("logging.symbols.success")


# ── effective values ────────────────────────────────────────────────────────


def test_placeholders_resolve_the_way_the_loader_resolves_them() -> None:
    doc = _doc(ANTEUMBRA_PASSWORD_HASH="scrypt$from-env")

    from_env = doc.effective("web_admin.password_hash")
    assert from_env.value == "scrypt$from-env"
    assert from_env.source == ".env"
    assert from_env.display == REDACTION

    assert _doc().effective("web_admin.password_hash").source == "unset"
    assert _doc().effective("web_admin.nope").source == "missing"
    assert _doc().effective("system").source == "config.toml"


def test_a_document_with_an_inline_default_uses_it() -> None:
    doc = ConfigDocument('x = "${MISSING_VAR:-fallback}"\n')

    effective = doc.effective("x")

    assert (effective.value, effective.source) == ("fallback", "default")


# ── raw text plumbing ───────────────────────────────────────────────────────


def test_split_lines_is_lossless() -> None:
    for text in ("", "a\n", "a\r\nb\r\n", "a\rb", "no trailing newline", "a\n\n\nb"):
        assert "".join(split_lines(text)) == text


def test_load_preserves_the_line_endings_on_disk(tmp_path) -> None:
    """Regression: ``read_text`` folded CRLF into LF, so the next edit rewrote
    every line ending in a Windows checkout's config.toml."""
    target = tmp_path / "config.toml"
    target.write_bytes(DOCUMENT.replace("\n", "\r\n").encode("utf-8"))

    doc = ConfigDocument.load(target)
    edited = doc.set_leaf("web_admin.port", 12000)

    assert doc.text.count("\r\n") == doc.text.count("\n")
    assert edited.text.count("\n") == edited.text.count("\r\n")
    assert edited.text.replace("12000", "11174") == doc.text


def test_load_rejects_text_that_is_not_toml() -> None:
    with pytest.raises(ConfigDocumentError):
        ConfigDocument("this is not toml").data()
