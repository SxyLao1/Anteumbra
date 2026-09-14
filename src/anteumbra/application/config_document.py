"""Raw-text-first document model behind the admin configuration editor.

``config.toml`` is the runtime's only source of truth and it is *documented in
place*: the shipped file carries Chinese/English comments, ``# @desc:`` hints
and deliberately grouped keys.  A model that parses the file into a dict and
writes it back destroys all of that, so this module treats the **raw text** as
the document and keeps a parsed view beside it:

* a *leaf edit* rewrites only the lines that carry the value.  Every other byte
  - comments, blank lines, key order, indentation, trailing comments and even
  ``\\r\\n`` line endings - is copied through untouched;
* only a *structural* edit (adding/removing a table, an array item or a
  ``[[website]]`` block) changes the shape of the document, and therefore has
  to re-serialize.  That path uses ``tomli_w`` - the same serializer
  ``cli/config_support.write_toml_file`` uses - and is always reported as
  structural so the caller can warn that comments may be reformatted.

Nothing here imports Flask, touches the network, or writes files: the model is
pure, so the whole edit pipeline (locate line -> rewrite -> diff -> classify)
is unit-testable without an application.  The blueprint owns the file writes.
"""

from __future__ import annotations

import copy
import json
import re
import sys
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import tomli_w

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - Python 3.10 support
    import tomli as tomllib

__all__ = [
    "REDACTION",
    "SECRET_KEY_NAMES",
    "Change",
    "ConfigDocument",
    "ConfigDocumentError",
    "Effective",
    "KeyNotFound",
    "KeyRef",
    "SecretSpan",
    "StructuralEditRequired",
    "TableRef",
    "TreeNode",
    "coerce_value",
    "format_value",
    "infer_value",
    "load_value_text",
    "render_value_block",
    "split_lines",
]

#: What a secret value is replaced with on its way to a browser.  The marker is
#: quoted on purpose: the redacted text stays valid TOML, so the raw view can be
#: re-parsed, diffed and validated without special-casing it.
REDACTION = "***REDACTED***"

_MISSING = object()

#: Last-segment names whose values must never reach a browser.  Anything that
#: resolves through a ``${ENV_VAR}`` placeholder is handled separately: the
#: placeholder is not a secret, the value it resolves to is.
SECRET_KEY_NAMES = frozenset(
    {
        "password",
        "password_hash",
        "passwd",
        "secret",
        "secret_key",
        "api_key",
        "apikey",
        "token",
        "auth_token",
        "access_token",
        "refresh_token",
        "webhook_secret",
        "client_secret",
        "private_key",
        "send_key",
    }
)

_PLACEHOLDER_RE = re.compile(r"^\$\{([A-Za-z_][A-Za-z0-9_]*)(?::([-?])([^}]*))?\}$")
_LINE_RE = re.compile(r"[^\r\n]*(?:\r\n|\r|\n)")
_BARE_KEY_RE = re.compile(r"[A-Za-z0-9_-]+")
_INDEX_RE = re.compile(r"\[(\d+)\]")


class ConfigDocumentError(ValueError):
    """An edit that cannot be expressed against the document as it stands."""


class KeyNotFound(ConfigDocumentError):
    """The requested dotted key does not exist in the document."""


class StructuralEditRequired(ConfigDocumentError):
    """The edit changes the shape of the document, not one value."""


def split_lines(text: str) -> list[str]:
    """Split ``text`` into lines that keep their own ``\\n`` / ``\\r\\n`` ending.

    ``str.splitlines`` also breaks on form feeds and U+2028, which would make
    "preserve the file byte for byte" quietly false for a value that contains
    one.  ``"".join(split_lines(text)) == text`` always holds here.
    """
    lines = _LINE_RE.findall(text)
    consumed = sum(len(line) for line in lines)
    if consumed < len(text):
        lines.append(text[consumed:])
    return lines


def load_value_text(text: str) -> Any:
    """Parse one TOML value written as text, e.g. ``["a", "b"]``."""
    try:
        return tomllib.loads(f"v = {text}\n")["v"]
    except Exception as exc:  # noqa: BLE001 - every parse failure is caller input
        raise ConfigDocumentError(f"Not a valid TOML value: {text!r} ({exc})") from exc


def format_value(value: Any, *, secret: bool = False) -> str:
    """Render a value as single-line TOML text for an editor field.

    Containers go through ``tomli_w`` and have their whitespace collapsed, so
    the text is always something TOML can read back - JSON would be wrong for an
    array of tables (``[{name = "x"}]``) and accepts shapes TOML rejects.
    ``None`` (an unresolved ``${VAR:?}``) renders empty.
    """
    if secret:
        return REDACTION
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    text = tomli_w.dumps({"v": value}).split("=", 1)[1].strip()
    return " ".join(text.split())


def render_value_block(value: Any) -> str:
    """Render a value the way it should appear after ``key = `` in the file.

    Arrays keep ``tomli_w``'s multi-line layout (the project writer's shape);
    anything that would need its own table header is refused, because inserting
    one is a structural change, not a value edit.
    """
    if isinstance(value, dict):
        raise StructuralEditRequired("a table value cannot be written as one key")
    if isinstance(value, list):
        return tomli_w.dumps({"v": value}).split("=", 1)[1].strip()
    return format_value(value)


def infer_value(text: str) -> Any:
    """Type an edited value for a key that does not exist yet.

    Order matters: ``true`` is a bool before it can be a string, and ``5`` is an
    int before it can be a float.  A bare word stays a string, so typing
    ``nginx`` cannot become a syntax error inside the config.
    """
    stripped = text.strip()
    lowered = stripped.lower()
    if lowered in ("true", "false"):
        return lowered == "true"
    if stripped[:1] in ("[", "{", '"', "'") or lowered in ("inf", "-inf", "nan"):
        return load_value_text(stripped)
    try:
        return int(stripped)
    except ValueError:
        pass
    try:
        return float(stripped)
    except ValueError:
        pass
    return stripped


def coerce_value(text: str, current: Any = _MISSING) -> Any:
    """Type a submitted field value using the type the document already has.

    The form view posts text, so the type has to come from somewhere.  It comes
    from the value on disk: a bool field cannot become the string ``"true"`` and
    a port cannot silently become ``"8080"``.  Strings are *always* taken
    literally (so ``logging.symbols.success = "[MONITOR][START][SUCCESS]"``
    keeps working), and containers are parsed as TOML because that is the only
    way to express one in a text field.
    """
    stripped = text.strip()
    if current is _MISSING:
        return infer_value(stripped)
    if isinstance(current, bool):
        lowered = stripped.lower()
        if lowered in ("true", "1", "yes", "on"):
            return True
        if lowered in ("false", "0", "no", "off"):
            return False
        raise ConfigDocumentError(f"Expected true or false, got {stripped!r}")
    if isinstance(current, int) and not isinstance(current, bool):
        try:
            return int(stripped)
        except ValueError as exc:
            raise ConfigDocumentError(f"Expected an integer, got {stripped!r}") from exc
    if isinstance(current, float):
        try:
            return float(stripped)
        except ValueError as exc:
            raise ConfigDocumentError(f"Expected a number, got {stripped!r}") from exc
    if isinstance(current, (list, dict)):
        parsed = load_value_text(stripped)
        if not isinstance(parsed, type(current)):
            raise ConfigDocumentError(
                f"Expected {'an array' if isinstance(current, list) else 'a table'}, "
                f"got {stripped!r}"
            )
        return parsed
    if current is None:
        return infer_value(stripped) if stripped else None
    return stripped


@dataclass(frozen=True)
class KeyRef:
    """One ``key = value`` line (or value block) of the document."""

    path: str
    key: str
    table: str
    line: int
    end_line: int
    indent: str
    raw_line: str
    value_text: str
    comment: str
    kind: str
    value: Any
    multiline: bool = False
    interior_comment: bool = False

    @property
    def line_count(self) -> int:
        return self.end_line - self.line + 1


@dataclass(frozen=True)
class TableRef:
    """One ``[table]`` or ``[[array.of.tables]]`` header."""

    path: str
    base: str
    kind: str
    index: int | None
    line: int
    header: str

    @property
    def label(self) -> str:
        if self.kind == "array_table":
            return f"[[{self.base}]]"
        return f"[{self.base}]"


@dataclass(frozen=True)
class TreeNode:
    """A table plus the keys and child tables it owns, in document order."""

    path: str
    label: str
    kind: str
    line: int
    keys: list[KeyRef] = field(default_factory=list)
    children: list["TreeNode"] = field(default_factory=list)


@dataclass(frozen=True)
class Change:
    """One entry of the semantic diff: ``path: old -> new``."""

    path: str
    kind: str
    old: Any = None
    new: Any = None

    @property
    def label(self) -> str:
        return {"changed": "changed", "added": "added", "removed": "removed"}[self.kind]


@dataclass(frozen=True)
class Effective:
    """The value a control shows, and where it came from."""

    path: str
    value: Any
    source: str
    raw: Any
    env_var: str | None = None
    secret: bool = False

    @property
    def display(self) -> str:
        return format_value(self.value, secret=self.secret)


@dataclass(frozen=True)
class SecretSpan:
    """Where a secret value sits in the raw text."""

    path: str
    start: int
    end: int
    line: int
    original: str
    redacted: str


@dataclass(frozen=True)
class SearchHit:
    """One search result: a key path match or a value match."""

    path: str
    line: int
    field: str
    value_display: str
    secret: bool = False


def key_name(path: str) -> str:
    """Last segment of a dotted path, without any ``[i]`` index."""
    segment = path.rsplit(".", 1)[-1]
    return _INDEX_RE.sub("", segment)


def is_secret_path(path: str) -> bool:
    """Whether a value at ``path`` must never be echoed to a browser."""
    return key_name(path).strip().lower() in SECRET_KEY_NAMES


def parent_path(path: str) -> str:
    """The path one level up: ``a.b[0].c`` -> ``a.b[0]``, ``a`` -> ``""``."""
    if path.endswith("]"):
        return path[: path.rfind("[")]
    if "." not in path:
        return ""
    return path.rsplit(".", 1)[0]


def _strip_index(path: str) -> str:
    return _INDEX_RE.sub("", path)


def _path_segments(path: str) -> list[tuple[str, int | None]] | None:
    """``a.b[1].c`` -> ``[("a", None), ("b", 1), ("c", None)]``."""
    segments: list[tuple[str, int | None]] = []
    for part in path.split("."):
        if not part:
            return None
        match = _INDEX_RE.search(part)
        if match:
            name = part[: match.start()]
            if not name or not part.endswith("]"):
                return None
            segments.append((name, int(match.group(1))))
        else:
            segments.append((part, None))
    return segments


def _delete_in(data: dict, path: str) -> bool:
    segments = _path_segments(path)
    if not segments:
        return False
    node: Any = data
    for segment, index in segments[:-1]:
        if not isinstance(node, dict) or segment not in node:
            return False
        node = node[segment]
        if index is not None:
            if not isinstance(node, list) or index >= len(node):
                return False
            node = node[index]
    name, index = segments[-1]
    if not isinstance(node, dict) or name not in node:
        return False
    if index is None:
        del node[name]
        return True
    if not isinstance(node[name], list) or index >= len(node[name]):
        return False
    del node[name][index]
    return True


def flatten(data: Mapping[str, Any] | Sequence[Any] | Any, prefix: str = "") -> dict[str, Any]:
    """Flat ``dotted.path -> leaf value`` view used for diffs and defaults.

    Tables and arrays-of-tables descend (so ``ip_blocker.devices[0].name`` is a
    leaf); an array of scalars stays one leaf, because rewriting one element of
    it is not a value edit an operator performs - it is a new array.
    """
    flat: dict[str, Any] = {}
    if isinstance(data, Mapping):
        for key, value in data.items():
            child = f"{prefix}.{key}" if prefix else str(key)
            if isinstance(value, Mapping):
                flat.update(flatten(value, child))
            elif isinstance(value, list) and any(isinstance(item, Mapping) for item in value):
                for index, item in enumerate(value):
                    if isinstance(item, Mapping):
                        flat.update(flatten(item, f"{child}[{index}]"))
                    else:
                        flat[f"{child}[{index}]"] = item
            else:
                flat[child] = value
    elif isinstance(data, list):
        for index, item in enumerate(data):
            flat.update(flatten(item, f"{prefix}[{index}]"))
    return flat


class ConfigDocument:
    """A ``config.toml`` text plus everything the editor needs to edit it."""

    def __init__(
        self,
        text: str,
        *,
        path: str | Path | None = None,
        env: Mapping[str, str] | None = None,
        dotenv_names: Iterable[str] | None = None,
    ) -> None:
        self.text = text
        self.path = Path(path) if path is not None else None
        self.env: dict[str, str] = dict(env or {})
        self.dotenv_names: frozenset[str] = frozenset(dotenv_names or ())
        self._lines = split_lines(text)
        self._keys: list[KeyRef] = []
        self._tables: list[TableRef] = []
        self._data: dict[str, Any] | None = None
        self._parse()

    # -- construction ------------------------------------------------------

    @classmethod
    def load(
        cls,
        path: str | Path,
        *,
        env: Mapping[str, str] | None = None,
        dotenv_names: Iterable[str] | None = None,
    ) -> "ConfigDocument":
        target = Path(path)
        text = target.read_text(encoding="utf-8")
        return cls(text, path=target, env=env, dotenv_names=dotenv_names)

    def with_text(self, text: str) -> "ConfigDocument":
        """A new document over different text, keeping path/env context."""
        return ConfigDocument(
            text, path=self.path, env=self.env, dotenv_names=self.dotenv_names
        )

    # -- parsed view -------------------------------------------------------

    def data(self) -> dict[str, Any]:
        """The document parsed as TOML (placeholders left unresolved)."""
        if self._data is None:
            try:
                parsed = tomllib.loads(self.text)
            except Exception as exc:  # noqa: BLE001 - reported to the operator
                raise ConfigDocumentError(f"config.toml does not parse: {exc}") from exc
            self._data = parsed if isinstance(parsed, dict) else {}
        return self._data

    def flat(self) -> dict[str, Any]:
        return flatten(self.data())

    @property
    def keys(self) -> list[KeyRef]:
        """Every key line, in document order."""
        return list(self._keys)

    @property
    def tables(self) -> list[TableRef]:
        """Every table header, in document order."""
        return list(self._tables)

    @property
    def lines(self) -> list[str]:
        return list(self._lines)

    def find(self, path: str) -> KeyRef | None:
        """The key line for a dotted path, or ``None``."""
        for ref in self._keys:
            if ref.path == path:
                return ref
        return None

    def has_table(self, path: str) -> bool:
        return any(table.path == path for table in self._tables) or path == ""

    def key_value(self, path: str) -> Any:
        """The parsed value at a dotted path, with ``_MISSING`` when absent."""
        return self.flat().get(path, _MISSING)

    def tree(self) -> TreeNode:
        """Table path -> keys with values and line numbers, as a render tree."""
        keys_by_table: dict[str, list[KeyRef]] = {}
        for ref in self._keys:
            keys_by_table.setdefault(ref.table, []).append(ref)

        nodes: dict[str, dict[str, Any]] = {
            "": {"path": "", "label": "[root]", "kind": "root", "line": 0, "children": []}
        }
        for table in self._tables:
            nodes[table.path] = {
                "path": table.path,
                "label": table.label,
                "kind": table.kind,
                "line": table.line,
                "children": [],
            }
        known = set(nodes)
        for table in self._tables:
            parent = self._resolve_parent(table.path, known)
            nodes[parent]["children"].append(nodes[table.path])

        def build(node: dict[str, Any]) -> TreeNode:
            return TreeNode(
                path=node["path"],
                label=node["label"],
                kind=node["kind"],
                line=node["line"],
                keys=list(keys_by_table.get(node["path"], [])),
                children=[build(child) for child in node["children"]],
            )

        root = build(nodes[""])
        # Keys written before the first table header belong to the root node.
        return root

    @staticmethod
    def _resolve_parent(path: str, known: set[str]) -> str:
        """Nearest ancestor that is itself a declared table.

        ``[[a.b]]`` introduces ``a.b[0]`` while ``[a.b]`` may never exist, so the
        walk climbs until it finds a real header instead of assuming the parent
        path was declared.
        """
        candidate = parent_path(_strip_index(path))
        while candidate:
            if candidate in known:
                return candidate
            candidate = parent_path(candidate)
        return ""

    # -- effective values --------------------------------------------------

    def effective(self, path: str) -> Effective:
        """The value a control shows plus where it came from."""
        raw = self.key_value(path)
        secret = is_secret_path(path)
        if raw is _MISSING:
            return Effective(path=path, value=None, source="missing", raw=None, secret=secret)
        return self.resolve_value(path, raw, secret=secret)

    def resolve_value(self, path: str, raw: Any, *, secret: bool | None = None) -> Effective:
        """Resolve ``${ENV}`` placeholders the way the config loader does.

        The loader prefers the environment (a ``.env`` file is loaded with
        ``override=True``), then the inline default, and leaves ``${VAR}``
        untouched when the variable is absent - this mirrors that exactly so the
        editor cannot claim a value the runtime is not using.
        """
        if secret is None:
            secret = is_secret_path(path)
        if not isinstance(raw, str):
            return Effective(path=path, value=raw, source="config.toml", raw=raw, secret=secret)
        match = _PLACEHOLDER_RE.match(raw.strip())
        if not match:
            return Effective(path=path, value=raw, source="config.toml", raw=raw, secret=secret)
        name, operator, default = match.group(1), match.group(2), match.group(3)
        if name in self.env:
            source = ".env" if name in self.dotenv_names else "environment"
            return Effective(
                path=path, value=self.env[name], source=source, raw=raw, env_var=name, secret=True
            )
        if operator == "-":
            return Effective(
                path=path, value=default, source="default", raw=raw, env_var=name, secret=secret
            )
        if operator == "?":
            return Effective(
                path=path, value=None, source="unset", raw=raw, env_var=name, secret=secret
            )
        return Effective(
            path=path, value=raw, source="unresolved", raw=raw, env_var=name, secret=secret
        )

    # -- diffs -------------------------------------------------------------

    def diff(self, other: "ConfigDocument") -> list[Change]:
        """Semantic diff against ``other``: only keys whose value differs."""
        mine = self.flat()
        theirs = other.flat()
        changes: list[Change] = []
        for path in sorted(set(mine) | set(theirs)):
            in_mine, in_theirs = path in mine, path in theirs
            if in_mine and in_theirs:
                if _values_differ(mine[path], theirs[path]):
                    changes.append(Change(path, "changed", mine[path], theirs[path]))
            elif in_theirs:
                changes.append(Change(path, "added", None, theirs[path]))
            else:
                changes.append(Change(path, "removed", mine[path], None))
        return changes

    def reference_diff(self, reference: "ConfigDocument") -> list[Change]:
        """Diff against the shipped defaults, i.e. "what did we change"."""
        return reference.diff(self)

    # -- search ------------------------------------------------------------

    def search(self, query: str, *, limit: int = 200) -> list[SearchHit]:
        """Match key paths and values across the whole document.

        Secret values are never searched and never rendered: a hit on a secret
        key only ever reports the key path.
        """
        needle = query.strip().lower()
        if not needle:
            return []
        hits: list[SearchHit] = []
        for ref in self._keys:
            secret = is_secret_path(ref.path)
            display = format_value(ref.value, secret=secret)
            if needle in ref.path.lower():
                hits.append(SearchHit(ref.path, ref.line, "key", display, secret))
            elif not secret and needle in display.lower():
                hits.append(SearchHit(ref.path, ref.line, "value", display, secret))
            elif not secret and needle in str(ref.comment).lower():
                hits.append(SearchHit(ref.path, ref.line, "comment", display, secret))
            if len(hits) >= limit:
                break
        return hits

    # -- secrets -----------------------------------------------------------

    def secret_spans(self) -> list[SecretSpan]:
        """Where the literal secret values sit in the raw text.

        Only literal values are spanned.  ``password_hash = "${...}"`` holds no
        secret - the placeholder is supposed to be visible - while a hash typed
        straight into the file must never leave the server.
        """
        spans: list[SecretSpan] = []
        for ref in self._keys:
            if not is_secret_path(ref.path) or not isinstance(ref.value, str):
                continue
            if _PLACEHOLDER_RE.match(ref.value.strip()):
                continue
            start, end = self._value_bounds(ref)
            spans.append(
                SecretSpan(
                    path=ref.path,
                    start=start,
                    end=end,
                    line=ref.line,
                    original=self.text[start:end],
                    redacted=json.dumps(REDACTION),
                )
            )
        return spans

    def redacted_text(self) -> str:
        """The raw text with every literal secret value replaced."""
        spans = self.secret_spans()
        if not spans:
            return self.text
        pieces: list[str] = []
        cursor = 0
        for span in spans:
            pieces.append(self.text[cursor : span.start])
            pieces.append(span.redacted)
            cursor = span.end
        pieces.append(self.text[cursor:])
        return "".join(pieces)

    def _value_bounds(self, ref: KeyRef) -> tuple[int, int]:
        """Character range of a key's value inside ``self.text``."""
        starts = self._line_starts()
        line_start = starts[ref.line - 1]
        line = self._lines[ref.line - 1]
        eq = _assignment_index(line)
        if eq < 0:  # pragma: no cover - defensive, the line came from a parse
            return line_start, line_start + len(line)
        head = line_start + eq + 1
        while head < len(self.text) and self.text[head] in " \t":
            head += 1
        end = head + len(ref.value_text)
        return head, end

    def _line_starts(self) -> list[int]:
        starts = [0]
        for line in self._lines[:-1]:
            starts.append(starts[-1] + len(line))
        return starts

    # -- leaf edits (comment preserving) -----------------------------------

    def set_leaf(self, path: str, value: Any) -> "ConfigDocument":
        """Rewrite one key's value, touching nothing else in the file.

        The replacement keeps the key's indentation and any trailing comment,
        and only ever replaces the lines that carried the old value.  A value
        block that hides comments *inside* itself (a commented multi-line array)
        is refused instead of silently dropping them, and a table value is a
        structural change rather than a value edit.
        """
        ref = self.find(path)
        if ref is None:
            raise KeyNotFound(f"{path} is not a key of {self._name()}")
        if isinstance(value, dict):
            raise StructuralEditRequired(f"{path} is a table; use the structural editor")
        if ref.interior_comment:
            raise StructuralEditRequired(
                f"{path} stores comments inside a multi-line value; "
                "editing it here would drop them - use the raw view"
            )
        newline = _ending_of(self._lines[ref.end_line - 1]) or _ending_of(ref.raw_line) or "\n"
        body = f"{ref.indent}{ref.key} = {render_value_block(value)}{ref.comment}"
        body = _align_newlines(body, newline) + newline
        lines = list(self._lines)
        lines[ref.line - 1 : ref.end_line] = [body]
        return self.with_text("".join(lines))

    def add_leaf(self, path: str, value: Any) -> "ConfigDocument":
        """Insert a new key into an existing table, without reformatting it.

        The line goes at the end of the table's body, before any comment block
        that introduces the following header - those comments belong to the next
        table, and moving a key underneath them would re-label it.
        """
        if self.find(path) is not None:
            raise ConfigDocumentError(f"{path} already exists; edit it instead")
        table = parent_path(path)
        name = key_name(path)
        if table and not self.has_table(table):
            raise KeyNotFound(f"{table} is not a table of {self._name()}")
        lines = list(self._lines)
        insert_at = self._table_body_end(table)
        indent = self._table_indent(table)
        newline = _ending_of(lines[insert_at - 1]) if insert_at > 0 else "\n"
        newline = newline or "\n"
        if isinstance(value, dict):
            raise StructuralEditRequired("adding a table is a structural change")
        block = f"{indent}{name} = {render_value_block(value)}"
        lines.insert(insert_at, _align_newlines(block, newline) + newline)
        return self.with_text("".join(lines))

    def remove_leaf(self, path: str) -> "ConfigDocument":
        """Delete one key line.  Its siblings and every comment stay put."""
        ref = self.find(path)
        if ref is None:
            raise KeyNotFound(f"{path} is not a key of {self._name()}")
        lines = list(self._lines)
        del lines[ref.line - 1 : ref.end_line]
        return self.with_text("".join(lines))

    def _table_indent(self, table: str) -> str:
        for ref in self._keys:
            if ref.table == table and ref.indent:
                return ref.indent
        return ""

    def _table_body_end(self, table: str) -> int:
        """Line index (0-based, insert position) of the end of a table's body."""
        header_line = 0
        for candidate in self._tables:
            if candidate.path == table:
                header_line = candidate.line
        start = header_line  # 0-based index just past the header
        end = len(self._lines)
        for candidate in self._tables:
            if candidate.line > header_line and candidate.line - 1 < end:
                end = candidate.line - 1
        index = end
        while index > start:
            stripped = self._lines[index - 1].strip()
            if not stripped:
                index -= 1
                continue
            if stripped.startswith("#"):
                # A comment block directly above the next header documents that
                # header, not this table: stop before it.
                index -= 1
                continue
            break
        return index

    # -- structural edits (re-serialized, comments may move) ---------------

    def with_data(self, data: Mapping[str, Any]) -> "ConfigDocument":
        """Serialize a whole table tree with ``tomli_w`` (the project writer).

        ``tomli_w`` always emits ``\\n``; the re-serialized text adopts the
        document's own dominant ending so a structural edit on a Windows
        checkout does not leave ``config.toml`` half CRLF and half LF.
        """
        return self.with_text(_align_newlines(tomli_w.dumps(dict(data)), self.dominant_ending()))

    def dominant_ending(self) -> str:
        """The line ending most of the document uses (``\\n`` when ambiguous)."""
        crlf = self.text.count("\r\n")
        total = self.text.count("\n")
        return "\r\n" if total and crlf >= (total - crlf) else "\n"

    def remove_table(self, path: str) -> "ConfigDocument":
        """Remove a table (or one ``[[array.of.tables]]`` item) entirely."""
        data = copy.deepcopy(self.data())
        if not self.has_table(path):
            raise KeyNotFound(f"{path} is not a table of {self._name()}")
        if not _delete_in(data, _strip_index(path)):
            raise KeyNotFound(f"{path} is not set in {self._name()}")
        return self.with_data(data)

    def add_table(self, path: str, value: Mapping[str, Any] | None = None) -> "ConfigDocument":
        """Add a table, or one more item to an array of tables.

        ``add_table("website")`` on a document where ``[website]`` is a single
        table converts it to ``[[website]]`` with the existing entry first: that
        is what "add a second site" means in TOML, and it keeps the existing
        site's values.
        """
        data = copy.deepcopy(self.data())
        base = _strip_index(path)
        segments = _path_segments(base)
        if segments is None or not segments:
            raise ConfigDocumentError(f"Invalid table path: {path!r}")
        node: Any = data
        for segment, index in segments[:-1]:
            if index is not None:
                raise ConfigDocumentError(f"Invalid table path: {path!r}")
            child = node.get(segment)
            if not isinstance(child, dict):
                child = {}
                node[segment] = child
            node = child
        name = segments[-1][0]
        new_item = dict(value or {})
        existing = node.get(name)
        if existing is None:
            node[name] = [new_item]
        elif isinstance(existing, dict):
            node[name] = [existing, new_item]
        elif isinstance(existing, list):
            existing.append(new_item)
        else:
            raise ConfigDocumentError(f"{path} is not a table")
        return self.with_data(data)

    def remove_array_item(self, path: str, index: int) -> "ConfigDocument":
        """Remove one item from an array (scalars or tables)."""
        data = copy.deepcopy(self.data())
        segments = _path_segments(path)
        if not segments or segments[-1][1] is not None:
            raise ConfigDocumentError(f"Invalid array path: {path!r}")
        node: Any = data
        for segment, item_index in segments[:-1]:
            if not isinstance(node, dict) or segment not in node:
                raise KeyNotFound(f"{path} is not set in {self._name()}")
            node = node[segment]
            if item_index is not None:
                node = node[item_index]
        name = segments[-1][0]
        target = node.get(name) if isinstance(node, dict) else None
        if not isinstance(target, list) or not (0 <= index < len(target)):
            raise KeyNotFound(f"{path}[{index}] does not exist")
        del target[index]
        return self.with_data(data)

    def add_array_item(self, path: str, value: Any) -> "ConfigDocument":
        """Append one item to an array (a scalar, a list, or a table)."""
        data = copy.deepcopy(self.data())
        segments = _path_segments(path)
        if not segments or segments[-1][1] is not None:
            raise ConfigDocumentError(f"Invalid array path: {path!r}")
        node: Any = data
        for segment, item_index in segments[:-1]:
            if not isinstance(node, dict) or segment not in node:
                raise KeyNotFound(f"{path} is not set in {self._name()}")
            node = node[segment]
            if item_index is not None:
                node = node[item_index]
        name = segments[-1][0]
        target = node.get(name) if isinstance(node, dict) else None
        if not isinstance(target, list):
            raise KeyNotFound(f"{path} is not an array of {self._name()}")
        target.append(value)
        return self.with_data(data)

    def structural_text(self, data: Mapping[str, Any]) -> str:
        """The text a structural change produces, for diffing before writing."""
        return tomli_w.dumps(dict(data))

    # -- internals ---------------------------------------------------------

    def _name(self) -> str:
        return self.path.name if self.path is not None else "config.toml"

    def _parse(self) -> None:
        lines = self._lines
        arrays: dict[str, int] = {}
        table = ""
        index = 0
        while index < len(lines):
            raw = lines[index]
            stripped = raw.strip()
            if not stripped or stripped.startswith("#"):
                index += 1
                continue
            if stripped.startswith("[["):
                header = _header_name(stripped, "[[", "]]")
                if header is not None:
                    count = arrays.get(header, 0)
                    arrays[header] = count + 1
                    table = f"{header}[{count}]"
                    self._tables.append(
                        TableRef(table, header, "array_table", count, index + 1, stripped)
                    )
                    index += 1
                    continue
            elif stripped.startswith("["):
                header = _header_name(stripped, "[", "]")
                if header is not None:
                    table = header
                    self._tables.append(TableRef(header, header, "table", None, index + 1, stripped))
                    index += 1
                    continue
            ref = self._parse_key_line(lines, index, table)
            if ref is None:
                index += 1
                continue
            self._keys.append(ref)
            index = ref.end_line

    def _parse_key_line(self, lines: list[str], index: int, table: str) -> KeyRef | None:
        raw = lines[index]
        eq = _assignment_index(raw)
        if eq < 0:
            return None
        key_text = raw[:eq].strip()
        dotted = _parse_key_text(key_text)
        if not dotted:
            return None
        path = ".".join([part for part in (table, *dotted) if part])
        indent = raw[: len(raw) - len(raw.lstrip())]
        span = _scan_value(self.text, self._line_starts()[index] + eq + 1)
        end_line = _line_of(self._line_starts(), span["end"])
        value_text = span["value"]
        try:
            parsed = tomllib.loads(f"v = {value_text}\n")["v"]
            kind = _kind_of(parsed, value_text)
        except Exception:  # noqa: BLE001 - keep a raw view rather than losing the key
            parsed = value_text
            kind = "raw"
        return KeyRef(
            path=path,
            key=dotted[-1],
            table=table,
            line=index + 1,
            end_line=end_line,
            indent=indent,
            raw_line=raw,
            value_text=value_text,
            comment=span["comment"],
            kind=kind,
            value=parsed,
            multiline=end_line > index + 1,
            interior_comment=span["interior_comment"],
        )


def _kind_of(value: Any, text: str) -> str:
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, int):
        return "int"
    if isinstance(value, float):
        return "float"
    if isinstance(value, str):
        return "string" if "\n" not in text else "multiline_string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "table"
    return "raw"


def _values_differ(left: Any, right: Any) -> bool:
    if isinstance(left, bool) != isinstance(right, bool):
        return True
    return left != right


def _ending_of(line: str) -> str:
    if line.endswith("\r\n"):
        return "\r\n"
    if line.endswith("\n"):
        return "\n"
    if line.endswith("\r"):
        return "\r"
    return ""


def _align_newlines(text: str, ending: str) -> str:
    """Rewrite layout newlines to ``ending``.

    ``tomli_w`` (and any generated block) emits ``\\n``; values never contain a
    literal newline - the writer escapes them - so this only touches layout.
    """
    if ending == "\n" or "\n" not in text:
        return text
    return text.replace("\r\n", "\n").replace("\n", ending)


def _assignment_index(line: str) -> int:
    """Index of the ``=`` that separates a key from its value, or ``-1``."""
    index = 0
    quote = ""
    while index < len(line):
        char = line[index]
        if quote:
            if char == "\\" and quote == '"':
                index += 2
                continue
            if char == quote:
                quote = ""
        elif char in ("'", '"'):
            quote = char
        elif char == "#":
            return -1
        elif char == "=":
            return index
        index += 1
    return -1


def _parse_key_text(text: str) -> list[str]:
    """Split ``a.b."c d"`` into its key segments."""
    parts: list[str] = []
    index = 0
    while index < len(text):
        char = text[index]
        if char in ("'", '"'):
            quote = char
            index += 1
            start = index
            while index < len(text) and text[index] != quote:
                index += 1
            parts.append(text[start:index])
            index += 1
            continue
        if char == ".":
            index += 1
            continue
        match = _BARE_KEY_RE.match(text, index)
        if not match:
            return []
        parts.append(match.group(0))
        index = match.end()
    return parts


def _header_name(stripped: str, opening: str, closing: str) -> str | None:
    if not stripped.endswith(closing):
        return None
    inner = stripped[len(opening) : -len(closing)].strip()
    return inner or None


def _scan_value(text: str, start: int) -> dict[str, Any]:
    """Find where a value ends, whether it hides comments, and its comment.

    Walks the raw text from the first character after ``=``: strings and
    bracket depth decide when the value is complete, and a ``#`` outside a
    string starts a comment.  A ``#`` inside a multi-line value is an *interior*
    comment: it belongs to the value and a single-line replacement would delete
    it, which the caller has to know about.
    """
    index = start
    depth = 0
    quote = ""
    triple = False
    interior_comment = False
    value_start = None
    length = len(text)
    while index < length:
        char = text[index]
        if value_start is None and char not in " \t":
            value_start = index
        if quote:
            if triple:
                if text.startswith(quote * 3, index):
                    index += 3
                    quote, triple = "", False
                    continue
                index += 1
                continue
            if char == "\\" and quote == '"':
                index += 2
                continue
            if char == quote:
                quote = ""
            index += 1
            continue
        if char in ("'", '"'):
            if text.startswith(char * 3, index):
                quote, triple = char, True
                index += 3
                continue
            quote = char
            index += 1
            continue
        if char in "[{":
            depth += 1
        elif char in "]}":
            depth = max(0, depth - 1)
        elif char == "#":
            comment_end = index
            while comment_end < length and text[comment_end] not in "\r\n":
                comment_end += 1
            at_line_end = depth == 0 and not quote
            if at_line_end and value_start is not None:
                value = text[value_start:index].rstrip()
                # Keep the whitespace before the '#' as well: it separates the
                # value from its comment and must survive the rewrite.
                comment_at = value_start + len(value)
                return {
                    "end": comment_at,
                    "value": value,
                    "comment": text[comment_at:comment_end],
                    "interior_comment": interior_comment,
                }
            interior_comment = True
            index = comment_end
            continue
        elif char in "\r\n" and depth == 0:
            cut = index
            if char == "\r" and index + 1 < length and text[index + 1] == "\n":
                cut = index
            value = text[value_start:cut].rstrip() if value_start is not None else ""
            return {
                "end": (value_start or 0) + len(value),
                "value": value,
                "comment": "",
                "interior_comment": interior_comment,
            }
        index += 1
    value = text[value_start:].rstrip() if value_start is not None else ""
    return {
        "end": (value_start or 0) + len(value),
        "value": value,
        "comment": "",
        "interior_comment": interior_comment,
    }


def _line_of(starts: list[int], position: int) -> int:
    """1-based line number of a character position."""
    low, high = 0, len(starts) - 1
    while low < high:
        middle = (low + high + 1) // 2
        if starts[middle] <= position:
            low = middle
        else:
            high = middle - 1
    return low + 1
