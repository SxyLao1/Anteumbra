# -*- coding: utf-8 -*-
"""Advanced ``config.toml`` editor: one document, three depths, gated saves.

The settings page is a dashboard; this blueprint is the editor.  It exposes a
single document model (``application.config_document``) through three views -
a schema-driven form, the real TOML tree, and the raw file - and gates every
write the same way:

1. build a *candidate* document from the submitted values against the file as
   it is on disk right now,
2. show the semantic diff (``key: old -> new``, changed keys only) and warn when
   the change had to re-serialize the file,
3. validate the candidate with ``cli.config_support.validate_config_file`` -
   the validator ``anteumbra config validate`` runs - and refuse to write when
   it introduces errors (pre-existing errors and warnings never block),
4. on confirmation, take the write lock, re-check that nobody else touched the
   file since the preview, copy ``config.toml`` to a timestamped ``.bak``, swap
   the candidate in atomically, reload the runtime, and say plainly whether the
   runtime picked the change up.

Secrets never travel in the other direction: values that live in ``.env`` are
write-only fields written through ``write_env_value``, ``web_admin.password_hash``
is only ever *set* (hashed here, like the CLI does) and never displayed, and
literal secret values inside ``config.toml`` are redacted from every response,
including the raw view and the revision download.
"""

from __future__ import annotations

import copy
import hashlib
import logging
import os
import re
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from flask import Blueprint, Response, current_app, request
from flask_babel import gettext
from markupsafe import Markup, escape
from werkzeug.security import generate_password_hash

from anteumbra.application import config_document as cd
from anteumbra.application.config_history_service import ConfigRevisionStore
from anteumbra.cli.config_support import (
    validate_config_file,
    write_env_value,
    write_toml_file,
)
from anteumbra.interfaces.web.auth import require_auth
from anteumbra.interfaces.web.pages import render_page
from anteumbra.interfaces.web.runtime import get_runtime

logger = logging.getLogger(__name__)

config_editor_bp = Blueprint("config_editor", __name__, url_prefix="/admin")

PAGE_URL = "/admin/config"
PANEL_URL = "/admin/config/editor/panel"

TABS: tuple[str, ...] = ("editor", "secrets", "history")
VIEWS: tuple[str, ...] = ("form", "tree", "raw")

#: ``.env`` variables the editor may set: exactly the deployment credentials.
#: ``ANTEUMBRA_SECRET_KEY`` is deliberately absent (rotating it signs every
#: session out), and the password hash has its own "set a new password" control
#: instead of a text field.
ENV_KEYS: tuple[str, ...] = (
    "ANTEUMBRA_EMAIL_USERNAME",
    "ANTEUMBRA_EMAIL_PASSWORD",
    "ANTEUMBRA_EMAIL_FROM",
    "ANTEUMBRA_EMAIL_TO",
    "ANTEUMBRA_WECHAT_API_KEY",
    "ANTEUMBRA_WAF_API_KEY",
    "ANTEUMBRA_WEBHOOK_SECRET",
)

PASSWORD_ENV_KEY = "ANTEUMBRA_PASSWORD_HASH"
PASSWORD_HASH_CONFIG_KEY = "web_admin.password_hash"

#: Keys the running runtime reads once, at startup.  Everything else is read
#: from the config snapshot on demand, so a reload is enough.  Reporting a live
#: pickup for a listen port would be a lie, and the operator would keep
#: wondering why nothing happened.
RESTART_REQUIRED_PREFIXES: tuple[str, ...] = (
    "web_admin.enabled",
    "web_admin.host",
    "web_admin.port",
    "web_admin.session_",
    "security.secret_key",
    "storage.",
    "paths.",
    "website.",
    "logging.",
    "plugins.",
    "siem.",
    "scanner.",
    "waf_source.",
)

MAX_RAW_BYTES = 512 * 1024

#: Serializes candidate-build -> validate -> backup -> write -> reload inside
#: one process.  The config provider has its own lock around the snapshot, but a
#: read-modify-write of the *file* needs one too: otherwise two operators saving
#: at the same moment would each diff against a text the other already replaced.
_WRITE_LOCK = threading.RLock()

_FIELD_PREFIX = "ce."


def _runtime():
    return get_runtime()


def _config_path() -> Path:
    return Path(_runtime().config.path)


def _fingerprint(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


# -- environment and documents ----------------------------------------------


def _read_env_file(config_path: Path) -> dict[str, str]:
    """``.env`` values as written, without touching ``os.environ``."""
    values: dict[str, str] = {}
    try:
        env_path = config_path.parent / ".env"
        if not env_path.exists():
            return values
        for line in env_path.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or "=" not in stripped:
                continue
            key, value = stripped.split("=", 1)
            values[key.strip()] = value.strip()
    except OSError:
        logger.debug("Failed to read .env for the config editor", exc_info=True)
    return values


def _env_snapshot(config_path: Path) -> tuple[dict[str, str], frozenset[str]]:
    """Effective environment plus the names that came from ``.env``.

    ``load_toml_config`` loads ``.env`` with ``override=True`` before resolving
    ``${VAR}`` placeholders, so the file wins over the process environment - and
    the editor has to resolve the same value the runtime will use.
    """
    from_env_file = _read_env_file(config_path)
    merged = dict(os.environ)
    merged.update(from_env_file)
    return merged, frozenset(from_env_file)


def _load_document(config_path: Path) -> cd.ConfigDocument:
    env, dotenv_names = _env_snapshot(config_path)
    return cd.ConfigDocument.load(config_path, env=env, dotenv_names=dotenv_names)


def _reference_document() -> cd.ConfigDocument:
    """The shipped template, for the "changed from the defaults" filter."""
    try:
        import anteumbra

        template = Path(anteumbra.__file__).resolve().parent / "config.toml"
        if template.is_file():
            return cd.ConfigDocument.load(template)
    except Exception:  # noqa: BLE001 - the filter is cosmetic, never fatal
        logger.debug("Shipped config template is unavailable", exc_info=True)
    return cd.ConfigDocument("")


def _danger_reason(path: str) -> str:
    """Why editing ``path`` deserves an explicit warning affordance.

    These are the keys where a plausible edit has an outcome this page cannot
    undo: files moved to quarantine, an attacker's address blocked, the operator
    locked out of the UI, or records written to a store the runtime is not
    reading.
    """
    if path == "quarantine.auto_quarantine_enabled":
        return gettext(
            "Turning automatic quarantine on moves every matching file out of the "
            "website directory."
        )
    if path == "web_admin.allowed_ips":
        return gettext(
            "This list is the admin IP allow-list: an entry that does not cover your "
            "current address locks you out of this UI."
        )
    if path == "web_admin.trusted_proxy_ips":
        return gettext(
            "Only a proxy you control belongs here; a wrong entry lets a client forge "
            "its own address in logs, profiles and blocking."
        )
    if path == "web_admin.session_cookie_secure":
        return gettext(
            "Forcing secure cookies over plain HTTP makes the login cookie unusable and "
            "locks everyone out."
        )
    if path.startswith("ip_blocker."):
        return gettext(
            "The IP blocker acts on live attacker addresses; a wrong threshold blocks "
            "real users at the WAF or firewall."
        )
    if path.startswith("storage."):
        return gettext(
            "The storage backend decides where detections are written; changing it "
            "splits the ledger this dashboard reads."
        )
    return ""


def _restart_keys(changed_paths: list[str]) -> list[str]:
    return [
        path
        for path in changed_paths
        if any(path == prefix or path.startswith(prefix) for prefix in RESTART_REQUIRED_PREFIXES)
    ]


def _notice(level: str, text: str) -> dict[str, str]:
    return {"level": level, "text": text}


# -- candidates and the gated save ------------------------------------------


@dataclass
class _Candidate:
    """A proposed document plus how it was produced."""

    doc: cd.ConfigDocument
    structural: bool = False
    label: str = ""
    path: str = ""
    #: True for the raw view, where a comment or layout edit is a real edit even
    #: though no key's value moved.
    raw_edit: bool = False


@dataclass
class _Plan:
    """Everything a rendered result needs, preview or write."""

    label: str = ""
    structural: bool = False
    changes: list[cd.Change] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    #: Errors the file already had before this change.  Only errors the change
    #: *introduces* block a save, before or after the write, so a config that
    #: already warns stays editable - exactly how ``config set`` treats it.
    baseline_errors: list[str] = field(default_factory=list)
    restart: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    payload: dict[str, str] = field(default_factory=dict)
    confirm_url: str = ""
    fingerprint: str = ""
    backup: str = ""
    written: bool = False
    reload_error: str = ""
    notice: dict[str, str] | None = None
    revision_id: str = ""
    #: Set when the raw text differs but no key's value did (comments, layout).
    text_only: bool = False

    @property
    def blocked(self) -> bool:
        return bool(self.errors)

    @property
    def can_confirm(self) -> bool:
        """Whether this plan may render a confirm button.

        ``confirm_url`` is part of the test on purpose: a history record that
        stores no content has no endpoint to post to, and a button that cannot
        be completed must not be offered.
        """
        return (
            not self.written
            and not self.blocked
            and bool(self.confirm_url)
            and (bool(self.changes) or self.text_only)
        )

    @property
    def display_changes(self) -> list[dict[str, str]]:
        """Diff rows for the template, with secret values redacted.

        Redaction happens here rather than in Jinja so that no secret can reach
        a response through a template that forgot about it.
        """
        rows: list[dict[str, str]] = []
        for change in self.changes:
            secret = cd.is_secret_path(change.path)
            rows.append(
                {
                    "path": change.path,
                    "kind": change.kind,
                    "old": cd.format_value(change.old, secret=secret),
                    "new": cd.format_value(change.new, secret=secret),
                }
            )
        return rows


def _write_document(target: Path, candidate: _Candidate) -> None:
    """Materialize a candidate at ``target``.

    A structural change was produced by ``tomli_w``, so it is written back
    through the project's own writer; a surgical or raw candidate is written
    verbatim, because re-serializing *that* is exactly what would destroy the
    comments this editor promises to keep.

    The verbatim branch writes bytes: ``Path.write_text`` translates ``"\\n"``
    to ``os.linesep``, which on Windows would silently turn a Unix ``config.toml``
    into a CRLF file on the first value edit - the one thing a surgical edit
    must never do.
    """
    if candidate.structural:
        write_toml_file(target, copy.deepcopy(candidate.doc.data()))
    else:
        target.write_bytes(candidate.doc.text.encode("utf-8"))


def _validate_candidate(
    candidate: _Candidate, config_path: Path
) -> tuple[list[str], list[str], list[str]]:
    """Run the real validator on the candidate, delta against the live file.

    ``validate_config_file`` resolves relative website and log paths against the
    file's own directory, so the candidate has to sit beside ``config.toml`` for
    its answers to mean anything.  Only errors this change *introduces* block the
    save - a config that already warns must stay editable, which is how the CLI
    treats it too.  The baseline comes back with the verdict so the post-write
    check below can use the same rule instead of calling a pre-existing error a
    new one.
    """
    check_path = config_path.with_name(
        f"{config_path.name}.{os.getpid()}.{threading.get_ident()}.editor-check.tmp"
    )
    try:
        _write_document(check_path, candidate)
        baseline_errors, _ = validate_config_file(config_path)
        candidate_errors, candidate_warnings = validate_config_file(check_path)
    finally:
        check_path.unlink(missing_ok=True)
    new_errors = [error for error in candidate_errors if error not in baseline_errors]
    return new_errors, candidate_warnings, baseline_errors


def _reload_runtime() -> str:
    """Reload the config snapshot; returns "" on success, else the reason."""
    try:
        _runtime().config.reload()
        return ""
    except Exception as exc:  # noqa: BLE001 - reported to the operator, not raised
        logger.error("Config reload failed after a config editor write", exc_info=True)
        return str(exc) or exc.__class__.__name__


def _revision_store(config_path: Path) -> ConfigRevisionStore:
    history = getattr(_runtime(), "config_history", None)
    return ConfigRevisionStore(config_path, history)


def _record_revision(changes: list[cd.Change], label: str) -> str:
    """Add this write to the version history, best effort."""
    try:
        history = getattr(_runtime(), "config_history", None)
        recorder = getattr(history, "record_change", None)
        if not callable(recorder):
            return ""
        try:
            snapshot = _runtime().config.get()
        except Exception:  # noqa: BLE001 - a summary is nice to have, not required
            snapshot = None
        return recorder(
            [change.path for change in changes],
            source="ui",
            detail=label,
            config_snapshot=snapshot,
        )
    except Exception:  # noqa: BLE001 - history must never fail a save
        logger.debug("Failed to record the config revision", exc_info=True)
        return ""


def _confirm_payload() -> dict[str, str]:
    """The submitted fields a confirmation has to re-post unchanged."""
    return {
        key: value
        for key, value in request.form.items()
        if key not in ("csrf_token", "confirm", "base")
    }


def _render_result(plan: _Plan):
    return render_page("admin/config_editor_result.html", plan=plan)


def _submit(builder: Callable[[cd.ConfigDocument], _Candidate], *, confirm: bool, base: str):
    """The whole gated-save pipeline, shared by every mutation route.

    The builder runs inside the write lock, so the candidate is always derived
    from the text this save is about to diff against - not from a snapshot taken
    a few milliseconds earlier.
    """
    config_path = _config_path()
    with _WRITE_LOCK:
        current = _load_document(config_path)
        candidate = builder(current)
        plan = _Plan(label=candidate.label, structural=candidate.structural)
        plan.fingerprint = _fingerprint(current.text)
        plan.payload = _confirm_payload()
        plan.confirm_url = request.path
        plan.changes = current.diff(candidate.doc)
        # A candidate can move the text without moving a key value: a raw edit of
        # a comment, or a structural add of an *empty* table (``[siem]``, or one
        # more ``[[website]]`` block, both of which the tree view offers as a
        # button).  Both are changes the operator asked for, so neither may be
        # reported as "nothing to save".
        plan.text_only = (
            not plan.changes
            and candidate.doc.text != current.text
            and (candidate.raw_edit or candidate.structural)
        )

        if not plan.changes and not plan.text_only:
            plan.notice = _notice("info", gettext("No changes: nothing to save."))
            return plan
        if plan.text_only:
            plan.notes.append(
                gettext(
                    "Saving an empty table: no key value changed, and the file is "
                    "re-serialized with the project writer."
                )
                if candidate.structural
                else gettext(
                    "Only comments or formatting changed: no configuration key moved, and "
                    "the file is still rewritten verbatim."
                )
            )

        plan.errors, plan.warnings, plan.baseline_errors = _validate_candidate(
            candidate, config_path
        )
        plan.restart = _restart_keys([change.path for change in plan.changes])
        if plan.errors:
            plan.notice = _notice(
                "error", gettext("Not saved: the change introduces configuration errors.")
            )
            return plan

        if not confirm:
            plan.notice = _notice(
                "info",
                gettext("Review the changes below, then confirm to write config.toml."),
            )
            return plan

        if base and base != plan.fingerprint:
            plan.errors = [
                gettext(
                    "config.toml changed on disk since this preview (another editor, the "
                    "CLI, or the runtime). Re-open the editor before saving."
                )
            ]
            plan.notice = _notice("error", gettext("Not saved: the file moved under us."))
            return plan

        store = _revision_store(config_path)
        backup = store.backup_current()
        plan.backup = backup.name if backup is not None else ""
        _write_document(config_path, candidate)
        # Re-validate what is actually on disk: the operator is told what the
        # runtime will read, not what this code intended to write.  The verdict is
        # a delta against the pre-write baseline for the same reason the gate is:
        # a config that already had an unrelated error must not be reported as
        # broken by this save.
        post_errors, post_warnings = validate_config_file(config_path)
        plan.written = True
        plan.warnings = post_warnings
        plan.errors = [error for error in post_errors if error not in plan.baseline_errors]
        plan.reload_error = _reload_runtime()
        plan.revision_id = _record_revision(plan.changes, candidate.label)
        if plan.errors:
            plan.notice = _notice(
                "error",
                gettext(
                    "Written, but the resulting config.toml does not validate - restore a "
                    "revision below."
                ),
            )
        elif plan.reload_error:
            plan.notice = _notice(
                "warning",
                gettext(
                    "Saved and backed up, but the runtime could not reload: it is still "
                    "running the previous configuration."
                ),
            )
        else:
            plan.notice = _notice("success", gettext("Saved: config.toml written and reloaded."))
        return plan


# -- building a candidate from the submitted payload ------------------------


def _candidate_for_leaf(doc: cd.ConfigDocument, key: str, text: str) -> _Candidate:
    value = cd.coerce_value(text, doc.key_value(key))
    if doc.find(key) is None:
        return _Candidate(
            doc.add_leaf(key, value), False, gettext("Add key %(key)s", key=key), key
        )
    return _Candidate(doc.set_leaf(key, value), False, gettext("Edit %(key)s", key=key), key)


def _candidate_for_batch(doc: cd.ConfigDocument, form: Mapping[str, str]) -> _Candidate:
    """Apply every posted ``ce.<path>`` field, in document order.

    The whole form is posted, not just the touched fields, because the server -
    not the browser - decides what actually changed: the diff below is computed
    from the candidate, so an untouched field simply produces no entry.
    """
    updates = {
        name[len(_FIELD_PREFIX) :]: value
        for name, value in form.items()
        if name.startswith(_FIELD_PREFIX)
    }
    if not updates:
        raise cd.ConfigDocumentError(gettext("No values were submitted."))
    candidate = doc
    for path in sorted(updates, key=lambda item: (doc.find(item) is None, item)):
        value = cd.coerce_value(updates[path], doc.key_value(path))
        if candidate.find(path) is None:
            candidate = candidate.add_leaf(path, value)
        else:
            candidate = candidate.set_leaf(path, value)
    return _Candidate(
        candidate,
        False,
        gettext("Edit %(count)s value(s)", count=len(updates)),
    )


# -- view models -------------------------------------------------------------


@dataclass
class _Row:
    """One key of the document, as the templates render it."""

    path: str
    key: str
    table: str
    line: int
    kind: str
    raw: str
    display: str
    source: str
    env_var: str | None
    secret: bool
    editable: bool
    dangerous: str
    non_default: bool
    hint: str = ""


def _rows(
    doc: cd.ConfigDocument,
    reference_changes: list[cd.Change],
    *,
    query: str = "",
    set_only: bool = False,
    non_default_only: bool = False,
    limit: int = 800,
) -> list[_Row]:
    """Build the form/tree rows, honouring the readability filters.

    ``set_only`` hides keys that resolve to nothing (an empty placeholder or an
    absent variable); ``non_default_only`` hides everything still identical to
    the shipped template.  Both exist because the shipped file is 650 lines of
    documented defaults, and "what did *I* change" is the question an operator
    actually has.
    """
    changed = {change.path for change in reference_changes}
    needle = query.strip().lower()
    rows: list[_Row] = []
    for ref in doc.keys:
        effective = doc.resolve_value(ref.path, ref.value)
        secret = cd.is_secret_path(ref.path)
        if set_only and not _is_set(effective):
            continue
        if non_default_only and ref.path not in changed:
            continue
        if needle and needle not in ref.path.lower() and needle not in effective.display.lower():
            continue
        rows.append(
            _Row(
                path=ref.path,
                key=ref.key,
                table=ref.table,
                line=ref.line,
                kind=ref.kind,
                raw="" if secret else cd.format_value(ref.value),
                display=effective.display,
                source=effective.source,
                env_var=effective.env_var,
                secret=secret,
                editable=not secret,
                dangerous=_danger_reason(ref.path),
                non_default=ref.path in changed,
                hint=_secret_hint(ref.path),
            )
        )
        if len(rows) >= limit:
            break
    return rows


def _is_set(effective: cd.Effective) -> bool:
    if effective.source in ("missing", "unset", "unresolved"):
        return False
    return effective.value not in ("", None)


def _secret_hint(path: str) -> str:
    if path == PASSWORD_HASH_CONFIG_KEY:
        return gettext("Set a new password instead of editing this hash.")
    if cd.is_secret_path(path):
        return gettext("Secret: set it in .env, never here.")
    return ""


def _tree_rows(doc: cd.ConfigDocument, rows: list[_Row]) -> list[dict[str, Any]]:
    """The document tree with each node's rows attached, for the tree view.

    The node key is ``rows``, not ``keys``: Jinja resolves ``node.keys`` to the
    ``dict.keys`` method before it ever looks at the item, so a node built with
    a ``keys`` entry renders as a bound method and the length filter below blows
    up.  The root node is included when it owns keys, otherwise a key written
    above the first ``[table]`` header would be invisible in the tree view.
    """
    by_path: dict[str, list[_Row]] = {}
    for row in rows:
        by_path.setdefault(row.table, []).append(row)

    def convert(node: cd.TreeNode) -> dict[str, Any]:
        return {
            "path": node.path,
            "label": node.label,
            "kind": node.kind,
            "line": node.line,
            "rows": by_path.get(node.path, []),
            "children": [convert(child) for child in node.children],
        }

    root = doc.tree()
    nodes = [convert(child) for child in root.children]
    if root.keys:
        nodes.insert(0, convert(root))
    return nodes


def _array_items(doc: cd.ConfigDocument) -> list[dict[str, Any]]:
    """Arrays and arrays-of-tables, so the tree view can offer item controls."""
    items: list[dict[str, Any]] = []
    seen: set[str] = set()
    for table in doc.tables:
        if table.kind != "array_table" or table.base in seen:
            continue
        seen.add(table.base)
        items.append(
            {
                "path": table.base,
                "count": sum(1 for other in doc.tables if other.base == table.base),
                "tables": True,
            }
        )
    for ref in doc.keys:
        if ref.kind != "array" or ref.path in seen:
            continue
        seen.add(ref.path)
        items.append({"path": ref.path, "count": len(ref.value), "tables": False})
    items.sort(key=lambda item: item["path"])
    return items


def _env_rows(config_path: Path) -> list[dict[str, Any]]:
    """``.env`` fields as write-only controls: set/unset, never the value."""
    values = _read_env_file(config_path)
    keys = [*ENV_KEYS, PASSWORD_ENV_KEY]
    return [
        {
            "key": key,
            "set": bool(str(values.get(key, "")).strip())
            or bool(str(os.environ.get(key, "")).strip()),
            "editable": key in ENV_KEYS,
            "is_password": key == PASSWORD_ENV_KEY,
        }
        for key in keys
    ]


def _current_validation(config_path: Path) -> dict[str, list[str]]:
    """What the validator says about the file on disk right now."""
    try:
        errors, warnings = validate_config_file(config_path)
    except Exception as exc:  # noqa: BLE001 - shown inline, never a 500
        logger.error("Config validation failed", exc_info=True)
        return {"errors": [str(exc)], "warnings": []}
    return {"errors": errors, "warnings": warnings}


#: How many changed key names the history list spells out per revision.
_HISTORY_KEY_PREVIEW = 6


def _revision_rows(
    store: ConfigRevisionStore, current: cd.ConfigDocument, *, limit: int = 80
) -> list[dict[str, Any]]:
    """The version history as the list renders it.

    A ``backup`` owns the file content, so its "changed keys" are *computed* by
    diffing it against the file on disk: that is the number the operator cares
    about ("what would restoring this take back"), and the entry itself only
    knows it is a copy.  A ``change`` entry is a history record - it remembers
    which keys moved and nothing else - so it reports its own count and is never
    offered a restore or a download it cannot honour.
    """
    rows: list[dict[str, Any]] = []
    for revision in store.list_revisions(limit=limit):
        changed_keys: list[str] = []
        changed_count = revision.changed_count
        text_differs = False
        if revision.kind == "backup":
            text = store.read(revision.revision_id)
            if text is not None:
                text_differs = text != current.text
                try:
                    changed_keys = [
                        change.path for change in current.diff(current.with_text(text))
                    ]
                except cd.ConfigDocumentError:
                    # A backup that no longer parses can still be downloaded and
                    # read; it just has no comparable key set.
                    logger.debug("Revision %s is not comparable", revision.revision_id)
                changed_count = len(changed_keys)
        else:
            changed_keys = list(revision.changed_keys)
        rows.append(
            {
                "revision_id": revision.revision_id,
                "kind": revision.kind,
                "source": revision.source,
                "timestamp": revision.timestamp,
                "display_time": revision.display_time,
                "detail": revision.detail,
                "size_bytes": revision.size_bytes,
                "changed_count": changed_count,
                "changed_keys": changed_keys[:_HISTORY_KEY_PREVIEW],
                "extra_keys": max(0, len(changed_keys) - _HISTORY_KEY_PREVIEW),
                "restoreable": revision.restoreable and text_differs,
                "downloadable": revision.kind == "backup",
                "text_differs": text_differs,
            }
        )
    return rows


def _page_context(
    *,
    tab: str,
    view: str,
    query: str,
    set_only: bool,
    non_default_only: bool,
    error: str = "",
    notice: dict[str, str] | None = None,
    plan: _Plan | None = None,
) -> dict[str, Any]:
    """Everything the page or the panel template renders."""
    config_path = _config_path()
    context: dict[str, Any] = {
        "tab": tab,
        "view": view,
        "query": query,
        "set_only": set_only,
        "non_default_only": non_default_only,
        "error": error,
        "notice": notice,
        "plan": plan,
        "page_url": PAGE_URL,
        "panel_url": PANEL_URL,
        "tabs": TABS,
        "views": VIEWS,
        "config_path": str(config_path),
        "config_name": config_path.name,
        "rows": [],
        "tree": [],
        "arrays": [],
        "env_rows": [],
        "revisions": [],
        "raw_text": "",
        "highlighted": Markup(""),
        "reference_available": False,
        "changed_count": 0,
        "key_count": 0,
        "table_count": 0,
        "validation": None,
        "fingerprint": "",
    }
    try:
        doc = _load_document(config_path)
    except (OSError, cd.ConfigDocumentError) as exc:
        context["error"] = gettext(
            "config.toml could not be read: %(detail)s", detail=str(exc)
        )
        return context
    reference = _reference_document()
    reference_changes = doc.reference_diff(reference) if reference.keys else []
    rows = _rows(
        doc,
        reference_changes,
        query=query,
        set_only=set_only,
        non_default_only=non_default_only,
    )
    revisions: list[dict[str, Any]] = []
    if tab == "history":
        try:
            revisions = _revision_rows(_revision_store(config_path), doc)
        except Exception:  # noqa: BLE001 - the history list is never fatal
            logger.error("Failed to list config revisions", exc_info=True)
    context.update(
        {
            "rows": rows,
            "fingerprint": _fingerprint(doc.text),
            "tree": _tree_rows(doc, rows),
            "arrays": _array_items(doc),
            "env_rows": _env_rows(config_path),
            "revisions": revisions,
            "raw_text": doc.redacted_text() if view == "raw" else "",
            "highlighted": _highlight_toml(doc.redacted_text()) if view == "raw" else Markup(""),
            "reference_available": bool(reference.keys),
            "changed_count": len(reference_changes),
            "key_count": len(doc.keys),
            "table_count": len(doc.tables),
            "validation": _current_validation(config_path),
        }
    )
    return context


# -- syntax highlighting -----------------------------------------------------
#
# Server-side on purpose: the raw view has to be readable without shipping JS
# into a shell this blueprint does not own, and the highlighted pane is always a
# view of the file on disk - never of a half-typed textarea.

_HIGHLIGHT_RE = re.compile(
    r"(?P<comment>#[^\n]*)"
    r"|(?P<header>^[ \t]*\[\[?[^\]\n]+\]\]?)"
    r"|(?P<key>^[ \t]*[A-Za-z0-9_\-.]+[ \t]*(?==))"
    r"|(?P<string>\"(?:\\.|[^\"\\])*\"|'[^']*')"
    r"|(?P<number>\b-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?\b)"
    r"|(?P<literal>\b(?:true|false|inf|nan)\b)",
    re.MULTILINE,
)

_HIGHLIGHT_CLASSES = {
    "comment": "ce-tok-comment",
    "header": "ce-tok-header",
    "key": "ce-tok-key",
    "string": "ce-tok-string",
    "number": "ce-tok-number",
    "literal": "ce-tok-literal",
}


def _highlight_toml(text: str) -> Markup:
    """Escape and wrap TOML tokens in spans; the input is never trusted."""
    parts: list[str] = []
    cursor = 0
    for match in _HIGHLIGHT_RE.finditer(text):
        parts.append(str(escape(text[cursor : match.start()])))
        css = _HIGHLIGHT_CLASSES.get(match.lastgroup or "", "")
        parts.append(f'<span class="{css}">{escape(match.group(0))}</span>')
        cursor = match.end()
    parts.append(str(escape(text[cursor:])))
    return Markup("".join(parts))


# -- routes ------------------------------------------------------------------


@config_editor_bp.route("/config")
@require_auth
def config_page():
    """The configuration editor: form, tree and raw views plus version history."""
    tab = request.args.get("tab", "editor")
    view = request.args.get("view", "form")
    try:
        context = _page_context(
            tab=tab if tab in TABS else "editor",
            view=view if view in VIEWS else "form",
            query=request.args.get("q", ""),
            set_only=request.args.get("set_only") == "1",
            non_default_only=request.args.get("non_default") == "1",
        )
    except Exception as exc:  # noqa: BLE001 - the page must still answer
        current_app.logger.error("[CONFIG-EDITOR] page failed: %s", exc, exc_info=True)
        return render_page(
            "admin/config_editor.html",
            tab="editor",
            view="form",
            error=str(exc),
            page_url=PAGE_URL,
            tabs=TABS,
            views=VIEWS,
            config_name="config.toml",
        )
    return render_page("admin/config_editor.html", **context)


@config_editor_bp.route("/config/watcher")
@require_auth
def config_watcher_page():
    """The pre-existing reload-history page, kept reachable under its own URL.

    ``/admin/config`` is the editor now, so the watcher page (reload history and
    the current signature) would otherwise have become unreachable.  Its
    fragments at ``/admin/config/history`` and ``/admin/config/signature`` are
    untouched and still serve this template.
    """
    return render_page("admin/config_watcher.html")


@config_editor_bp.route("/config/editor/panel")
@require_auth
def config_panel():
    """The editor body on its own, for view switches, filters and search."""
    view = request.args.get("view", "form")
    try:
        context = _page_context(
            tab="editor",
            view=view if view in VIEWS else "form",
            query=request.args.get("q", ""),
            set_only=request.args.get("set_only") == "1",
            non_default_only=request.args.get("non_default") == "1",
        )
    except Exception as exc:  # noqa: BLE001 - inline error, never a 500
        current_app.logger.error("[CONFIG-EDITOR] panel failed: %s", exc, exc_info=True)
        return render_page(
            "admin/config_editor_panel.html", error=str(exc), rows=[], tree=[], views=VIEWS
        )
    return render_page("admin/config_editor_panel.html", **context)


def _mutation_response(builder: Callable[[cd.ConfigDocument], _Candidate]):
    """Shared body of every mutation route: build, gate, maybe write."""
    confirm = request.form.get("confirm", "") == "1"
    base = request.form.get("base", "")
    try:
        plan = _submit(builder, confirm=confirm, base=base)
    except cd.ConfigDocumentError as exc:
        return _render_result(_Plan(notice=_notice("error", str(exc))))
    except (OSError, ValueError) as exc:
        current_app.logger.error("[CONFIG-EDITOR] change rejected: %s", exc, exc_info=True)
        return _render_result(_Plan(notice=_notice("error", str(exc))))
    except Exception as exc:  # noqa: BLE001 - never a 500 on bad input
        current_app.logger.error("[CONFIG-EDITOR] change failed: %s", exc, exc_info=True)
        return _render_result(
            _Plan(
                notice=_notice(
                    "error",
                    gettext("The change could not be prepared: %(detail)s", detail=str(exc)),
                )
            )
        )
    return _render_result(plan)


@config_editor_bp.route("/config/editor/value", methods=["POST"])
@require_auth
def config_value():
    """Edit one leaf value: review first, then confirm.

    The form view names every field ``ce.<dotted.path>``, so this endpoint needs
    no separate key field - and a row that somehow carries two fields is refused
    rather than silently applied as a batch.
    """
    fields = [name for name in request.form if name.startswith(_FIELD_PREFIX)]
    if not fields:
        return _render_result(_Plan(notice=_notice("error", gettext("No key was submitted."))))
    if len(fields) > 1:
        return _render_result(
            _Plan(
                notice=_notice(
                    "error", gettext("One value at a time: use Save changed fields instead.")
                )
            )
        )
    return _mutation_response(lambda doc: _candidate_for_batch(doc, request.form))


@config_editor_bp.route("/config/editor/batch", methods=["POST"])
@require_auth
def config_batch():
    """Review every changed field of the form view at once."""
    return _mutation_response(lambda doc: _candidate_for_batch(doc, request.form))


@config_editor_bp.route("/config/editor/key/add", methods=["POST"])
@require_auth
def config_key_add():
    """Add a key that does not exist yet (surgical: nothing else moves)."""
    table = request.form.get("table", "").strip()
    name = request.form.get("key", "").strip()
    if not name or "." in name or "[" in name or "]" in name:
        return _render_result(
            _Plan(notice=_notice("error", gettext("A key name must be a bare TOML key.")))
        )
    path = f"{table}.{name}" if table else name
    text = request.form.get("value", "")
    return _mutation_response(lambda doc: _candidate_for_leaf(doc, path, text))


@config_editor_bp.route("/config/editor/key/remove", methods=["POST"])
@require_auth
def config_key_remove():
    """Remove a key: the file is re-serialized, so the UI warns first."""
    key = request.form.get("key", "").strip()
    if not key:
        return _render_result(_Plan(notice=_notice("error", gettext("No key was submitted."))))

    def build(doc: cd.ConfigDocument) -> _Candidate:
        return _Candidate(
            doc.remove_leaf(key), True, gettext("Remove key %(key)s", key=key), key
        )

    return _mutation_response(build)


@config_editor_bp.route("/config/editor/table/add", methods=["POST"])
@require_auth
def config_table_add():
    """Add a table, or one more ``[[array.of.tables]]`` entry."""
    table = request.form.get("table", "").strip()
    if not table:
        return _render_result(_Plan(notice=_notice("error", gettext("No table was submitted."))))

    def build(doc: cd.ConfigDocument) -> _Candidate:
        return _Candidate(
            doc.add_table(table), True, gettext("Add table %(table)s", table=table), table
        )

    return _mutation_response(build)


@config_editor_bp.route("/config/editor/table/remove", methods=["POST"])
@require_auth
def config_table_remove():
    """Remove a table and everything under it."""
    table = request.form.get("table", "").strip()
    if not table:
        return _render_result(_Plan(notice=_notice("error", gettext("No table was submitted."))))

    def build(doc: cd.ConfigDocument) -> _Candidate:
        return _Candidate(
            doc.remove_table(table), True, gettext("Remove table %(table)s", table=table), table
        )

    return _mutation_response(build)


@config_editor_bp.route("/config/editor/array/add", methods=["POST"])
@require_auth
def config_array_add():
    """Append an array item; ``kind=table`` adds an empty table item."""
    key = request.form.get("key", "").strip()
    raw = request.form.get("value", "")
    if not key:
        return _render_result(_Plan(notice=_notice("error", gettext("No key was submitted."))))

    def build(doc: cd.ConfigDocument) -> _Candidate:
        value = {} if request.form.get("kind") == "table" else cd.load_value_text(raw)
        return _Candidate(
            doc.add_array_item(key, value),
            True,
            gettext("Add an item to %(key)s", key=key),
            key,
        )

    return _mutation_response(build)


@config_editor_bp.route("/config/editor/array/remove", methods=["POST"])
@require_auth
def config_array_remove():
    """Remove one array item by index."""
    key = request.form.get("key", "").strip()
    try:
        index = int(request.form.get("index", "-1"))
    except (TypeError, ValueError):
        index = -1
    if not key or index < 0:
        return _render_result(
            _Plan(notice=_notice("error", gettext("A key and an array index are required.")))
        )

    def build(doc: cd.ConfigDocument) -> _Candidate:
        return _Candidate(
            doc.remove_array_item(key, index),
            True,
            gettext("Remove item %(index)s of %(key)s", index=index, key=key),
            key,
        )

    return _mutation_response(build)


@config_editor_bp.route("/config/editor/raw", methods=["POST"])
@require_auth
def config_raw():
    """Save the raw text, with the redacted secret lines restored from disk.

    The textarea shows ``***REDACTED***`` where a secret value sits, so a save
    has to put the real value back.  If a secret line was edited or deleted in
    the meantime the save is refused: silently writing a placeholder over a
    password hash is exactly the lockout this editor exists to prevent.
    """
    submitted = request.form.get("raw_text", "")
    if len(submitted.encode("utf-8")) > MAX_RAW_BYTES:
        return _render_result(
            _Plan(notice=_notice("error", gettext("The submitted text is too large to save.")))
        )

    def build(doc: cd.ConfigDocument) -> _Candidate:
        candidate = doc.with_text(_restore_secrets(doc, submitted))
        candidate.data()  # fail here, with a message, if the text is not TOML
        return _Candidate(candidate, False, gettext("Save the raw config.toml"), raw_edit=True)

    return _mutation_response(build)


def _restore_secrets(doc: cd.ConfigDocument, submitted: str) -> str:
    """Put the real secret values back, or refuse a save that touched them.

    Three cases, and only three:

    * the redaction marker is re-posted where it came from - the operator did not
      touch that line, so the real value is written back from disk;
    * a secret-designated line is re-posted byte for byte - that is a
      ``${ENV_VAR:?}`` placeholder, which is visible documentation rather than a
      secret, and re-posting it is not an edit;
    * anything else on a secret-designated line is a hand-written secret, and
      that is refused: it is what would let a literal hash be typed here instead
      of set through the password flow.
    """
    spans = doc.secret_spans()
    markers = {span.redacted.strip('"') for span in spans}
    lines = cd.split_lines(submitted)
    for index, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        name = stripped.split("=", 1)[0].strip() if "=" in stripped else ""
        carries_marker = any(marker and marker in line for marker in markers)
        if name and cd.is_secret_path(name):
            original = _original_secret_line(doc, name)
            if original is not None and carries_marker:
                lines[index] = original
                continue
            if original is not None and line == original:
                continue
            raise cd.ConfigDocumentError(
                gettext(
                    "Secret values are not editable here: leave %(key)s as it is, or set a "
                    "new password / .env value on the Secrets tab.",
                    key=name,
                )
            )
        if carries_marker:
            raise cd.ConfigDocumentError(
                gettext("A redacted value was moved or duplicated; reload the raw view.")
            )
    return "".join(lines)


def _original_secret_line(doc: cd.ConfigDocument, key: str) -> str | None:
    lines = cd.split_lines(doc.text)
    for ref in doc.keys:
        if ref.key == key and cd.is_secret_path(ref.path):
            return lines[ref.line - 1]
    return None


@config_editor_bp.route("/config/editor/env", methods=["POST"])
@require_auth
def config_env_set():
    """Write one ``.env`` variable (write-only: the value is never echoed)."""
    key = request.form.get("key", "").strip()
    value = request.form.get("value", "")
    if key not in ENV_KEYS:
        return _render_result(
            _Plan(notice=_notice("error", gettext("That variable cannot be edited here.")))
        )
    if not str(value).strip():
        return _render_result(
            _Plan(notice=_notice("error", gettext("Enter a value first; nothing was written.")))
        )
    return _env_write(key, str(value).strip())


@config_editor_bp.route("/config/editor/env/clear", methods=["POST"])
@require_auth
def config_env_clear():
    """Clear one ``.env`` variable by writing it empty."""
    key = request.form.get("key", "").strip()
    if key not in ENV_KEYS:
        return _render_result(
            _Plan(notice=_notice("error", gettext("That variable cannot be edited here.")))
        )
    return _env_write(key, "")


def _env_write(key: str, value: str):
    config_path = _config_path()
    env_path = config_path.parent / ".env"
    try:
        with _WRITE_LOCK:
            write_env_value(env_path, key, value)
            reload_error = _reload_runtime()
    except Exception as exc:  # noqa: BLE001 - inline error, never a 500
        current_app.logger.error("[CONFIG-EDITOR] .env write failed: %s", exc, exc_info=True)
        return _render_result(
            _Plan(
                notice=_notice(
                    "error",
                    gettext("The .env value could not be written: %(detail)s", detail=str(exc)),
                )
            )
        )
    plan = _Plan(label=gettext("Set %(key)s in .env", key=key))
    plan.written = True
    plan.reload_error = reload_error
    plan.notes = [
        gettext(
            "Credentials are read when the config loads, so the reload above is what "
            "applies this to the running runtime."
        )
    ]
    plan.notice = _notice(
        "warning" if reload_error else "success",
        gettext("%(key)s written to .env; the value is never shown again.", key=key),
    )
    return _render_result(plan)


@config_editor_bp.route("/config/editor/password", methods=["POST"])
@require_auth
def config_password():
    """Set a new admin password: hashed here, written to ``.env``, never echoed."""
    password = request.form.get("password", "")
    confirmation = request.form.get("password_confirm", "")
    if len(password) < 8:
        return _render_result(
            _Plan(
                notice=_notice(
                    "error", gettext("Use at least 8 characters for the admin password.")
                )
            )
        )
    if password != confirmation:
        return _render_result(
            _Plan(notice=_notice("error", gettext("The two passwords do not match.")))
        )
    hashed = generate_password_hash(password)
    del password, confirmation
    config_path = _config_path()
    env_path = config_path.parent / ".env"
    try:
        with _WRITE_LOCK:
            write_env_value(env_path, PASSWORD_ENV_KEY, hashed)
            reload_error = _reload_runtime()
    except Exception as exc:  # noqa: BLE001 - inline error, never a 500
        current_app.logger.error("[CONFIG] password write failed: %s", exc, exc_info=True)
        return _render_result(
            _Plan(
                notice=_notice(
                    "error",
                    gettext("The new password could not be written: %(detail)s", detail=str(exc)),
                )
            )
        )
    plan = _Plan(label=gettext("Set a new admin password"))
    plan.written = True
    plan.reload_error = reload_error
    plan.notes = [
        gettext("The hash is never displayed, not even to you."),
        gettext(
            "web_admin.password_hash resolves this value, and it is read on every "
            "sign-in, so the reload above is what activates the new password."
        ),
    ]
    plan.notice = _notice(
        "warning" if reload_error else "success",
        gettext("The new password is active for the next sign-in."),
    )
    return _render_result(plan)


@config_editor_bp.route("/config/editor/validate")
@require_auth
def config_validate():
    """Validate the file on disk with the same validator the CLI uses."""
    config_path = _config_path()
    report = _current_validation(config_path)
    plan = _Plan(label=gettext("Validate %(name)s", name=config_path.name))
    plan.errors = report["errors"]
    plan.warnings = report["warnings"]
    plan.notice = _notice(
        "error" if report["errors"] else ("warning" if report["warnings"] else "success"),
        gettext("Validated %(name)s.", name=config_path.name),
    )
    return _render_result(plan)


# -- version history ---------------------------------------------------------


@config_editor_bp.route("/config/editor/history")
@require_auth
def config_history_panel():
    """The revision list, refreshed on its own."""
    try:
        context = _page_context(
            tab="history", view="form", query="", set_only=False, non_default_only=False
        )
    except Exception as exc:  # noqa: BLE001 - inline error, never a 500
        current_app.logger.error("[CONFIG-EDITOR] history failed: %s", exc, exc_info=True)
        return render_page(
            "admin/config_editor_history.html", error=str(exc), revisions=[], tabs=TABS
        )
    return render_page("admin/config_editor_history.html", **context)


@config_editor_bp.route("/config/editor/revision/diff")
@require_auth
def config_revision_diff():
    """Semantic diff of one revision against the file on disk."""
    return _render_result(_revision_diff_plan(request.args.get("revision", "")))


def _revision_diff_plan(revision_id: str) -> _Plan:
    config_path = _config_path()
    plan = _Plan(label=gettext("Revision %(id)s", id=revision_id))
    if not revision_id:
        plan.errors = [gettext("Unknown revision.")]
        return plan
    try:
        store = _revision_store(config_path)
        current = _load_document(config_path)
        if revision_id.startswith("backup:"):
            text = store.read(revision_id)
            if text is None:
                plan.errors = [gettext("That backup is no longer on disk.")]
                return plan
            # ``current.diff(old)`` reads as "what restoring this would change".
            plan.changes = current.diff(current.with_text(text))
            # A backup that differs only in comments or layout is still a real
            # restore target; without this the diff view would show no table and
            # offer no confirm, and the restore could never be completed.
            plan.text_only = not plan.changes and text != current.text
            plan.restart = _restart_keys([change.path for change in plan.changes])
            plan.fingerprint = _fingerprint(current.text)
            plan.payload = {"revision": revision_id, "base": plan.fingerprint}
            plan.confirm_url = "/admin/config/editor/revision/restore"
            plan.notice = _notice(
                "info",
                gettext(
                    "Restoring this backup applies the changes below; the current file is "
                    "backed up first."
                ),
            )
            return plan
        revision = next(
            (item for item in store.list_revisions(limit=200) if item.revision_id == revision_id),
            None,
        )
        if revision is None:
            plan.errors = [gettext("Unknown revision.")]
            return plan
        plan.changes = [cd.Change(path, "changed", None, None) for path in revision.changed_keys]
        plan.notes = [gettext("Recorded keys only: this entry stores no content to restore.")]
        # ``confirm_url`` stays empty: a recorded change owns no content, so the
        # template renders this as a read-only report instead of a button that
        # would post to a route that only answers GET.
        plan.notice = _notice(
            "warning",
            gettext(
                "This entry records which keys changed, not their content: it can be read "
                "but not restored or downloaded."
            ),
        )
        return plan
    except (OSError, cd.ConfigDocumentError) as exc:
        plan.errors = [str(exc)]
        return plan
    except Exception as exc:  # noqa: BLE001 - never a 500
        current_app.logger.error("[CONFIG-EDITOR] revision diff failed: %s", exc, exc_info=True)
        plan.errors = [str(exc)]
        return plan


@config_editor_bp.route("/config/editor/revision/restore", methods=["POST"])
@require_auth
def config_revision_restore():
    """Write a backup's content back, then revalidate and report the restart."""
    revision_id = request.form.get("revision", "")
    base = request.form.get("base", "")
    config_path = _config_path()
    try:
        with _WRITE_LOCK:
            store = _revision_store(config_path)
            text = store.read(revision_id)
            if text is None:
                return _render_result(
                    _Plan(
                        notice=_notice(
                            "error", gettext("That revision has no stored content to restore.")
                        )
                    )
                )
            current = _load_document(config_path)
            if base and base != _fingerprint(current.text):
                return _render_result(
                    _Plan(
                        notice=_notice(
                            "error",
                            gettext(
                                "config.toml changed on disk since the preview; re-open the "
                                "editor before restoring."
                            ),
                        )
                    )
                )
            label = gettext("Restore revision %(id)s", id=revision_id)
            # The backup is re-validated exactly like any other candidate: a
            # restore that would introduce errors is refused, and one that only
            # removes them is allowed.
            #
            # ``raw_edit`` is set because a backup is restored verbatim: a copy
            # that differs only in comments or layout is still a restore the
            # operator asked for, and without the flag the gate below would call
            # it "no changes" and quietly do nothing.
            plan = _submit(
                lambda doc: _Candidate(doc.with_text(text), False, label, raw_edit=True),
                confirm=True,
                base="",
            )
            return _render_result(plan)
    except Exception as exc:  # noqa: BLE001 - never a 500
        current_app.logger.error("[CONFIG-EDITOR] restore failed: %s", exc, exc_info=True)
        return _render_result(_Plan(notice=_notice("error", str(exc))))


@config_editor_bp.route("/config/editor/revision/download")
@require_auth
def config_revision_download():
    """Download a backup with secret values redacted.

    A backup is a copy of a file the operator can already read, but a response
    body is still a response: keeping the redaction rule absolute means there is
    no endpoint in this blueprint that can hand out a literal secret.
    """
    revision_id = request.args.get("revision", "")
    config_path = _config_path()
    text = _revision_store(config_path).read(revision_id)
    if text is None:
        return _render_result(
            _Plan(
                notice=_notice(
                    "error", gettext("That revision has no stored content to download.")
                )
            )
        )
    try:
        body = cd.ConfigDocument(text).redacted_text()
    except cd.ConfigDocumentError as exc:
        # Never fall back to the raw text here.  This response is a *download*,
        # and an unredactable file is exactly the one that may carry a literal
        # secret: refusing is the only safe answer.
        logger.warning("Refused an unredactable config download: %s", exc)
        return _render_result(
            _Plan(
                notice=_notice(
                    "error",
                    gettext(
                        "That revision could not be redacted, so it will not be downloaded."
                    ),
                )
            )
        )
    name = revision_id.partition(":")[2] or f"{config_path.name}.bak"
    response = Response(body, mimetype="text/plain")
    response.headers["Content-Disposition"] = f'attachment; filename="{name}"'
    return response


__all__ = [
    "ENV_KEYS",
    "PAGE_URL",
    "RESTART_REQUIRED_PREFIXES",
    "TABS",
    "VIEWS",
    "config_editor_bp",
]
