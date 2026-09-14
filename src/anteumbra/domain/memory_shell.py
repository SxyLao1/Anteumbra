# -*- coding: utf-8 -*-
"""Domain objects for the memory-shell probe.

A memory shell lives only inside the servlet container's memory: it is not a
file on disk, so the file monitor can never see it. The only honest way for a
local defender to find one is to ask the container itself, from inside the
same JVM, which is what the probe does:

    drop a token-guarded JSP into the watched web root
      -> request it once over HTTP
      -> read back what is registered in memory
      -> delete the probe and its directory

Everything in this module is inert data plus the two ports the probe needs, so
the workflow can be tested without a container, a filesystem or a network.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol, Sequence

PROBE_MARKER = "ANTEUMBRA-MEMORY-SHELL-PROBE"
# 1.1.0 added the ``action`` parameter (probe / dump / kill): the probe no longer
# only answers a read-only report.
PROBE_VERSION = "1.1.0"

# ── probe actions ───────────────────────────────────────────────────
# One probe file answers three token-gated questions.  ``probe`` is the read-only
# report that the first release shipped; ``dump`` records everything the JVM can
# still be asked about one component; ``kill`` removes that component from the
# container's memory.  All three are POST-free GETs that return a single JSON
# object, and none of them ever touches a file.
ACTION_PROBE = "probe"
ACTION_DUMP = "dump"
ACTION_KILL = "kill"
PROBE_ACTIONS = (ACTION_PROBE, ACTION_DUMP, ACTION_KILL)


class ProbeError(RuntimeError):
    """Raised when a probe cannot be deployed, read or parsed.

    It lives in the domain layer because both sides of the probe speak it: the
    infrastructure that performs the filesystem and HTTP work raises it, and the
    application service that orchestrates a run reports it as a probe failure.
    """


# entry kinds reported by the probe
KIND_FILTER = "filter"
KIND_SERVLET = "servlet"
KIND_LISTENER = "listener"

# Only filters, servlets and listeners can be dumped or removed: they are what a
# container registers, and therefore what a probe can identify again later.
# Classes parked in an HttpSession are reported (KIND_SESSION) but are never an
# action target, because removing a session attribute is not remediation of a
# memory shell.
KIND_SESSION = "session"
ACTION_KINDS = (KIND_FILTER, KIND_SERVLET, KIND_LISTENER)

# ── refusal / failure reasons ───────────────────────────────────────
# Every one of these is a machine-readable code that reaches the operator in
# the API response and in the alert path; a refusal never silently does nothing.
REASON_COMPONENT_NOT_FOUND = "component_not_found"
REASON_CLASS_NAME_MISMATCH = "class_name_mismatch"
REASON_CLASS_ON_DISK = "class_on_disk"
REASON_NO_RECORDED_CLASS = "no_recorded_class"
REASON_FORENSICS_REQUIRED = "forensics_required"
REASON_FORENSICS_DISABLED = "forensics_disabled"
REASON_FORENSICS_STORE_UNAVAILABLE = "forensics_store_unavailable"
REASON_FORENSICS_STORE_ERROR = "forensics_store_error"
REASON_UNKNOWN_KIND = "unknown_kind"
REASON_INVALID_COMPONENT = "invalid_component"
REASON_UNKNOWN_SITE = "unknown_or_unwatchable_site"
REASON_PROBE_DISABLED = "probe_disabled"
REASON_ALREADY_RUNNING = "probe_already_running"

# The one honest way a dump request can end without bytes: the class was defined
# at runtime, so no classloader resource exists for it.  A JSP cannot recover
# the bytecode of such a class from a running JVM, and pretending otherwise
# would be worse than saying so.
CLASS_BYTES_RUNTIME_DEFINED = "class_defined_at_runtime_without_bytecode_resource"

# Bounds shared by everything that reads probe output.  The probe bounds itself,
# but this side parses whatever came back over HTTP, so it bounds again.
MAX_MANIFEST_MEMBERS = 500
MAX_MANIFEST_TEXT = 512
MAX_INDEX_NAME = 200

# ── forensics defaults (validated in the service, not in a config template) ──
DEFAULT_FORENSICS_HISTORY = 200
MAX_FORENSICS_HISTORY = 10_000
DEFAULT_FORENSICS_MAX_DUMP_MB = 2048
MAX_FORENSICS_MAX_DUMP_MB = 1_048_576
# A heap dump answers slowly; this is the budget for dump/kill requests only.
DEFAULT_FORENSICS_TIMEOUT_SECONDS = 300.0


@dataclass(frozen=True)
class ProbeArtifact:
    """A probe file that exists on disk right now and must be removed again."""

    site_id: str
    site_root: Path
    directory: Path
    file_path: Path
    token: str
    url: str
    created_at: float

    @property
    def relative_url_path(self) -> str:
        """URL path of the probe as seen by the web server."""
        return "/" + self.file_path.relative_to(self.site_root).as_posix()


@dataclass(frozen=True)
class MemoryShellEntry:
    """One filter/servlet/listener currently registered inside the container."""

    kind: str
    name: str
    urls: tuple[str, ...] = ()
    class_name: str = ""
    class_loader: str | None = None
    resource: str | None = None
    code_source: str | None = None
    suspect: bool = False
    reasons: tuple[str, ...] = ()

    @property
    def on_disk(self) -> bool:
        """True when the class can be resolved to a file/jar on disk."""
        return bool(self.resource or self.code_source)

    def as_dict(self) -> dict[str, object]:
        return {
            "kind": self.kind,
            "name": self.name,
            "urls": list(self.urls),
            "class_name": self.class_name,
            "class_loader": self.class_loader,
            "resource": self.resource,
            "code_source": self.code_source,
            "suspect": self.suspect,
            "reasons": list(self.reasons),
            "on_disk": self.on_disk,
        }


@dataclass(frozen=True)
class ProbeReport:
    """What one probe run saw, plus how the run itself went."""

    site_id: str
    url: str
    fetched_at: float
    probe_version: str = PROBE_VERSION
    context_path: str = ""
    container: tuple[str, ...] = ()
    entries: tuple[MemoryShellEntry, ...] = ()
    error: str | None = None
    duration_ms: int = 0
    raw_bytes: int = 0

    @property
    def suspects(self) -> tuple[MemoryShellEntry, ...]:
        return tuple(entry for entry in self.entries if entry.suspect)

    @property
    def ok(self) -> bool:
        return self.error is None

    def counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for entry in self.entries:
            counts[entry.kind] = counts.get(entry.kind, 0) + 1
        return counts

    def as_dict(self) -> dict[str, object]:
        return {
            "site_id": self.site_id,
            "url": self.url,
            "fetched_at": self.fetched_at,
            "probe_version": self.probe_version,
            "context_path": self.context_path,
            "container": list(self.container),
            "error": self.error,
            "duration_ms": self.duration_ms,
            "raw_bytes": self.raw_bytes,
            "counts": self.counts(),
            "entries": [entry.as_dict() for entry in self.entries],
        }


@dataclass(frozen=True)
class ProbeOutcome:
    """Result of one deploy/read/cleanup cycle, including failures."""

    site_id: str
    site_name: str
    started_at: float
    finished_at: float
    report: ProbeReport | None = None
    failure: str | None = None
    cleanup_ok: bool = True
    cleanup_error: str | None = None
    trigger: str = "manual"
    triggered_by: str = ""
    extra: dict[str, object] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.failure is None and self.report is not None and self.report.ok

    @property
    def suspect_count(self) -> int:
        return len(self.report.suspects) if self.report else 0

    def as_dict(self) -> dict[str, object]:
        return {
            "site_id": self.site_id,
            "site_name": self.site_name,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_ms": int((self.finished_at - self.started_at) * 1000),
            "ok": self.ok,
            "failure": self.failure,
            "cleanup_ok": self.cleanup_ok,
            "cleanup_error": self.cleanup_error,
            "trigger": self.trigger,
            "triggered_by": self.triggered_by,
            "suspect_count": self.suspect_count,
            "report": self.report.as_dict() if self.report else None,
            **self.extra,
        }


class InternalArtifactRegistryPort(Protocol):
    """Tracks files Anteumbra itself created inside watched directories.

    Without this, the probe would be detected by Anteumbra's own scanner and
    its HTTP access would be attributed to an attacker. Registration is
    deliberately time-boxed: an entry disappears with the probe.
    """

    def register(self, *, path: str | Path, url_fragment: str, ttl: float) -> None:
        ...

    def release(self, path: str | Path) -> None:
        ...

    def is_internal_path(self, path: str | Path) -> bool:
        ...

    def contains_url(self, url: str) -> bool:
        ...


class ProbeReaderPort(Protocol):
    """Fetches the probe URL. Kept injectable so tests need no server."""

    def __call__(self, url: str, timeout: float) -> bytes:
        ...


@dataclass(frozen=True)
class SiteTarget:
    """The part of a website configuration a probe needs.

    ``root`` is the monitored directory (used to attribute detections to a
    site). ``probe_root`` is the directory the probe is written into, which
    differs whenever the web server only serves a subdirectory of the monitored
    tree: a JSP written next to Tomcat's contexts under ``webapps`` belongs to
    no deployed context and answers 404, so the probe has to land inside one
    (for example ``webapps/dshlab``) and be requested with that context as the
    URL prefix.
    """

    site_id: str
    name: str
    root: Path
    base_url: str          # e.g. http://127.0.0.1:8081
    port: int = 80
    scheme: str = "http"
    host: str = "127.0.0.1"
    url_prefix: str = ""   # URL path that maps to the deployment root
    probe_root: Path | None = None
    base_note: str = ""    # why this deployment root was chosen

    @property
    def deployment_root(self) -> Path:
        return Path(self.probe_root) if self.probe_root else Path(self.root)

    def url_for(self, relative_url_path: str) -> str:
        prefix = self.url_prefix.rstrip("/")
        path = relative_url_path if relative_url_path.startswith("/") else "/" + relative_url_path
        return f"{self.scheme}://{self.host}:{self.port}{prefix}{path}"


def entry_from_payload(payload: dict[str, object]) -> MemoryShellEntry:
    """Build one entry from the probe's JSON, tolerating missing fields."""
    urls = payload.get("urls") or ()
    reasons = payload.get("reasons") or ()
    return MemoryShellEntry(
        kind=str(payload.get("type") or payload.get("kind") or ""),
        name=str(payload.get("name") or ""),
        urls=tuple(str(item) for item in urls) if isinstance(urls, Sequence) else (),
        class_name=str(payload.get("class") or payload.get("class_name") or ""),
        class_loader=_optional_str(payload.get("class_loader")),
        resource=_optional_str(payload.get("resource")),
        code_source=_optional_str(payload.get("code_source")),
        suspect=bool(payload.get("suspect")),
        reasons=tuple(str(item) for item in reasons) if isinstance(reasons, Sequence) else (),
    )


def _optional_str(value: object) -> str | None:
    if value is None:
        return None
    text = str(value)
    return text or None


# ════════════════════════════════════════════════════════════════════
#  forensics (取证) and remediation (处置)
# ════════════════════════════════════════════════════════════════════
#
# Detection answers "is something registered in memory that should not be".
# Forensics answers "what exactly is it", and remediation answers "take it out".
# Both are deliberately conservative: the dump records only what the JVM can
# really be asked, and the kill refuses unless the component is still the same
# class Anteumbra recorded and is not a legitimately deployed file.


def _text(value: object, limit: int = MAX_MANIFEST_TEXT) -> str:
    """Render one untrusted probe field as bounded text."""
    if value is None:
        return ""
    text = str(value)
    if len(text) <= limit:
        return text
    return text[:limit] + f"...[+{len(text) - limit} chars]"


def _int(value: object, default: int = 0) -> int:
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default


def _bounded_strings(value: object, limit: int = MAX_MANIFEST_MEMBERS) -> tuple[str, ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        return ()
    items = [_text(item) for item in value]
    return tuple(items[:limit])


def slugify(value: object, *, fallback: str = "component", limit: int = 48) -> str:
    """A filesystem-safe, human-readable fragment for artifact directories."""
    text = str(value or "").strip().lower()
    out: list[str] = []
    for char in text:
        if char.isalnum() or char in "._-":
            out.append(char)
        elif char in " /\\:@#$%^&*()+={}[]|;'\"<>,?!":
            out.append("-")
    slug = "".join(out)
    while "--" in slug:
        slug = slug.replace("--", "-")
    slug = slug.strip("-._")
    return (slug[:limit].strip("-._")) or fallback


def artifact_id_for(created_at: float, kind: str, name: str) -> str:
    """``<UTC timestamp>-<kind>-<slug>``: sortable, readable, path-safe."""
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime(created_at))
    return f"{stamp}-{slugify(kind, fallback='component', limit=16)}-{slugify(name)}"


@dataclass(frozen=True)
class ComponentRef:
    """One component identified well enough to be dumped or removed again.

    ``kind`` + ``name`` is what the container registers; ``class_name`` is what
    Anteumbra recorded for it, and therefore the only thing a later action is
    allowed to match against.  Without a recorded class name there is nothing to
    compare, so remediation refuses rather than guessing.
    """

    kind: str
    name: str
    class_name: str = ""
    urls: tuple[str, ...] = ()

    @property
    def valid(self) -> bool:
        return self.kind in ACTION_KINDS and bool(self.name)

    @property
    def label(self) -> str:
        return f"{self.kind}:{self.name or self.class_name or 'unknown'}"

    def as_dict(self) -> dict[str, object]:
        return {
            "kind": self.kind,
            "name": self.name,
            "class_name": self.class_name,
            "urls": list(self.urls),
        }


@dataclass(frozen=True)
class ForensicsManifest:
    """Everything the probe could honestly report about one component."""

    kind: str = ""
    name: str = ""
    urls: tuple[str, ...] = ()
    class_name: str = ""
    class_loader: str = ""
    class_loader_identity: str = ""
    code_source: str = ""
    on_disk: bool = False
    methods: tuple[str, ...] = ()
    fields: tuple[str, ...] = ()
    protection_domain: str = ""
    container: tuple[str, ...] = ()
    context_path: str = ""
    probe_url: str = ""
    jvm_input_arguments: tuple[str, ...] = ()
    attach_self: str = ""
    on_disk_path: str = ""
    class_bytes_source: str = ""
    class_bytes_note: str = ""
    captured_at: float = 0.0
    extra: dict[str, object] = field(default_factory=dict)

    def as_dict(self) -> dict[str, object]:
        return {
            "kind": self.kind,
            "name": self.name,
            "urls": list(self.urls),
            "class_name": self.class_name,
            "class_loader": self.class_loader,
            "class_loader_identity": self.class_loader_identity,
            "code_source": self.code_source,
            "on_disk": self.on_disk,
            "on_disk_path": self.on_disk_path,
            "methods": list(self.methods),
            "fields": list(self.fields),
            "protection_domain": self.protection_domain,
            "container": list(self.container),
            "context_path": self.context_path,
            "probe_url": self.probe_url,
            "jvm_input_arguments": list(self.jvm_input_arguments),
            "attach_self": self.attach_self,
            "class_bytes_source": self.class_bytes_source,
            "class_bytes_note": self.class_bytes_note,
            "captured_at": self.captured_at,
            **self.extra,
        }


def manifest_from_payload(payload: object) -> ForensicsManifest:
    """Build a manifest from the probe's JSON, tolerating and bounding anything."""
    data = payload if isinstance(payload, dict) else {}
    known = {
        "kind", "name", "urls", "class_name", "class_loader", "class_loader_identity",
        "code_source", "on_disk", "on_disk_path", "methods", "fields",
        "protection_domain", "container", "context_path", "probe_url",
        "jvm_input_arguments", "attach_self", "class_bytes_source", "class_bytes_note",
        "captured_at",
    }
    extra = {str(key): _text(value) for key, value in data.items() if str(key) not in known}
    return ForensicsManifest(
        kind=_text(data.get("kind"), 64),
        name=_text(data.get("name"), MAX_INDEX_NAME),
        urls=_bounded_strings(data.get("urls")),
        class_name=_text(data.get("class_name")),
        class_loader=_text(data.get("class_loader")),
        class_loader_identity=_text(data.get("class_loader_identity")),
        code_source=_text(data.get("code_source")),
        on_disk=bool(data.get("on_disk")),
        methods=_bounded_strings(data.get("methods")),
        fields=_bounded_strings(data.get("fields")),
        protection_domain=_text(data.get("protection_domain")),
        container=_bounded_strings(data.get("container")),
        context_path=_text(data.get("context_path"), 256),
        probe_url=_text(data.get("probe_url"), 1024),
        jvm_input_arguments=_bounded_strings(data.get("jvm_input_arguments"), 64),
        attach_self=_text(data.get("attach_self"), 64),
        on_disk_path=_text(data.get("on_disk_path"), 1024),
        class_bytes_source=_text(data.get("class_bytes_source"), 1024),
        class_bytes_note=_text(data.get("class_bytes_note"), 1024),
        captured_at=float(_int(data.get("captured_at")) or 0),
        extra=extra,
    )


@dataclass(frozen=True)
class HeapDumpInfo:
    """What the JVM said about the heap dump it was asked to write."""

    path: str = ""
    bytes: int = 0
    sha256: str = ""
    live: bool = False
    requested: bool = False

    @property
    def ok(self) -> bool:
        return bool(self.path) and self.bytes > 0

    def as_dict(self) -> dict[str, object]:
        return {
            "path": self.path,
            "bytes": self.bytes,
            "sha256": self.sha256,
            "live": self.live,
            "requested": self.requested,
        }


def heap_from_payload(payload: object) -> HeapDumpInfo:
    data = payload if isinstance(payload, dict) else {}
    return HeapDumpInfo(
        path=_text(data.get("heap_path"), 1024),
        bytes=_int(data.get("heap_bytes")),
        sha256=_text(data.get("heap_sha256"), 128),
        live=bool(data.get("heap_live")),
        requested=bool(data.get("heap_requested")),
    )


def entries_from_payload(payload: object) -> tuple["MemoryShellEntry", ...]:
    """Read an entry list out of an action response (probe or kill)."""
    data = payload if isinstance(payload, dict) else {}
    raw = data.get("entries")
    entries: list[MemoryShellEntry] = []
    if isinstance(raw, list):
        for item in raw:
            if isinstance(item, dict):
                entries.append(entry_from_payload(item))
    return tuple(entries)


def component_from_payload(payload: object) -> ComponentRef:
    data = payload if isinstance(payload, dict) else {}
    return ComponentRef(
        kind=_text(data.get("kind"), 64),
        name=_text(data.get("name"), MAX_INDEX_NAME),
        class_name=_text(data.get("class_name")),
        urls=_bounded_strings(data.get("urls")),
    )


def action_failure_reason(payload: object) -> str:
    """The refusal/failure code an action response carries, if any."""
    data = payload if isinstance(payload, dict) else {}
    if data.get("refused"):
        return _text(data.get("reason"), 128) or "refused"
    if data.get("error"):
        return _text(data.get("error"), 256)
    if data.get("failure"):
        return _text(data.get("failure"), 256)
    return ""


@dataclass(frozen=True)
class ForensicsPlan:
    """Where one forensics run will put its artifacts before the probe runs.

    The directory has to exist *before* the request: the heap dump is written by
    the target JVM itself, so the path handed to ``dumpHeap`` must already be a
    real, writable directory.
    """

    artifact_id: str
    site_id: str
    directory: Path
    manifest_path: Path
    class_path: Path | None
    heap_path: Path

    def as_dict(self) -> dict[str, object]:
        return {
            "artifact_id": self.artifact_id,
            "site_id": self.site_id,
            "directory": str(self.directory),
            "heap_path": str(self.heap_path),
        }


@dataclass(frozen=True)
class ForensicsOutcome:
    """Result of one forensics run, failures and cleanup state included."""

    site_id: str
    site_name: str
    started_at: float
    finished_at: float
    ref: ComponentRef | None = None
    trigger: str = "manual"
    triggered_by: str = ""
    failure: str | None = None
    cleanup_ok: bool = True
    cleanup_error: str | None = None
    manifest: ForensicsManifest | None = None
    class_bytes_bytes: int = 0
    class_bytes_unavailable_reason: str = ""
    heap: HeapDumpInfo | None = None
    heap_error: str = ""
    heap_skipped_reason: str = ""
    artifact_id: str = ""
    artifact_dir: str = ""
    files: tuple[dict[str, object], ...] = ()
    index_recorded: bool = False
    index_error: str = ""
    report_error: str = ""
    probe_url: str = ""
    extra: dict[str, object] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.failure is None and self.manifest is not None

    @property
    def has_class_bytes(self) -> bool:
        return self.class_bytes_bytes > 0

    def as_dict(self) -> dict[str, object]:
        return {
            "action": ACTION_DUMP,
            "site_id": self.site_id,
            "site_name": self.site_name,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_ms": int((self.finished_at - self.started_at) * 1000),
            "ok": self.ok,
            "failure": self.failure,
            "cleanup_ok": self.cleanup_ok,
            "cleanup_error": self.cleanup_error,
            "trigger": self.trigger,
            "triggered_by": self.triggered_by,
            "component": self.ref.as_dict() if self.ref else None,
            "manifest": self.manifest.as_dict() if self.manifest else None,
            "class_bytes_bytes": self.class_bytes_bytes,
            "class_bytes_available": self.has_class_bytes,
            "class_bytes_unavailable_reason": self.class_bytes_unavailable_reason,
            "heap": self.heap.as_dict() if self.heap else None,
            "heap_error": self.heap_error,
            "heap_skipped_reason": self.heap_skipped_reason,
            "artifact_id": self.artifact_id,
            "artifact_dir": self.artifact_dir,
            "files": [dict(item) for item in self.files],
            "index_recorded": self.index_recorded,
            "index_error": self.index_error,
            "report_error": self.report_error,
            "probe_url": self.probe_url,
            **self.extra,
        }


@dataclass(frozen=True)
class RemediationOutcome:
    """Result of one remediation request: removed, refused, or failed."""

    site_id: str
    site_name: str
    kind: str
    name: str
    started_at: float
    finished_at: float
    expect_class: str = ""
    trigger: str = "manual"
    triggered_by: str = ""
    removed: bool = False
    refused: bool = False
    reason: str = ""
    failure: str | None = None
    cleanup_ok: bool = True
    cleanup_error: str | None = None
    acknowledge_no_forensics: bool = False
    force: bool = False
    forensics_artifact_id: str = ""
    before_entries: tuple[MemoryShellEntry, ...] = ()
    after_entries: tuple[MemoryShellEntry, ...] = ()
    before_component: dict[str, object] = field(default_factory=dict)
    after_component: dict[str, object] = field(default_factory=dict)
    probe_url: str = ""
    published: bool = False
    recorded: bool = False
    extra: dict[str, object] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.failure is None and not self.refused and self.removed

    @property
    def component_label(self) -> str:
        return f"{self.kind}:{self.name}"

    def as_dict(self) -> dict[str, object]:
        return {
            "action": ACTION_KILL,
            "site_id": self.site_id,
            "site_name": self.site_name,
            "kind": self.kind,
            "name": self.name,
            "component": self.component_label,
            "expect_class": self.expect_class,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_ms": int((self.finished_at - self.started_at) * 1000),
            "ok": self.ok,
            "removed": self.removed,
            "refused": self.refused,
            "reason": self.reason,
            "failure": self.failure,
            "cleanup_ok": self.cleanup_ok,
            "cleanup_error": self.cleanup_error,
            "force": self.force,
            "acknowledge_no_forensics": self.acknowledge_no_forensics,
            "trigger": self.trigger,
            "triggered_by": self.triggered_by,
            "forensics_artifact_id": self.forensics_artifact_id,
            "before_component": dict(self.before_component),
            "after_component": dict(self.after_component),
            "before_entries": [item.as_dict() for item in self.before_entries],
            "after_entries": [item.as_dict() for item in self.after_entries],
            "before_count": len(self.before_entries),
            "after_count": len(self.after_entries),
            "probe_url": self.probe_url,
            "published": self.published,
            "recorded": self.recorded,
            **self.extra,
        }


class ForensicsStorePort(Protocol):
    """Persists forensics artifacts plus the one index that describes them.

    The store owns the layout (``<root>/<site>/<artifact id>/...``) and the
    index file, and it is the only writer of both.  It never deletes a component
    or a site file: removing artifacts is out of scope.
    """

    @property
    def available(self) -> bool:
        ...

    @property
    def root(self) -> Path:
        ...

    def begin(self, *, site_id: str, kind: str, name: str, created_at: float) -> ForensicsPlan:
        ...

    def save_run(
        self,
        plan: ForensicsPlan,
        *,
        site_name: str,
        class_name: str,
        on_disk: bool,
        trigger: str,
        triggered_by: str,
        manifest: ForensicsManifest,
        class_bytes: bytes | None,
        heap: HeapDumpInfo | None,
        heap_error: str,
        class_bytes_unavailable_reason: str,
        report_error: str,
        live: bool = False,
    ) -> dict[str, object]:
        ...

    def discard(self, plan: ForensicsPlan) -> bool:
        ...

    def index(self, *, limit: int = 0) -> list[dict[str, object]]:
        ...

    def get(self, artifact_id: str) -> dict[str, object] | None:
        ...

    def find_component(
        self, *, site_id: str, kind: str, name: str
    ) -> dict[str, object] | None:
        ...

    def record_remediation(
        self,
        artifact_id: str,
        *,
        result: str,
        removed: bool,
        reason: str,
        operator: str,
        acknowledge_no_forensics: bool,
        force: bool,
        remediated_at: float,
    ) -> dict[str, object] | None:
        ...

    def read_manifest(self, artifact_id: str) -> dict[str, object] | None:
        ...

    def file_entry(self, artifact_id: str, filename: str) -> dict[str, object] | None:
        ...

    def resolve_file(self, artifact_id: str, filename: str) -> Path | None:
        ...


class NullForensicsStore:
    """The store a runtime gets when no forensics backend was injected.

    It answers honestly instead of pretending: nothing is stored, and every
    caller sees that the feature is unavailable rather than an empty history
    that looks like "no memory shell was ever found".
    """

    @property
    def available(self) -> bool:
        return False

    @property
    def root(self) -> Path:
        return Path("")

    def begin(self, **_kwargs) -> ForensicsPlan:
        raise ProbeError(REASON_FORENSICS_STORE_UNAVAILABLE)

    def save_run(self, *_args, **_kwargs) -> dict[str, object]:
        return {}

    def discard(self, _plan: ForensicsPlan) -> bool:
        return False

    def index(self, *, limit: int = 0) -> list[dict[str, object]]:
        return []

    def get(self, _artifact_id: str) -> dict[str, object] | None:
        return None

    def find_component(self, **_kwargs) -> dict[str, object] | None:
        return None

    def record_remediation(self, _artifact_id: str, **_kwargs) -> dict[str, object] | None:
        return None

    def read_manifest(self, _artifact_id: str) -> dict[str, object] | None:
        return None

    def file_entry(self, _artifact_id: str, _filename: str) -> dict[str, object] | None:
        return None

    def resolve_file(self, _artifact_id: str, _filename: str) -> Path | None:
        return None
