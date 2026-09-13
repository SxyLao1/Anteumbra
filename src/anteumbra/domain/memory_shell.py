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

from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol, Sequence

PROBE_MARKER = "ANTEUMBRA-MEMORY-SHELL-PROBE"
PROBE_VERSION = "1.0.0"


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
