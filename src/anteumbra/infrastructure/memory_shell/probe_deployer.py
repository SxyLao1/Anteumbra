# -*- coding: utf-8 -*-
"""Deploy, read and remove the memory-shell probe.

The probe is a JSP file that asks the servlet container what it has registered
in memory. Deploying one means writing a file into a live web root, which is
exactly why this module is small, explicit and defensive:

* the directory and file names are random, so the probe cannot be guessed;
* the probe answers only when its per-run token is presented;
* the artifact is registered as internal before the first byte is written;
* cleanup removes only the file it wrote, and only while that file still
  carries the probe marker, so a replaced file is never destroyed.
"""

from __future__ import annotations

import json
import logging
import secrets
import shutil
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Callable, Mapping

from anteumbra.domain.memory_shell import (
    ACTION_PROBE,
    PROBE_ACTIONS,
    PROBE_MARKER,
    PROBE_VERSION,
    InternalArtifactRegistryPort,
    MemoryShellEntry,
    ProbeArtifact,
    ProbeError,
    ProbeReport,
    SiteTarget,
    entry_from_payload,
)
from anteumbra.infrastructure.memory_shell.forensics_store import (
    MemoryShellForensicsStore,
)

logger = logging.getLogger(__name__)

TOKEN_PLACEHOLDER = "{{PROBE_TOKEN}}"
PROBE_FILENAME_SUFFIX = ".jsp"
DEFAULT_DIRECTORY_PREFIX = "mb-"
PROBE_USER_AGENT = f"Anteumbra-MemoryShellProbe/{PROBE_VERSION}"

# A probe lives for a couple of seconds, but the file monitor and the scan
# queue process its create/modify events a moment later. Dropping the internal
# registration at cleanup therefore made Anteumbra treat its own (already
# deleted) probe as an unknown file, which surfaced as FileNotFoundError noise
# in the live log. The registration now outlives the deletion by this grace
# period; the path is random per run, so nothing else can inherit it.
DEFAULT_CLEANUP_GRACE_SECONDS = 60.0


def default_template_path() -> Path:
    return Path(__file__).resolve().parent / "assets" / "probe.jsp"


def load_probe_template(path: Path | None = None) -> str:
    template_path = path or default_template_path()
    try:
        template = template_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ProbeError(f"probe template unavailable: {template_path} ({exc})") from exc
    if TOKEN_PLACEHOLDER not in template:
        raise ProbeError(f"probe template is missing {TOKEN_PLACEHOLDER}")
    if PROBE_MARKER not in template:
        raise ProbeError("probe template is missing its marker")
    return template


def render_probe(template: str, token: str) -> str:
    return template.replace(TOKEN_PLACEHOLDER, token)


def fetch_url(url: str, timeout: float) -> bytes:
    """Default probe reader: one plain GET with a hard timeout."""
    request = urllib.request.Request(url, headers={"User-Agent": PROBE_USER_AGENT})
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
        return response.read()


class MemoryShellProbeDeployer:
    """Filesystem + HTTP mechanics for one probe run."""

    def __init__(
        self,
        *,
        artifacts: InternalArtifactRegistryPort,
        reader: Callable[[str, float], bytes] | None = None,
        template_loader: Callable[[], str] | None = None,
        directory_prefix: str = DEFAULT_DIRECTORY_PREFIX,
        token_bytes: int = 16,
        cleanup_grace_seconds: float = DEFAULT_CLEANUP_GRACE_SECONDS,
        log: logging.Logger | None = None,
    ) -> None:
        self._artifacts = artifacts
        self._reader = reader or fetch_url
        self._template_loader = template_loader or load_probe_template
        self._directory_prefix = directory_prefix
        self._token_bytes = max(int(token_bytes), 8)
        self._cleanup_grace_seconds = max(float(cleanup_grace_seconds), 0.0)
        self._logger = log or logger
        self._template: str | None = None

    # ── artifact lifecycle ──────────────────────────────────────────
    def forensics_store_for(self, root: str | Path, **options) -> "MemoryShellForensicsStore":
        """Build the forensics store that belongs next to this deployer's probes.

        The deployer is the one infrastructure collaborator the probe service is
        handed, and the application layer may not import infrastructure, so this
        is where a service asks for the store that persists what a probe finds.
        The caller supplies the data directory; nothing is created until the
        store writes its first artifact.
        """
        return MemoryShellForensicsStore(root, **options)

    def deploy(self, target: SiteTarget, *, ttl: float, token: str | None = None) -> ProbeArtifact:
        """Create the random probe directory and write the probe into it."""
        root = Path(target.deployment_root)
        if not root.is_dir():
            raise ProbeError(f"site root is not a directory: {root}")

        token = token or secrets.token_hex(self._token_bytes)
        directory = self._unique_directory(root)
        try:
            directory.mkdir(mode=0o755)
        except OSError as exc:
            raise ProbeError(f"cannot create probe directory under {root}: {exc}") from exc

        file_path = directory / (secrets.token_hex(6) + PROBE_FILENAME_SUFFIX)
        artifact = ProbeArtifact(
            site_id=target.site_id,
            site_root=root,
            directory=directory,
            file_path=file_path,
            token=token,
            url=target.url_for("/" + file_path.relative_to(root).as_posix()) + f"?t={token}",
            created_at=time.time(),
        )

        # Register before writing: the create event must already be internal.
        self._artifacts.register(path=file_path, url_fragment=artifact.relative_url_path, ttl=ttl)
        self._artifacts.register(path=directory, url_fragment=artifact.relative_url_path, ttl=ttl)

        try:
            file_path.write_text(render_probe(self._template_text(), token), encoding="utf-8")
        except OSError as exc:
            self.cleanup(artifact)
            raise ProbeError(f"cannot write probe file {file_path}: {exc}") from exc
        self._logger.debug("memory-shell probe deployed at %s", file_path)
        return artifact

    # ── read ────────────────────────────────────────────────────────
    def read(self, artifact: ProbeArtifact, *, timeout: float) -> bytes:
        """Read the default action (``probe``): the read-only report."""
        return self.read_action(artifact, action=ACTION_PROBE, timeout=timeout)

    def read_action(
        self,
        artifact: ProbeArtifact,
        *,
        action: str = ACTION_PROBE,
        params: Mapping[str, object] | None = None,
        timeout: float,
    ) -> bytes:
        """Read one token-gated action, with its parameters in the query string.

        The per-run token is already part of the artifact URL; everything else is
        appended here.  Parameters are URL-encoded, and the action name must be
        one of the three the probe implements, so a caller cannot smuggle an
        unknown verb into a live web server.
        """
        if action not in PROBE_ACTIONS:
            raise ProbeError(f"unknown probe action: {action}")
        url = self.action_url(artifact, action=action, params=params)
        try:
            payload = self._reader(url, timeout)
        except urllib.error.HTTPError as exc:
            raise ProbeError(f"probe HTTP {exc.code} at {url}") from exc
        except Exception as exc:  # noqa: BLE001 - surfaced to the caller as a failure
            raise ProbeError(f"probe request failed: {exc}") from exc
        if not payload:
            raise ProbeError("probe returned an empty body")
        return payload

    def action_url(
        self,
        artifact: ProbeArtifact,
        *,
        action: str = ACTION_PROBE,
        params: Mapping[str, object] | None = None,
    ) -> str:
        """The exact URL one action request goes to (token always included)."""
        query: list[tuple[str, str]] = [("action", action)]
        for key, value in (params or {}).items():
            if value is None:
                continue
            if isinstance(value, bool):
                query.append((str(key), "1" if value else "0"))
            else:
                query.append((str(key), str(value)))
        separator = "&" if "?" in artifact.url else "?"
        return artifact.url + separator + urllib.parse.urlencode(query)

    def parse(self, payload: bytes, artifact: ProbeArtifact) -> ProbeReport:
        data = self.parse_action(payload, artifact)

        raw_entries = data.get("entries")
        entries: list[MemoryShellEntry] = []
        if isinstance(raw_entries, list):
            for item in raw_entries:
                if isinstance(item, dict):
                    entries.append(entry_from_payload(item))

        container = data.get("container") or ()
        return ProbeReport(
            site_id=artifact.site_id,
            url=artifact.url,
            fetched_at=time.time(),
            probe_version=str(data.get("version") or PROBE_VERSION),
            context_path=str(data.get("context_path") or ""),
            container=tuple(str(item) for item in container) if isinstance(container, list) else (),
            entries=tuple(entries),
            error=str(data["error"]) if data.get("error") else None,
            duration_ms=int(data.get("duration_ms") or 0),
            raw_bytes=len(payload),
        )

    def parse_action(self, payload: bytes, artifact: ProbeArtifact) -> dict[str, object]:
        """Decode one action response, rejecting anything that is not ours.

        Every action answers with the same envelope, so the marker check is the
        single gate that stops a 404 page, a WAF page or another application's
        JSON from being read as a probe result.
        """
        try:
            data = json.loads(payload.decode("utf-8", "replace"))
        except ValueError as exc:
            raise ProbeError(f"probe returned non-JSON output ({len(payload)} bytes)") from exc
        if not isinstance(data, dict):
            raise ProbeError("probe returned JSON that is not an object")
        if data.get("probe") != PROBE_MARKER:
            raise ProbeError("probe response does not carry the expected marker")
        return data

    # ── cleanup ─────────────────────────────────────────────────────
    def cleanup(self, artifact: ProbeArtifact) -> None:
        """Remove the probe file and its directory. Never touches anything else.

        If the file no longer carries the probe marker, somebody else's content
        is sitting at our path: that file is not ours to delete, so nothing is
        removed and the caller sees a cleanup failure. The registry entries are
        released either way, so a foreign file is never suppressed by us.
        """
        root = Path(artifact.site_root).resolve()
        directory = Path(artifact.directory)

        try:
            directory.resolve().relative_to(root)
        except (ValueError, OSError) as exc:
            raise ProbeError(f"refusing to clean up outside the site root: {directory}") from exc

        file_path = Path(artifact.file_path)
        if file_path.exists():
            try:
                content = file_path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                content = ""
            if PROBE_MARKER not in content:
                self._artifacts.release(file_path)
                self._artifacts.release(directory)
                raise ProbeError(
                    f"probe file {file_path} was replaced after deployment; "
                    "leaving it in place for review"
                )
            try:
                file_path.unlink()
            except OSError as exc:
                raise ProbeError(f"cannot remove probe file {file_path}: {exc}") from exc

        if directory.exists():
            try:
                shutil.rmtree(directory)
            except OSError as exc:
                raise ProbeError(f"cannot remove probe directory {directory}: {exc}") from exc

        # Keep the registration alive for a grace period instead of releasing it
        # immediately: the create/modify events for this very file may still be
        # sitting in the monitor queue, and by the time they are processed the
        # file is gone. Releasing here turned Anteumbra's own probe into an
        # unknown, vanished file and produced FileNotFoundError noise.
        for path in (file_path, directory):
            if self._cleanup_grace_seconds > 0:
                self._artifacts.register(
                    path=path,
                    url_fragment=artifact.relative_url_path,
                    ttl=self._cleanup_grace_seconds,
                )
            else:
                self._artifacts.release(path)
        self._logger.debug("memory-shell probe removed from %s", directory)

    # ── internals ───────────────────────────────────────────────────
    def _template_text(self) -> str:
        if self._template is None:
            self._template = self._template_loader()
        return self._template

    def _unique_directory(self, root: Path) -> Path:
        for _ in range(16):
            candidate = root / (self._directory_prefix + secrets.token_hex(8))
            if not candidate.exists():
                return candidate
        raise ProbeError("could not allocate a unique probe directory")
