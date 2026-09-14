# -*- coding: utf-8 -*-
"""On-disk storage for memory-shell forensics artifacts.

Detection is a point-in-time answer; forensics has to survive a restart.  One
run produces one directory and one index entry:

    <data_dir>/forensics/<site_id>/<UTC timestamp>-<kind>-<slug>/
        manifest.json          what the probe reported about the component
        class-<name>.class     the class bytes, when they could be resolved
        heap.hprof             the heap dump, when one was requested

    <data_dir>/forensics/index.json
        every run, newest first, bounded to the configured history

Design rules, all of them about not lying to the operator:

* the index is written atomically (temp file + ``os.replace``), so a crash
  during a write can never leave a half-parsed index behind;
* an entry describes what is *actually* on disk right now: sizes are stat'ed
  and hashes are computed here, not copied from the response;
* a class whose bytes could not be obtained is recorded with the probe's
  ``class_bytes_unavailable_reason`` verbatim — the absence is data;
* a failed or unreadable index is reported, never silently reset;
* nothing outside the forensics root is ever written or removed.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import secrets
import threading
import time
from pathlib import Path
from typing import Any

from anteumbra.domain.memory_shell import (
    DEFAULT_FORENSICS_HISTORY,
    ForensicsManifest,
    ForensicsPlan,
    HeapDumpInfo,
    ProbeError,
    artifact_id_for,
    slugify,
)

logger = logging.getLogger(__name__)

INDEX_FILENAME = "index.json"
MANIFEST_FILENAME = "manifest.json"
HEAP_FILENAME = "heap.hprof"
INDEX_VERSION = 1

# Beyond this, hashing would turn a forensics run into a disk read of the whole
# dump for no analyst benefit; the probe's own hash is recorded instead.
DEFAULT_MAX_HASH_BYTES = 512 * 1024 * 1024

# Remediation history is short by nature (a component is removed once), but a
# refused attempt is repeated whenever an operator retries, so it is bounded.
MAX_REMEDIATION_HISTORY = 50


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _iso(epoch: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch))


class MemoryShellForensicsStore:
    """Files plus one index; the only writer of both."""

    def __init__(
        self,
        root: str | Path,
        *,
        history_limit: int = DEFAULT_FORENSICS_HISTORY,
        max_hash_bytes: int = DEFAULT_MAX_HASH_BYTES,
        clock: Any = time.time,
        log: logging.Logger | None = None,
    ) -> None:
        self._root = Path(root)
        self._history_limit = max(int(history_limit), 1)
        self._max_hash_bytes = max(int(max_hash_bytes), 0)
        self._clock = clock
        self._logger = log or logger
        self._lock = threading.RLock()
        self._load_error = ""

    # ── configuration / introspection ───────────────────────────────
    @property
    def available(self) -> bool:
        return True

    @property
    def root(self) -> Path:
        return self._root

    @property
    def index_path(self) -> Path:
        return self._root / INDEX_FILENAME

    @property
    def history_limit(self) -> int:
        return self._history_limit

    def set_history_limit(self, limit: int) -> None:
        """Follow the configured history size without rebuilding the store."""
        with self._lock:
            self._history_limit = max(int(limit), 1)

    @property
    def load_error(self) -> str:
        """Why the previous index could not be read, if it could not."""
        return self._load_error

    # ── artifact lifecycle ──────────────────────────────────────────
    def begin(self, *, site_id: str, kind: str, name: str, created_at: float) -> ForensicsPlan:
        """Create the artifact directory and return where everything goes.

        The directory must exist before the probe request: a heap dump is
        written by the target JVM, and ``dumpHeap`` cannot create a directory.
        """
        with self._lock:
            site_dir = self._root / slugify(site_id, fallback="site", limit=64)
            artifact_id = self._unique_id(site_dir, kind, name, created_at)
            directory = site_dir / artifact_id
            try:
                directory.mkdir(parents=True, exist_ok=True)
            except OSError as exc:
                raise ProbeError(f"cannot create forensics directory {directory}: {exc}") from exc
            return ForensicsPlan(
                artifact_id=artifact_id,
                site_id=site_id,
                directory=directory,
                manifest_path=directory / MANIFEST_FILENAME,
                # The class file name is only known once the probe answers with
                # the real class name; the service writes it through save_run().
                class_path=None,
                heap_path=directory / HEAP_FILENAME,
            )

    def discard(self, plan: ForensicsPlan) -> bool:
        """Remove an artifact directory that never got a manifest.

        Only a directory this store created and that is still completely empty is
        removed.  Anything else - a heap dump the target JVM already wrote, a
        partial manifest - is left alone, because evidence that exists is worth
        more than a tidy directory.
        """
        directory = Path(plan.directory)
        with self._lock:
            if not self._is_inside_root(directory):
                return False
            if not directory.is_dir():
                return False
            if (directory / MANIFEST_FILENAME).exists():
                return False
            try:
                if any(directory.iterdir()):
                    return False
                directory.rmdir()
            except OSError as exc:  # pragma: no cover - defensive
                self._logger.warning("cannot discard forensics directory %s: %s", directory, exc)
                return False
            return True

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
        """Write the manifest, index the run, and describe what is on disk."""
        directory = Path(plan.directory)
        with self._lock:
            if not self._is_inside_root(directory):
                raise ProbeError(f"refusing to write forensics outside the root: {directory}")
            try:
                directory.mkdir(parents=True, exist_ok=True)
            except OSError as exc:
                raise ProbeError(f"cannot create forensics directory {directory}: {exc}") from exc

            class_file_name = ""
            if class_bytes:
                class_file_name = self._class_file_name(class_name)
                target = directory / class_file_name
                try:
                    self._atomic_write_bytes(target, class_bytes)
                except OSError as exc:
                    raise ProbeError(f"cannot write class bytes to {target}: {exc}") from exc

            payload = manifest.as_dict()
            payload.update(
                {
                    "artifact_id": plan.artifact_id,
                    "site_id": plan.site_id,
                    "site_name": site_name,
                    "trigger": trigger,
                    "triggered_by": triggered_by,
                    "class_bytes_available": bool(class_bytes),
                    "class_bytes_file": class_file_name,
                    "class_bytes_unavailable_reason": class_bytes_unavailable_reason,
                    "heap": heap.as_dict() if heap else None,
                    "heap_error": heap_error,
                    "heap_live": bool(live),
                    "report_error": report_error,
                }
            )
            try:
                self._atomic_write_json(plan.manifest_path, payload)
            except OSError as exc:
                raise ProbeError(f"cannot write manifest {plan.manifest_path}: {exc}") from exc

            # A reported hash is trusted only for a file too large to hash here:
            # for a heap dump that is the difference between indexing a run and
            # reading gigabytes twice.
            reported: dict[str, str] = {}
            if heap is not None and heap.sha256:
                reported[HEAP_FILENAME] = heap.sha256

            files = [
                self._file_entry(
                    path,
                    directory=directory,
                    reported_sha256=reported.get(path.name, ""),
                )
                for path in sorted(directory.iterdir())
                if path.is_file()
            ]
            entry: dict[str, object] = {
                "artifact_id": plan.artifact_id,
                "site_id": plan.site_id,
                "site_name": site_name,
                "created_at": self._clock(),
                "created_at_iso": _iso(self._clock()),
                "trigger": trigger,
                "triggered_by": triggered_by,
                "kind": manifest.kind,
                "name": manifest.name,
                "class_name": class_name or manifest.class_name,
                "on_disk": bool(on_disk),
                "directory": self._relative(directory),
                "manifest_file": MANIFEST_FILENAME,
                "class_bytes_available": bool(class_bytes),
                "class_bytes_file": class_file_name,
                "class_bytes_unavailable_reason": class_bytes_unavailable_reason,
                "heap": heap.as_dict() if heap else None,
                "heap_error": heap_error,
                "heap_live": bool(live),
                "report_error": report_error,
                "files": files,
                "bytes": sum(int(item.get("bytes") or 0) for item in files),
                "remediations": [],
            }
            self._append(entry)
            return entry

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
        """Append one remediation attempt to the artifact's history."""
        with self._lock:
            runs = self._read_index()
            for entry in runs:
                if str(entry.get("artifact_id") or "") != artifact_id:
                    continue
                history = entry.get("remediations")
                if not isinstance(history, list):
                    history = []
                history.insert(
                    0,
                    {
                        "remediated_at": remediated_at,
                        "remediated_at_iso": _iso(remediated_at),
                        "result": result,
                        "removed": bool(removed),
                        "reason": reason,
                        "operator": operator,
                        "acknowledge_no_forensics": bool(acknowledge_no_forensics),
                        "force": bool(force),
                    },
                )
                entry["remediations"] = history[:MAX_REMEDIATION_HISTORY]
                self._write_index(runs)
                return dict(entry)
            return None

    # ── reads ───────────────────────────────────────────────────────
    def index(self, *, limit: int = 0) -> list[dict[str, object]]:
        with self._lock:
            runs = self._read_index()
        if limit > 0:
            return runs[:limit]
        return runs

    def get(self, artifact_id: str) -> dict[str, object] | None:
        if not artifact_id:
            return None
        for entry in self.index():
            if str(entry.get("artifact_id") or "") == artifact_id:
                return entry
        return None

    def find_component(
        self, *, site_id: str, kind: str, name: str
    ) -> dict[str, object] | None:
        """Newest artifact for exactly this component, or None.

        The match is on site + kind + name, so a remediation can only ever be
        justified by forensics taken from the component it is about to remove.
        """
        if not name:
            return None
        for entry in self.index():
            if str(entry.get("site_id") or "") != site_id:
                continue
            if str(entry.get("kind") or "") != kind:
                continue
            if str(entry.get("name") or "") != name:
                continue
            return entry
        return None

    def read_manifest(self, artifact_id: str) -> dict[str, object] | None:
        entry = self.get(artifact_id)
        if entry is None:
            return None
        path = self._entry_directory(entry) / MANIFEST_FILENAME
        if not path.is_file():
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            self._logger.warning("forensics manifest unreadable: %s", path)
            return None
        return data if isinstance(data, dict) else None

    def file_entry(self, artifact_id: str, filename: str) -> dict[str, object] | None:
        entry = self.get(artifact_id)
        if entry is None:
            return None
        for item in entry.get("files") or []:
            if isinstance(item, dict) and str(item.get("name") or "") == filename:
                return item
        return None

    def resolve_file(self, artifact_id: str, filename: str) -> Path | None:
        """Absolute path of one indexed artifact file, or None."""
        if not filename or filename != Path(filename).name:
            return None
        entry = self.get(artifact_id)
        if entry is None or self.file_entry(artifact_id, filename) is None:
            return None
        directory = self._entry_directory(entry)
        path = directory / filename
        if not path.is_file() or not self._is_inside_root(path):
            return None
        return path

    # ── internals ───────────────────────────────────────────────────
    def _class_file_name(self, class_name: str) -> str:
        """``class-<SimpleName>.class``: readable, and safe on Windows too.

        The case is preserved (``class-WsFilter.class`` reads better than a
        lower-cased slug), and anything that is not a filename-safe character
        becomes ``-``, so a hostile class name can never escape the directory.
        """
        simple = (class_name or "").rsplit(".", 1)[-1]
        safe = "".join(
            char if (char.isalnum() or char in "._-$") else "-" for char in simple
        ).strip("-._")
        return f"class-{safe[:64] or 'component'}.class"

    def _entry_directory(self, entry: dict[str, object]) -> Path:
        relative = str(entry.get("directory") or "")
        return self._root / relative if relative else self._root

    def _relative(self, path: Path) -> str:
        try:
            return path.relative_to(self._root).as_posix()
        except ValueError:  # pragma: no cover - guarded by _is_inside_root
            return path.as_posix()

    def _is_inside_root(self, path: Path) -> bool:
        try:
            Path(path).resolve().relative_to(self._root.resolve())
        except (ValueError, OSError):
            return False
        return True

    def _unique_id(self, site_dir: Path, kind: str, name: str, created_at: float) -> str:
        base = artifact_id_for(created_at, kind, name)
        candidate = base
        for index in range(2, 64):
            if not (site_dir / candidate).exists():
                break
            candidate = f"{base}-{index}"
        return candidate

    def _file_entry(
        self, path: Path, *, directory: Path, reported_sha256: str = ""
    ) -> dict[str, object]:
        try:
            size = path.stat().st_size
        except OSError:
            size = 0
        item: dict[str, object] = {
            "name": path.name,
            "bytes": size,
            "sha256": "",
            "sha256_source": "unavailable",
        }
        if size and (self._max_hash_bytes == 0 or size <= self._max_hash_bytes):
            try:
                item["sha256"] = _sha256(path)
                item["sha256_source"] = "computed"
            except OSError as exc:  # pragma: no cover - unreadable artifact
                item["sha256_note"] = f"cannot hash: {exc}"
        elif size and reported_sha256:
            item["sha256"] = reported_sha256
            item["sha256_source"] = "probe"
            item["sha256_note"] = (
                f"hashed by the probe: {size} bytes exceeds the "
                f"{self._max_hash_bytes} byte hashing limit"
            )
        elif size:
            item["sha256_note"] = (
                f"not hashed: {size} bytes exceeds the {self._max_hash_bytes} byte hashing limit"
            )
        item["relative_path"] = f"{directory.name}/{path.name}"
        return item

    def _read_index(self) -> list[dict[str, object]]:
        path = self.index_path
        if not path.is_file():
            return []
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            self._load_error = str(exc)
            self._logger.error("forensics index is unreadable (%s): %s", path, exc)
            return []
        runs = data.get("runs") if isinstance(data, dict) else None
        if not isinstance(runs, list):
            self._load_error = "index has no run list"
            return []
        self._load_error = ""
        return [item for item in runs if isinstance(item, dict)]

    def _append(self, entry: dict[str, object]) -> None:
        runs = [item for item in self._read_index()]
        runs.insert(0, entry)
        self._write_index(runs)

    def _write_index(self, runs: list[dict[str, object]]) -> None:
        bounded = runs[: self._history_limit]
        payload = {
            "version": INDEX_VERSION,
            "updated_at": self._clock(),
            "updated_at_iso": _iso(self._clock()),
            "history_limit": self._history_limit,
            "run_count": len(bounded),
            "runs": bounded,
        }
        try:
            self._root.mkdir(parents=True, exist_ok=True)
            self._atomic_write_json(self.index_path, payload)
        except OSError as exc:
            raise ProbeError(f"cannot write forensics index {self.index_path}: {exc}") from exc

    def _atomic_write_json(self, path: Path, payload: object) -> None:
        self._atomic_write_bytes(
            path, json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
        )

    def _atomic_write_bytes(self, path: Path, payload: bytes) -> None:
        """Write, fsync and rename: a reader sees the old or the new file."""
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(f".{path.name}.{secrets.token_hex(6)}.tmp")
        try:
            with temporary.open("wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, path)
        finally:
            if temporary.exists():
                try:
                    temporary.unlink()
                except OSError:  # pragma: no cover - best effort
                    pass
