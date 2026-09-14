# -*- coding: utf-8 -*-
"""Memory-shell probe orchestration: detection, forensics (取证) and remediation (处置).

One probe run is a small, bounded conversation with the target container:

    pick the site -> deploy a random probe -> read it over HTTP
      -> parse what the container has in memory -> delete probe and directory

The same probe answers three token-gated actions, and this service owns all
three:

* ``probe``  - the read-only report the panel shows, with an alert when
  something suspicious is registered in memory;
* ``dump``   - forensics: one component's manifest, its class bytes when they
  really exist, and an optional heap dump, stored under ``<data_dir>/forensics``
  so the evidence outlives the process;
* ``kill``   - remediation: unregister exactly one component, refusing unless it
  is still the class Anteumbra recorded and is not a deployed file.

The service owns everything that can go wrong around those: configuration,
cooldown, single-flight per site, history for the admin UI, the alert on
detection and the event trail for remediation.

Cleanup is not optional. The probe is removed in a ``finally`` block, and a
failed cleanup is reported as its own field rather than being hidden, because a
leftover probe is a security problem in the very site the defender protects.
The same rule applies to forensics: a failure or a refusal is a field in the
outcome, never a silent empty result and never a fabricated artifact.
"""

from __future__ import annotations

import base64
import binascii
import logging
import threading
import time
from collections import deque
from dataclasses import replace
from pathlib import Path
from typing import Any, Callable, Mapping

from anteumbra.domain.memory_shell import (
    ACTION_DUMP,
    ACTION_KILL,
    ACTION_KINDS,
    DEFAULT_FORENSICS_HISTORY,
    DEFAULT_FORENSICS_MAX_DUMP_MB,
    DEFAULT_FORENSICS_TIMEOUT_SECONDS,
    MAX_FORENSICS_HISTORY,
    MAX_FORENSICS_MAX_DUMP_MB,
    REASON_ALREADY_RUNNING,
    REASON_FORENSICS_DISABLED,
    REASON_FORENSICS_REQUIRED,
    REASON_FORENSICS_STORE_UNAVAILABLE,
    REASON_INVALID_COMPONENT,
    REASON_NO_RECORDED_CLASS,
    REASON_PROBE_DISABLED,
    REASON_UNKNOWN_KIND,
    REASON_UNKNOWN_SITE,
    ComponentRef,
    ForensicsManifest,
    ForensicsOutcome,
    ForensicsStorePort,
    InternalArtifactRegistryPort,
    ProbeError,
    ProbeOutcome,
    RemediationOutcome,
    SiteTarget,
    action_failure_reason,
    component_from_payload,
    entries_from_payload,
    heap_from_payload,
    manifest_from_payload,
)

logger = logging.getLogger(__name__)

DEFAULT_CONFIG: dict[str, Any] = {
    "enabled": True,
    "auto_probe_on_detection": True,
    "trigger_extensions": [".jsp", ".jspx", ".jspf", ".jsw", ".jsv"],
    "site_ids": [],
    "cooldown_seconds": 300,
    "http_timeout_seconds": 8,
    "artifact_ttl_seconds": 120,
    "directory_prefix": "mb-",
    "history_size": 50,
    "alert_on_suspects": True,
    "host": "127.0.0.1",
    "scheme": "http",
    # site_id -> subdirectory of the site root that the web server serves as a
    # context (for Tomcat: "webapps/<context>"). Required when the monitored
    # path is a container root instead of a document root, because a JSP next
    # to the contexts belongs to no deployed context and answers 404.
    "probe_base_dirs": {},
    # site_id -> URL prefix, for a site whose path is a subdirectory of the
    # document root rather than the root itself.
    "url_prefixes": {},
    # ── forensics (取证) ────────────────────────────────────────────
    # Artifacts are files plus one index under <data_dir>/forensics; there is
    # deliberately no SQLite table for them.
    "forensics_enabled": True,
    "heap_dump_enabled": True,
    "forensics_history": DEFAULT_FORENSICS_HISTORY,
    "forensics_max_dump_mb": DEFAULT_FORENSICS_MAX_DUMP_MB,
    # A heap dump answers slowly; this budget covers dump and kill requests
    # only, never the plain probe.
    "forensics_timeout_seconds": DEFAULT_FORENSICS_TIMEOUT_SECONDS,
}

CONFIG_SECTION = "memory_shell_probe"


def _as_bool(value: object, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    if value is None:
        return default
    return bool(value)


def _as_float(value: object, default: float) -> float:
    try:
        return float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default


def _as_list(value: object) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    if isinstance(value, (list, tuple, set)):
        return [str(item).strip() for item in value if str(item).strip()]
    return []


def _as_int(value: object, default: int, *, minimum: int, maximum: int) -> int:
    """Validate a numeric config value by clamping it into its real range."""
    try:
        number = int(float(value))  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default
    return max(minimum, min(maximum, number))


class MemoryShellService:
    """Deploy, read and remove memory-shell probes; keep the results for the UI."""

    def __init__(
        self,
        *,
        config_provider: Any,
        deployer: Any,  # injected by the composition root; not this layer's type
        artifacts: InternalArtifactRegistryPort,
        notifier: Any | None = None,
        publisher: Any | None = None,
        forensics: ForensicsStorePort | None = None,
        clock: Callable[[], float] = time.time,
        log: logging.Logger | None = None,
    ) -> None:
        self._config_provider = config_provider
        self._deployer = deployer
        self._artifacts = artifacts
        self._notifier = notifier
        self._publisher = publisher
        self._clock = clock
        self._logger = log or logger

        # The forensics store is infrastructure. When the composition root does
        # not inject one, the service asks the deployer it already holds for a
        # store rooted at the configured data directory; without a configured
        # data directory the feature reports itself as unavailable instead of
        # guessing a location, which is the difference between "no evidence" and
        # "no evidence was ever collected".
        self._forensics = forensics
        self._forensics_resolved = forensics is not None
        self._forensics_error = "" if forensics is not None else REASON_FORENSICS_STORE_UNAVAILABLE

        self._lock = threading.RLock()
        self._site_locks: dict[str, threading.Lock] = {}
        self._history: deque[ProbeOutcome] = deque(maxlen=200)
        self._latest: dict[str, ProbeOutcome] = {}
        self._last_run: dict[str, float] = {}
        self._running: set[str] = set()
        self._runs = 0
        self._failures = 0

        self._forensics_history: deque[ForensicsOutcome] = deque(maxlen=100)
        self._latest_forensics: dict[str, ForensicsOutcome] = {}
        self._forensics_running: set[str] = set()
        self._latest_remediation: dict[str, RemediationOutcome] = {}

    # ── configuration ───────────────────────────────────────────────
    def bind_publisher(self, publisher: Any | None) -> None:
        with self._lock:
            self._publisher = publisher

    def bind_forensics(self, forensics: ForensicsStorePort | None) -> None:
        """Attach (or detach) the forensics store after construction."""
        with self._lock:
            self._forensics = forensics
            self._forensics_resolved = True
            self._forensics_error = (
                "" if forensics is not None else REASON_FORENSICS_STORE_UNAVAILABLE
            )

    @property
    def forensics_root(self) -> Path | None:
        """``<data_dir>/forensics``, or None when no data directory is configured."""
        try:
            paths = self._config_provider.get().get("paths", {})
        except Exception:  # pragma: no cover - config provider failure
            return None
        if not isinstance(paths, Mapping):
            return None
        configured = str(paths.get("data_dir") or "").strip()
        if not configured:
            return None
        return (Path(configured).expanduser() / "forensics").resolve()

    def _default_forensics(self) -> ForensicsStorePort | None:
        """Ask the deployer for a store at the configured data directory."""
        root = self.forensics_root
        if root is None:
            return None
        factory = getattr(self._deployer, "forensics_store_for", None)
        if not callable(factory):
            return None
        try:
            return factory(root)
        except Exception as exc:  # noqa: BLE001 - the feature reports itself unavailable
            self._logger.error("cannot create the forensics store at %s: %s", root, exc)
            return None

    @property
    def forensics_store(self) -> ForensicsStorePort | None:
        with self._lock:
            if not self._forensics_resolved:
                self._forensics = self._default_forensics()
                self._forensics_resolved = True
                self._forensics_error = (
                    "" if self._forensics is not None else REASON_FORENSICS_STORE_UNAVAILABLE
                )
            return self._forensics

    @property
    def config(self) -> dict[str, Any]:
        merged = dict(DEFAULT_CONFIG)
        try:
            plugin_config = self._config_provider.get().get("plugins", {})
            section = plugin_config.get(CONFIG_SECTION, {})
            if isinstance(section, Mapping):
                merged.update(section)
        except Exception:  # pragma: no cover - config provider failure
            self._logger.debug("memory-shell config unavailable, using defaults", exc_info=True)
        return merged

    @property
    def enabled(self) -> bool:
        return _as_bool(self.config.get("enabled"), True)

    @property
    def history_size(self) -> int:
        return max(int(_as_float(self.config.get("history_size"), 50)), 1)

    @property
    def forensics_enabled(self) -> bool:
        return _as_bool(self.config.get("forensics_enabled"), True)

    @property
    def heap_dump_enabled(self) -> bool:
        return _as_bool(self.config.get("heap_dump_enabled"), True)

    @property
    def forensics_history(self) -> int:
        """How many forensics runs the index keeps; clamped to a sane range."""
        return _as_int(
            self.config.get("forensics_history"),
            DEFAULT_FORENSICS_HISTORY,
            minimum=1,
            maximum=MAX_FORENSICS_HISTORY,
        )

    @property
    def forensics_max_dump_mb(self) -> int:
        """Upper bound the probe checks free space against; 0 means no check."""
        return _as_int(
            self.config.get("forensics_max_dump_mb"),
            DEFAULT_FORENSICS_MAX_DUMP_MB,
            minimum=0,
            maximum=MAX_FORENSICS_MAX_DUMP_MB,
        )

    @property
    def forensics_timeout(self) -> float:
        value = _as_float(
            self.config.get("forensics_timeout_seconds"), DEFAULT_FORENSICS_TIMEOUT_SECONDS
        )
        return max(value, _as_float(self.config.get("http_timeout_seconds"), 8.0))

    # ── sites ───────────────────────────────────────────────────────
    def sites(self) -> list[SiteTarget]:
        host = str(self.config.get("host") or "127.0.0.1")
        scheme = str(self.config.get("scheme") or "http")
        allowed = set(_as_list(self.config.get("site_ids")))
        targets: list[SiteTarget] = []
        try:
            websites = self._config_provider.get_enabled_websites()
        except Exception:  # pragma: no cover - config provider failure
            self._logger.debug("website list unavailable", exc_info=True)
            return []
        for website in websites:
            site_id = str(getattr(website, "site_id", "") or getattr(website, "name", ""))
            if allowed and site_id not in allowed:
                continue
            root = Path(getattr(website, "path"))
            if not root.is_dir():
                continue
            probe_root, url_prefix, base_note = self._resolve_probe_location(root, site_id)
            targets.append(
                SiteTarget(
                    site_id=site_id,
                    name=str(getattr(website, "name", site_id)),
                    root=root,
                    base_url=f"{scheme}://{host}:{int(getattr(website, 'port', 80) or 80)}",
                    port=int(getattr(website, "port", 80) or 80),
                    scheme=scheme,
                    host=host,
                    url_prefix=url_prefix,
                    probe_root=probe_root,
                    base_note=base_note,
                )
            )
        return targets

    def _resolve_probe_location(self, site_root: Path, site_id: str) -> tuple[Path, str, str]:
        """Where the probe may be written, and under which URL prefix.

        Three cases, in order: an explicit `probe_base_dirs` entry, a site root
        that is itself a document root (has `WEB-INF/web.xml`), or exactly one
        deployed context below the site root. Anything ambiguous stays at the
        site root with a note, so the failure is explained instead of silently
        404ing.
        """
        config = self.config
        base_dirs = config.get("probe_base_dirs")
        prefixes = config.get("url_prefixes")
        explicit_base = ""
        if isinstance(base_dirs, Mapping):
            explicit_base = str(base_dirs.get(site_id, "") or "").strip().strip("/\\")
        explicit_prefix = ""
        if isinstance(prefixes, Mapping):
            explicit_prefix = str(prefixes.get(site_id, "") or "").strip()

        if explicit_base:
            candidate = (site_root / explicit_base).resolve()
            prefix = explicit_prefix or "/" + explicit_base.replace("\\", "/")
            return candidate, prefix, f"configured probe_base_dirs={explicit_base!r}"

        if (site_root / "WEB-INF" / "web.xml").is_file():
            return site_root, explicit_prefix, "site root is a deployed context"

        contexts: list[Path] = []
        try:
            for entry in sorted(site_root.iterdir()):
                if entry.is_dir() and (entry / "WEB-INF" / "web.xml").is_file():
                    contexts.append(entry)
        except OSError:  # pragma: no cover - unreadable root
            contexts = []

        if len(contexts) == 1:
            name = contexts[0].name
            return contexts[0], explicit_prefix or f"/{name}", f"single deployed context {name!r}"

        if contexts:
            return (
                site_root,
                explicit_prefix,
                f"{len(contexts)} deployed contexts found; set probe_base_dirs for this site",
            )
        if explicit_prefix:
            return site_root, explicit_prefix, "configured url_prefixes"
        return site_root, "", "no deployed context found; probe may not be reachable"

    def target(self, site_id: str) -> SiteTarget | None:
        for target in self.sites():
            if target.site_id == site_id:
                return target
        return None

    # ── automatic trigger ───────────────────────────────────────────
    def trigger_extensions(self) -> set[str]:
        values = _as_list(self.config.get("trigger_extensions"))
        if not values:
            values = list(DEFAULT_CONFIG["trigger_extensions"])
        return {value.lower() for value in values}

    def should_auto_probe(self, file_path: str | Path, site_id: str | None = None) -> bool:
        """True when an automatic probe is warranted for this detected file."""
        config = self.config
        if not _as_bool(config.get("enabled"), True):
            return False
        if not _as_bool(config.get("auto_probe_on_detection"), True):
            return False
        path = Path(file_path)
        if path.suffix.lower() not in self.trigger_extensions():
            return False
        candidates = [site for site in self.sites() if site_id in (None, "", site.site_id)]
        if not candidates:
            return False
        try:
            resolved = path.resolve()
        except OSError:  # pragma: no cover - defensive
            return False
        for site in candidates:
            try:
                resolved.relative_to(site.root.resolve())
            except (ValueError, OSError):
                continue
            return self._cooldown_elapsed(site.site_id)
        return False

    def handle_detection(self, payload: Mapping[str, Any]) -> None:
        """Auto-probe entry point used by the plugin on detection events."""
        file_path = str(payload.get("file_path") or "")
        site_id = str(payload.get("site_id") or "") or None
        if not file_path or not self.should_auto_probe(file_path, site_id):
            return None
        target = self._site_for_path(file_path) if not site_id else self.target(site_id)
        if target is None:
            return None
        # Never block the event dispatcher on an HTTP round trip.
        self.run_probe(target.site_id, trigger="auto", triggered_by=file_path, background=True)
        return None

    # ── the probe run ───────────────────────────────────────────────
    def run_probe(
        self,
        site_id: str,
        *,
        trigger: str = "manual",
        triggered_by: str = "",
        background: bool = False,
    ) -> ProbeOutcome | None:
        """Run one probe. Returns None when started in the background.

        ``background`` exists because a probe can take up to the HTTP timeout,
        and the event dispatcher and the web request both have tighter budgets
        than that.
        """
        if background:
            return self._start_background(site_id, trigger, triggered_by)

        started = self._clock()
        target = self.target(site_id)
        if target is None:
            return self._record(
                ProbeOutcome(
                    site_id=site_id,
                    site_name=site_id,
                    started_at=started,
                    finished_at=self._clock(),
                    failure="unknown_or_unwatchable_site",
                    trigger=trigger,
                    triggered_by=triggered_by,
                )
            )

        if not self.enabled:
            return self._record(
                ProbeOutcome(
                    site_id=target.site_id,
                    site_name=target.name,
                    started_at=started,
                    finished_at=self._clock(),
                    failure="probe_disabled",
                    trigger=trigger,
                    triggered_by=triggered_by,
                )
            )

        lock = self._site_lock(target.site_id)
        if not lock.acquire(blocking=False):
            return self._record(
                ProbeOutcome(
                    site_id=target.site_id,
                    site_name=target.name,
                    started_at=started,
                    finished_at=self._clock(),
                    failure="probe_already_running",
                    trigger=trigger,
                    triggered_by=triggered_by,
                )
            )

        try:
            with self._lock:
                self._running.add(target.site_id)
            try:
                return self._record(self._run_locked(target, started, trigger, triggered_by))
            finally:
                with self._lock:
                    self._running.discard(target.site_id)
        finally:
            lock.release()

    def _start_background(self, site_id: str, trigger: str, triggered_by: str) -> None:
        thread = threading.Thread(
            target=self.run_probe,
            args=(site_id,),
            kwargs={"trigger": trigger, "triggered_by": triggered_by},
            name=f"MemoryShellProbe-{site_id or 'unknown'}",
            daemon=True,
        )
        thread.start()
        return None

    def _run_locked(
        self,
        target: SiteTarget,
        started: float,
        trigger: str,
        triggered_by: str,
    ) -> ProbeOutcome:
        config = self.config
        timeout = _as_float(config.get("http_timeout_seconds"), 8.0)
        ttl = _as_float(config.get("artifact_ttl_seconds"), 120.0)
        artifact = None
        outcome: ProbeOutcome
        try:
            artifact = self._deployer.deploy(target, ttl=ttl)
            payload = self._deployer.read(artifact, timeout=timeout)
            report = self._deployer.parse(payload, artifact)
            outcome = ProbeOutcome(
                site_id=target.site_id,
                site_name=target.name,
                started_at=started,
                finished_at=self._clock(),
                report=report,
                trigger=trigger,
                triggered_by=triggered_by,
            )
        except ProbeError as exc:
            outcome = ProbeOutcome(
                site_id=target.site_id,
                site_name=target.name,
                started_at=started,
                finished_at=self._clock(),
                failure=str(exc),
                trigger=trigger,
                triggered_by=triggered_by,
            )
        except Exception as exc:  # noqa: BLE001 - a probe must never take the runtime down
            self._logger.exception("memory-shell probe failed for %s", target.site_id)
            outcome = ProbeOutcome(
                site_id=target.site_id,
                site_name=target.name,
                started_at=started,
                finished_at=self._clock(),
                failure=f"{type(exc).__name__}: {exc}",
                trigger=trigger,
                triggered_by=triggered_by,
            )
        finally:
            if artifact is not None:
                try:
                    self._deployer.cleanup(artifact)
                except ProbeError as exc:
                    outcome = ProbeOutcome(
                        site_id=outcome.site_id,
                        site_name=outcome.site_name,
                        started_at=outcome.started_at,
                        finished_at=self._clock(),
                        report=outcome.report,
                        failure=outcome.failure,
                        cleanup_ok=False,
                        cleanup_error=str(exc),
                        trigger=outcome.trigger,
                        triggered_by=outcome.triggered_by,
                    )
                    self._logger.error(
                        "memory-shell probe cleanup failed for %s: %s", target.site_id, exc
                    )
        self._logger.info(
            "memory-shell probe on %s (%s): %s",
            target.name,
            trigger,
            "failed: " + outcome.failure
            if outcome.failure
            else f"{len(outcome.report.entries) if outcome.report else 0} entries, "
            f"{outcome.suspect_count} suspicious",
        )
        if outcome.suspect_count:
            self._raise_alert(outcome)
        return outcome

    # ════════════════════════════════════════════════════════════════
    #  forensics (取证)
    # ════════════════════════════════════════════════════════════════
    def run_forensics(
        self,
        site_id: str,
        kind: str,
        name: str,
        *,
        trigger: str = "manual",
        triggered_by: str = "",
        background: bool = False,
        heap_live: bool = False,
        heap_path: str | Path | None = None,
    ) -> ForensicsOutcome | None:
        """Dump everything the JVM can honestly say about one component.

        The probe writes the (optional) heap dump straight into the artifact
        directory, because it runs on the same host as Anteumbra: the path handed
        to ``dumpHeap`` is an absolute path in *our* forensics tree.  Every
        failure - including a failed dump - is a field in the outcome.
        """
        if background:
            return self._start_forensics_background(
                site_id, kind, name, trigger, triggered_by, heap_live, heap_path
            )

        started = self._clock()
        target = self.target(site_id)
        if target is None:
            return self._record_forensics(
                self._forensics_failure(site_id, site_id, started, REASON_UNKNOWN_SITE,
                                        trigger, triggered_by, kind, name)
            )
        if not self.enabled:
            return self._record_forensics(
                self._forensics_failure(target.site_id, target.name, started,
                                        REASON_PROBE_DISABLED, trigger, triggered_by, kind, name)
            )
        if not self.forensics_enabled:
            return self._record_forensics(
                self._forensics_failure(target.site_id, target.name, started,
                                        REASON_FORENSICS_DISABLED, trigger, triggered_by,
                                        kind, name)
            )
        invalid = self._invalid_component(kind, name)
        if invalid:
            return self._record_forensics(
                self._forensics_failure(target.site_id, target.name, started, invalid,
                                        trigger, triggered_by, kind, name)
            )
        store = self.forensics_store
        if store is None or not getattr(store, "available", False):
            return self._record_forensics(
                self._forensics_failure(target.site_id, target.name, started,
                                        REASON_FORENSICS_STORE_UNAVAILABLE, trigger,
                                        triggered_by, kind, name)
            )

        lock = self._site_lock(target.site_id)
        if not lock.acquire(blocking=False):
            return self._record_forensics(
                self._forensics_failure(target.site_id, target.name, started, REASON_ALREADY_RUNNING,
                                        trigger, triggered_by, kind, name)
            )
        try:
            with self._lock:
                self._forensics_running.add(target.site_id)
            try:
                outcome = self._run_forensics_locked(
                    target, kind, name, started, trigger, triggered_by, heap_live, heap_path
                )
                return self._record_forensics(outcome)
            finally:
                with self._lock:
                    self._forensics_running.discard(target.site_id)
        finally:
            lock.release()

    def _start_forensics_background(
        self,
        site_id: str,
        kind: str,
        name: str,
        trigger: str,
        triggered_by: str,
        heap_live: bool,
        heap_path: str | Path | None,
    ) -> None:
        thread = threading.Thread(
            target=self.run_forensics,
            args=(site_id, kind, name),
            kwargs={
                "trigger": trigger,
                "triggered_by": triggered_by,
                "heap_live": heap_live,
                "heap_path": heap_path,
            },
            name=f"MemoryShellForensics-{site_id or 'unknown'}",
            daemon=True,
        )
        thread.start()
        return None

    def _run_forensics_locked(
        self,
        target: SiteTarget,
        kind: str,
        name: str,
        started: float,
        trigger: str,
        triggered_by: str,
        heap_live: bool,
        heap_path_override: str | Path | None,
    ) -> ForensicsOutcome:
        store = self.forensics_store
        assert store is not None  # guarded by the caller
        timeout = self.forensics_timeout
        ttl = max(_as_float(self.config.get("artifact_ttl_seconds"), 120.0), timeout + 30.0)

        plan = None
        artifact = None
        outcome: ForensicsOutcome
        try:
            # The artifact directory has to exist before the request: the heap
            # dump is written by the target JVM itself.
            plan = store.begin(site_id=target.site_id, kind=kind, name=name,
                               created_at=self._clock())
            setter = getattr(store, "set_history_limit", None)
            if callable(setter):
                setter(self.forensics_history)

            heap_requested = self.heap_dump_enabled
            heap_path = ""
            if heap_requested:
                heap_path = str(
                    Path(heap_path_override).resolve()
                    if heap_path_override
                    else Path(plan.heap_path).resolve()
                )

            params: dict[str, object] = {"kind": kind, "name": name}
            if heap_path:
                params["heap_path"] = heap_path
                params["heap_live"] = bool(heap_live)
                params["heap_max_mb"] = self.forensics_max_dump_mb

            artifact = self._deployer.deploy(target, ttl=ttl)
            payload = self._deployer.read_action(
                artifact, action=ACTION_DUMP, params=params, timeout=timeout
            )
            data = self._deployer.parse_action(payload, artifact)
            outcome = self._forensics_from_payload(
                target, kind, name, started, trigger, triggered_by, plan, data,
                heap_requested=heap_requested, heap_live=heap_live,
            )
        except ProbeError as exc:
            outcome = self._forensics_failure(
                target.site_id, target.name, started, str(exc), trigger, triggered_by,
                kind, name, plan=plan,
            )
        except Exception as exc:  # noqa: BLE001 - forensics must never take the runtime down
            self._logger.exception("memory-shell forensics failed for %s", target.site_id)
            outcome = self._forensics_failure(
                target.site_id, target.name, started, f"{type(exc).__name__}: {exc}",
                trigger, triggered_by, kind, name, plan=plan,
            )
        finally:
            # Cleanup is reported on the outcome that is actually returned, so a
            # leftover probe file can never be hidden behind a successful dump.
            if artifact is not None:
                try:
                    self._deployer.cleanup(artifact)
                except ProbeError as exc:
                    self._logger.error(
                        "memory-shell forensics probe cleanup failed for %s: %s",
                        target.site_id, exc,
                    )
                    outcome = replace(
                        outcome, cleanup_ok=False, cleanup_error=str(exc),
                        finished_at=self._clock(),
                    )
        return outcome

    def _forensics_from_payload(
        self,
        target: SiteTarget,
        kind: str,
        name: str,
        started: float,
        trigger: str,
        triggered_by: str,
        plan: Any,
        data: Mapping[str, Any],
        *,
        heap_requested: bool,
        heap_live: bool,
    ) -> ForensicsOutcome:
        store = self.forensics_store
        ref = component_from_payload(data)
        if not ref.kind:
            ref = ComponentRef(kind=kind, name=name)
        manifest = manifest_from_payload(data.get("manifest"))
        report_error = str(data.get("error") or "")

        class_bytes, class_reason = self._decode_class_bytes(data)
        if not class_reason:
            class_reason = str(data.get("class_bytes_unavailable_reason") or "")

        heap = heap_from_payload(data.get("heap")) if heap_requested else None
        heap_error = str(data.get("heap_error") or "")
        skipped = "" if heap_requested else "heap_dump_disabled"

        failure = action_failure_reason(data)
        if failure:
            return self._forensics_failure(
                target.site_id, target.name, started, failure, trigger, triggered_by,
                kind, name, plan=plan, manifest=manifest, report_error=report_error,
                heap_error=heap_error, class_bytes_unavailable_reason=class_reason,
            )

        entry: dict[str, object] = {}
        index_error = ""
        try:
            if store is not None:
                entry = store.save_run(
                    plan,
                    site_name=target.name,
                    class_name=ref.class_name or manifest.class_name,
                    on_disk=manifest.on_disk,
                    trigger=trigger,
                    triggered_by=triggered_by,
                    manifest=manifest,
                    class_bytes=class_bytes,
                    heap=heap,
                    heap_error=heap_error,
                    class_bytes_unavailable_reason=class_reason,
                    report_error=report_error,
                    live=heap_live,
                )
        except ProbeError as exc:
            index_error = str(exc)
            self._logger.error("memory-shell forensics index write failed: %s", exc)
        except Exception as exc:  # noqa: BLE001 - a storage failure is reported, not hidden
            index_error = f"{type(exc).__name__}: {exc}"
            self._logger.exception("memory-shell forensics index write failed")

        outcome = ForensicsOutcome(
            site_id=target.site_id,
            site_name=target.name,
            started_at=started,
            finished_at=self._clock(),
            ref=ref,
            trigger=trigger,
            triggered_by=triggered_by,
            manifest=manifest,
            class_bytes_bytes=len(class_bytes) if class_bytes else 0,
            class_bytes_unavailable_reason=class_reason,
            heap=heap,
            heap_error=heap_error,
            heap_skipped_reason=skipped,
            artifact_id=str(entry.get("artifact_id") or plan.artifact_id),
            artifact_dir=str(entry.get("directory") or ""),
            files=tuple(entry.get("files") or ()),
            index_recorded=bool(entry) and not index_error,
            index_error=index_error,
            report_error=report_error,
            probe_url=manifest.probe_url,
        )
        self._logger.info(
            "memory-shell forensics on %s: %s class_bytes=%s heap=%s",
            target.name,
            ref.label,
            "yes" if class_bytes else f"no ({class_reason or 'unknown'})",
            "yes" if (heap and heap.ok) else (heap_error or skipped or "no"),
        )
        return outcome

    @staticmethod
    def _decode_class_bytes(data: Mapping[str, Any]) -> tuple[bytes | None, str]:
        """Decode the probe's base64 payload, or explain why there is none.

        A malformed payload is treated as "no bytes with a reason", never as a
        silent success: the artifact would otherwise claim evidence it does not
        have.
        """
        encoded = data.get("class_bytes_b64")
        if not encoded:
            return None, ""
        try:
            raw = base64.b64decode(str(encoded).encode("ascii"), validate=True)
        except (binascii.Error, ValueError, UnicodeEncodeError) as exc:
            return None, f"class_bytes_undecodable: {type(exc).__name__}: {exc}"
        if not raw:
            return None, "class_bytes_empty_after_decode"
        return raw, ""

    def _forensics_failure(
        self,
        site_id: str,
        site_name: str,
        started: float,
        failure: str,
        trigger: str,
        triggered_by: str,
        kind: str,
        name: str,
        *,
        plan: Any = None,
        manifest: ForensicsManifest | None = None,
        report_error: str = "",
        heap_error: str = "",
        class_bytes_unavailable_reason: str = "",
    ) -> ForensicsOutcome:
        """A failed run: the artifact is discarded unless it has content."""
        artifact_id = ""
        artifact_dir = ""
        if plan is not None:
            store = self.forensics_store
            artifact_id = str(plan.artifact_id)
            artifact_dir = str(getattr(plan, "directory", ""))
            if store is not None:
                try:
                    store.discard(plan)
                except Exception:  # noqa: BLE001 - never mask the real failure
                    self._logger.debug("forensics discard failed", exc_info=True)
        return ForensicsOutcome(
            site_id=site_id,
            site_name=site_name,
            started_at=started,
            finished_at=self._clock(),
            ref=ComponentRef(kind=kind, name=name),
            trigger=trigger,
            triggered_by=triggered_by,
            failure=failure,
            manifest=manifest,
            class_bytes_unavailable_reason=class_bytes_unavailable_reason,
            heap_error=heap_error,
            artifact_id=artifact_id,
            artifact_dir=artifact_dir,
            report_error=report_error,
        )

    def _record_forensics(self, outcome: ForensicsOutcome) -> ForensicsOutcome:
        with self._lock:
            self._forensics_history.append(outcome)
            self._latest_forensics[outcome.site_id] = outcome
        return outcome

    # ════════════════════════════════════════════════════════════════
    #  remediation (处置)
    # ════════════════════════════════════════════════════════════════
    def remediate(
        self,
        site_id: str,
        kind: str,
        name: str,
        *,
        acknowledge_no_forensics: bool,
        force: bool = False,
        expect_class: str = "",
        trigger: str = "manual",
        triggered_by: str = "",
        background: bool = False,
    ) -> RemediationOutcome | None:
        """Remove one memory-resident component, or refuse with a reason.

        Three gates stand between a request and the removal, and all three are
        about the component being the thing Anteumbra actually saw:

        1. forensics must exist for this component, unless the operator
           explicitly acknowledged that it will be removed without any
           (``acknowledge_no_forensics``);
        2. the class name must be the one Anteumbra recorded for it, and the
           probe re-checks it inside the JVM before touching anything;
        3. a class that resolves to a file on disk is a deployed component, not
           a memory shell, and is refused unless ``force`` was passed.

        Nothing here ever deletes a file, edits ``web.xml`` or touches a second
        component.
        """
        if background:
            return self._start_remediation_background(
                site_id, kind, name, acknowledge_no_forensics, force, expect_class,
                trigger, triggered_by,
            )

        started = self._clock()
        target = self.target(site_id)
        if target is None:
            return self._record_remediation(
                self._remediation_refusal(site_id, site_id, kind, name, REASON_UNKNOWN_SITE,
                                          started, trigger, triggered_by,
                                          acknowledge_no_forensics, force, expect_class)
            )
        if not self.enabled:
            return self._record_remediation(
                self._remediation_refusal(target.site_id, target.name, kind, name,
                                          REASON_PROBE_DISABLED, started, trigger, triggered_by,
                                          acknowledge_no_forensics, force, expect_class)
            )
        invalid = self._invalid_component(kind, name)
        if invalid:
            return self._record_remediation(
                self._remediation_refusal(target.site_id, target.name, kind, name, invalid,
                                          started, trigger, triggered_by,
                                          acknowledge_no_forensics, force, expect_class)
            )

        store = self.forensics_store
        artifact = None
        if store is not None and getattr(store, "available", False):
            try:
                artifact = store.find_component(site_id=target.site_id, kind=kind, name=name)
            except Exception as exc:  # noqa: BLE001 - an unreadable index is a refusal, not a crash
                self._logger.error("forensics lookup failed: %s", exc, exc_info=True)

        recorded_class = expect_class.strip()
        if not recorded_class and artifact:
            recorded_class = str(artifact.get("class_name") or "")
        if not recorded_class:
            recorded_class = self._latest_recorded_class(target.site_id, kind, name)
        if not recorded_class:
            return self._record_remediation(
                self._remediation_refusal(target.site_id, target.name, kind, name,
                                          REASON_NO_RECORDED_CLASS, started, trigger, triggered_by,
                                          acknowledge_no_forensics, force, expect_class)
            )

        if artifact is None and not acknowledge_no_forensics:
            outcome = self._remediation_refusal(
                target.site_id, target.name, kind, name, REASON_FORENSICS_REQUIRED,
                started, trigger, triggered_by, acknowledge_no_forensics, force, recorded_class,
            )
            return self._record_remediation(outcome)

        lock = self._site_lock(target.site_id)
        if not lock.acquire(blocking=False):
            return self._record_remediation(
                self._remediation_refusal(target.site_id, target.name, kind, name,
                                          REASON_ALREADY_RUNNING, started, trigger, triggered_by,
                                          acknowledge_no_forensics, force, recorded_class)
            )
        try:
            with self._lock:
                self._running.add(target.site_id)
            try:
                outcome = self._run_remediation_locked(
                    target, kind, name, recorded_class, acknowledge_no_forensics, force,
                    started, trigger, triggered_by, artifact,
                )
                return self._record_remediation(outcome)
            finally:
                with self._lock:
                    self._running.discard(target.site_id)
        finally:
            lock.release()

    def _start_remediation_background(
        self,
        site_id: str,
        kind: str,
        name: str,
        acknowledge_no_forensics: bool,
        force: bool,
        expect_class: str,
        trigger: str,
        triggered_by: str,
    ) -> None:
        thread = threading.Thread(
            target=self.remediate,
            args=(site_id, kind, name),
            kwargs={
                "acknowledge_no_forensics": acknowledge_no_forensics,
                "force": force,
                "expect_class": expect_class,
                "trigger": trigger,
                "triggered_by": triggered_by,
            },
            name=f"MemoryShellRemediate-{site_id or 'unknown'}",
            daemon=True,
        )
        thread.start()
        return None

    def _run_remediation_locked(
        self,
        target: SiteTarget,
        kind: str,
        name: str,
        expect_class: str,
        acknowledge_no_forensics: bool,
        force: bool,
        started: float,
        trigger: str,
        triggered_by: str,
        artifact: Mapping[str, Any] | None,
    ) -> RemediationOutcome:
        timeout = self.forensics_timeout
        ttl = max(_as_float(self.config.get("artifact_ttl_seconds"), 120.0), timeout + 30.0)
        artifact_id = str((artifact or {}).get("artifact_id") or "")
        before_entries = self._latest_entries(target.site_id)

        artifact_probe = None
        data: Mapping[str, Any] = {}
        failure: str | None = None
        cleanup_ok = True
        cleanup_error: str | None = None
        try:
            artifact_probe = self._deployer.deploy(target, ttl=ttl)
            payload = self._deployer.read_action(
                artifact_probe,
                action=ACTION_KILL,
                params={
                    "kind": kind,
                    "name": name,
                    "expect_class": expect_class,
                    "force": bool(force),
                },
                timeout=timeout,
            )
            data = self._deployer.parse_action(payload, artifact_probe)
        except ProbeError as exc:
            failure = str(exc)
        except Exception as exc:  # noqa: BLE001 - remediation must never take the runtime down
            self._logger.exception("memory-shell remediation failed for %s", target.site_id)
            failure = f"{type(exc).__name__}: {exc}"
        finally:
            if artifact_probe is not None:
                try:
                    self._deployer.cleanup(artifact_probe)
                except ProbeError as exc:
                    cleanup_ok = False
                    cleanup_error = str(exc)
                    self._logger.error(
                        "memory-shell remediation probe cleanup failed for %s: %s",
                        target.site_id, exc,
                    )

        refused = bool(data.get("refused"))
        # A refusal carries its reason; a removal that failed carries the error
        # from the reflected call that did not go through.
        reason = str(data.get("reason") or "") or str(data.get("removal_error") or "")
        if failure:
            reason = reason or failure
        removed = bool(data.get("removed")) and failure is None and not refused

        outcome = RemediationOutcome(
            site_id=target.site_id,
            site_name=target.name,
            kind=kind,
            name=name,
            started_at=started,
            finished_at=self._clock(),
            expect_class=expect_class,
            trigger=trigger,
            triggered_by=triggered_by,
            removed=removed,
            refused=refused,
            reason=reason,
            failure=failure,
            cleanup_ok=cleanup_ok,
            cleanup_error=cleanup_error,
            acknowledge_no_forensics=bool(acknowledge_no_forensics),
            force=bool(force),
            forensics_artifact_id=artifact_id,
            before_entries=before_entries,
            after_entries=entries_from_payload(data),
            before_component=self._as_dict(data.get("before_component")),
            after_component=self._as_dict(data.get("after_component")),
            probe_url=str((data or {}).get("probe_url") or getattr(artifact_probe, "url", "")),
            extra={
                "class_name": expect_class,
                "before_entries_source": "last_probe_report" if before_entries else "unavailable",
            },
        )
        outcome = self._record_remediation_entry(outcome)
        self._log_remediation(outcome)
        return self._publish_remediation(outcome)

    def _record_remediation_entry(self, outcome: RemediationOutcome) -> RemediationOutcome:
        """Append the attempt to the artifact's history, if there is an artifact."""
        store = self.forensics_store
        if store is None or not outcome.forensics_artifact_id:
            return outcome
        # "refused" is a decision this side made, "not_removed" is a container that
        # did not let go: the two must not read the same in the audit trail.
        if outcome.failure:
            result = "failed"
        elif outcome.removed:
            result = "removed"
        elif outcome.refused:
            result = "refused"
        else:
            result = "not_removed"
        try:
            store.record_remediation(
                outcome.forensics_artifact_id,
                result=result,
                removed=outcome.removed,
                reason=outcome.reason,
                operator=outcome.triggered_by,
                acknowledge_no_forensics=outcome.acknowledge_no_forensics,
                force=outcome.force,
                remediated_at=outcome.finished_at,
            )
        except Exception as exc:  # noqa: BLE001 - the removal already happened
            self._logger.error("forensics remediation history write failed: %s", exc)
            return replace(outcome, recorded=False)
        return replace(outcome, recorded=True)

    def _publish_remediation(self, outcome: RemediationOutcome) -> RemediationOutcome:
        """Publish the audit event. The detection alert path is unchanged."""
        publisher = self._publisher
        if publisher is None:
            return outcome
        payload = {
            "event_type": "memory_shell_remediated",
            "site_id": outcome.site_id,
            "site_name": outcome.site_name,
            "kind": outcome.kind,
            "name": outcome.name,
            "class_name": outcome.expect_class,
            "removed": outcome.removed,
            "refused": outcome.refused,
            "reason": outcome.reason,
            "force": outcome.force,
            "acknowledge_no_forensics": outcome.acknowledge_no_forensics,
            "forensics_artifact_id": outcome.forensics_artifact_id,
            "before_component": outcome.before_component,
            "after_component": outcome.after_component,
            "before_count": len(outcome.before_entries),
            "after_count": len(outcome.after_entries),
            "operator": outcome.triggered_by,
            "trigger": outcome.trigger,
            "remediated_at": outcome.finished_at,
        }
        try:
            publisher.publish("memory_shell_remediated", "memory_shell_probe", payload)
        except Exception:  # pragma: no cover - the publisher stays best effort
            self._logger.debug("memory_shell_remediated publish failed", exc_info=True)
            return outcome
        return replace(outcome, published=True)

    def _log_remediation(self, outcome: RemediationOutcome) -> None:
        """Every remediation attempt, allowed or refused, is in the log."""
        self._logger.warning(
            "[MEMORY-SHELL] remediation %s on %s: %s (%s) before=%s after=%s cleanup_ok=%s",
            "removed" if outcome.removed else ("refused" if outcome.refused else "not-removed"),
            outcome.site_name,
            outcome.component_label,
            outcome.reason or "ok",
            outcome.before_component or {"count": len(outcome.before_entries)},
            outcome.after_component or {"count": len(outcome.after_entries)},
            outcome.cleanup_ok,
        )

    def _remediation_refusal(
        self,
        site_id: str,
        site_name: str,
        kind: str,
        name: str,
        reason: str,
        started: float,
        trigger: str,
        triggered_by: str,
        acknowledge_no_forensics: bool,
        force: bool,
        expect_class: str,
    ) -> RemediationOutcome:
        """A refusal changes nothing and says exactly why."""
        outcome = RemediationOutcome(
            site_id=site_id,
            site_name=site_name,
            kind=kind,
            name=name,
            started_at=started,
            finished_at=self._clock(),
            expect_class=expect_class,
            trigger=trigger,
            triggered_by=triggered_by,
            removed=False,
            refused=True,
            reason=reason,
            acknowledge_no_forensics=bool(acknowledge_no_forensics),
            force=bool(force),
        )
        self._log_remediation(outcome)
        return self._publish_remediation(outcome)

    def _record_remediation(self, outcome: RemediationOutcome) -> RemediationOutcome:
        with self._lock:
            self._latest_remediation[outcome.site_id] = outcome
        return outcome

    def _invalid_component(self, kind: str, name: str) -> str:
        if kind not in ACTION_KINDS:
            return REASON_UNKNOWN_KIND
        if not str(name or "").strip():
            return REASON_INVALID_COMPONENT
        return ""

    def _latest_recorded_class(self, site_id: str, kind: str, name: str) -> str:
        """The class Anteumbra itself recorded for this component, if any.

        Only suspicious entries count: remediation may never be justified by a
        component the probe did not flag.
        """
        with self._lock:
            outcome = self._latest.get(site_id)
        report = outcome.report if outcome is not None else None
        if report is None:
            return ""
        for entry in report.suspects:
            if entry.kind == kind and entry.name == name:
                return entry.class_name
        return ""

    def _latest_entries(self, site_id: str):
        with self._lock:
            outcome = self._latest.get(site_id)
        report = outcome.report if outcome is not None else None
        return report.entries if report is not None else ()

    @staticmethod
    def _as_dict(value: Any) -> dict[str, object]:
        return dict(value) if isinstance(value, Mapping) else {}

    # ════════════════════════════════════════════════════════════════
    #  forensics views for the admin surface
    # ════════════════════════════════════════════════════════════════
    def forensics_snapshot(self, *, limit: int = 0) -> dict[str, Any]:
        """Everything the forensics tab needs, in one JSON-safe structure."""
        store = self.forensics_store
        available = store is not None and bool(getattr(store, "available", False))
        runs: list[dict[str, object]] = []
        error = self._forensics_error
        if available and store is not None:
            try:
                runs = list(store.index(limit=limit))
            except Exception as exc:  # noqa: BLE001 - the panel reports, it does not crash
                self._logger.error("forensics index read failed: %s", exc, exc_info=True)
                error = f"{type(exc).__name__}: {exc}"
        with self._lock:
            running = sorted(self._forensics_running)
            latest = {
                site: outcome.as_dict() for site, outcome in self._latest_forensics.items()
            }
            latest_remediation = {
                site: outcome.as_dict() for site, outcome in self._latest_remediation.items()
            }
        return {
            "available": available,
            "store_error": error,
            "root": str(store.root) if store is not None else "",
            "enabled": self.forensics_enabled,
            "heap_dump_enabled": self.heap_dump_enabled,
            "history": self.forensics_history,
            "max_dump_mb": self.forensics_max_dump_mb,
            "timeout_seconds": self.forensics_timeout,
            "running": running,
            "runs": runs,
            "latest": latest,
            "latest_remediation": latest_remediation,
        }

    def forensics_manifest(self, artifact_id: str) -> dict[str, Any] | None:
        """The stored manifest of one artifact, or None when there is none."""
        store = self.forensics_store
        if store is None:
            return None
        try:
            return store.read_manifest(artifact_id)
        except Exception as exc:  # noqa: BLE001 - a broken artifact is reported as missing
            self._logger.error("forensics manifest read failed for %s: %s", artifact_id, exc)
            return None

    def forensics_file_entry(self, artifact_id: str, filename: str) -> dict[str, Any] | None:
        store = self.forensics_store
        if store is None:
            return None
        try:
            return store.file_entry(artifact_id, filename)
        except Exception:  # noqa: BLE001 - an unreadable index means "unknown file"
            return None

    def forensics_file_path(self, artifact_id: str, filename: str) -> Path | None:
        """Absolute path of one indexed artifact file, confined to the store."""
        store = self.forensics_store
        if store is None:
            return None
        try:
            return store.resolve_file(artifact_id, filename)
        except Exception:  # noqa: BLE001 - an unreadable index means "unknown file"
            return None

    def remediation_for(self, site_id: str) -> dict[str, Any] | None:
        with self._lock:
            outcome = self._latest_remediation.get(site_id)
        return outcome.as_dict() if outcome is not None else None

    # ── reporting ───────────────────────────────────────────────────
    def _raise_alert(self, outcome: ProbeOutcome) -> None:
        report = outcome.report
        if report is None or not _as_bool(self.config.get("alert_on_suspects"), True):
            return
        suspects = report.suspects
        summary = ", ".join(
            f"{item.kind}:{item.name or item.class_name}" for item in suspects[:4]
        )
        message = (
            f"内存马检出: 站点 {outcome.site_name} 内存中注册了 {len(suspects)} 个可疑组件 "
            f"({summary})"
        )
        analysis = {
            "alert_type": "memory_shell",
            "level": "CRITICAL",
            "site_id": outcome.site_id,
            "site_name": outcome.site_name,
            "probe_url": report.url,
            "context_path": report.context_path,
            "container": list(report.container),
            "suspects": [item.as_dict() for item in suspects],
            "entry_counts": report.counts(),
            "trigger": outcome.trigger,
            "triggered_by": outcome.triggered_by,
        }
        if self._publisher is not None:
            try:
                self._publisher.publish("memory_shell_found", "memory_shell_probe", analysis)
            except Exception:  # pragma: no cover - publisher must stay best effort
                self._logger.debug("memory_shell_found publish failed", exc_info=True)
        if self._notifier is not None:
            try:
                self._notifier.send_alert(
                    message,
                    level="CRITICAL",
                    analysis=analysis,
                    site_id=outcome.site_id,
                )
            except Exception:  # pragma: no cover - notifier must stay best effort
                self._logger.exception("memory-shell alert delivery failed")

    def _record(self, outcome: ProbeOutcome) -> ProbeOutcome:
        with self._lock:
            self._runs += 1
            if outcome.failure:
                self._failures += 1
            self._latest[outcome.site_id] = outcome
            self._last_run[outcome.site_id] = outcome.finished_at
            self._history.append(outcome)
            while len(self._history) > self.history_size:
                self._history.popleft()
        return outcome

    def snapshot(self) -> dict[str, Any]:
        """Everything the admin panel needs, in one JSON-safe structure."""
        with self._lock:
            history = [item.as_dict() for item in reversed(self._history)]
            latest = {site: item.as_dict() for site, item in self._latest.items()}
            running = sorted(self._running)
            runs = self._runs
            failures = self._failures
        config = self.config
        return {
            "enabled": self.enabled,
            "auto_probe": _as_bool(config.get("auto_probe_on_detection"), True),
            "cooldown_seconds": _as_float(config.get("cooldown_seconds"), 300.0),
            "http_timeout_seconds": _as_float(config.get("http_timeout_seconds"), 8.0),
            "trigger_extensions": sorted(self.trigger_extensions()),
            "sites": [
                {
                    "site_id": site.site_id,
                    "name": site.name,
                    "root": str(site.root),
                    "base_url": site.base_url,
                    "port": site.port,
                    "cooldown_remaining": round(self._cooldown_remaining(site.site_id), 1),
                    "probe_root": str(site.deployment_root),
                    "url_prefix": site.url_prefix,
                    "base_note": site.base_note,
                }
                for site in self.sites()
            ],
            "latest": latest,
            "history": history,
            "running": running,
            "runs": runs,
            "failures": failures,
        }

    # ── internals ───────────────────────────────────────────────────
    def _site_lock(self, site_id: str) -> threading.Lock:
        with self._lock:
            lock = self._site_locks.get(site_id)
            if lock is None:
                lock = threading.Lock()
                self._site_locks[site_id] = lock
            return lock

    def _cooldown_remaining(self, site_id: str) -> float:
        cooldown = _as_float(self.config.get("cooldown_seconds"), 300.0)
        with self._lock:
            last = self._last_run.get(site_id)
        if last is None:
            return 0.0
        return max(cooldown - (self._clock() - last), 0.0)

    def _cooldown_elapsed(self, site_id: str) -> bool:
        return self._cooldown_remaining(site_id) <= 0.0

    def _site_for_path(self, file_path: str) -> SiteTarget | None:
        try:
            resolved = Path(file_path).resolve()
        except OSError:  # pragma: no cover - defensive
            return None
        for site in self.sites():
            try:
                resolved.relative_to(site.root.resolve())
            except (ValueError, OSError):
                continue
            return site
        return None
