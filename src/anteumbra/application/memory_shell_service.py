# -*- coding: utf-8 -*-
"""Memory-shell probe orchestration.

One probe run is a small, bounded conversation with the target container:

    pick the site -> deploy a random probe -> read it over HTTP
      -> parse what the container has in memory -> delete probe and directory

The service owns everything that can go wrong around that: configuration,
cooldown, single-flight per site, history for the admin UI, and the alert when
something suspicious is registered in memory.

Cleanup is not optional. The probe is removed in a ``finally`` block, and a
failed cleanup is reported as its own field rather than being hidden, because a
leftover probe is a security problem in the very site the defender protects.
"""

from __future__ import annotations

import logging
import threading
import time
from collections import deque
from pathlib import Path
from typing import Any, Callable, Mapping

from anteumbra.domain.memory_shell import (
    InternalArtifactRegistryPort,
    ProbeError,
    ProbeOutcome,
    SiteTarget,
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

        self._lock = threading.RLock()
        self._site_locks: dict[str, threading.Lock] = {}
        self._history: deque[ProbeOutcome] = deque(maxlen=200)
        self._latest: dict[str, ProbeOutcome] = {}
        self._last_run: dict[str, float] = {}
        self._running: set[str] = set()
        self._runs = 0
        self._failures = 0

    # ── configuration ───────────────────────────────────────────────
    def bind_publisher(self, publisher: Any | None) -> None:
        with self._lock:
            self._publisher = publisher

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
