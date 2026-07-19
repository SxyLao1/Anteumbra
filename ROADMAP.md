# Anteumbra Roadmap

[中文](ROADMAP_cn.md)

> **Latest Release**: v1.0.30 (release validation completed, 2026-07-19)
> **Vision**: Single-host and small-Web-workload security operations: passive file detection, access-log behavior analysis, attacker profiling, operator response, and standard SIEM output.
> **Source Status**: `main` matches the validated v1.0.30 source: 499 non-browser tests, 41 browser tests, Ruff, and a 116-module import sweep pass. Clean Wheel, editable-source, Windows runtime, Docker health/detection, and GitHub CI checks are complete.

---

## Where The Project Stands

Anteumbra has moved past the initial Trident rename and packaging surgery. The current 1.0.x line is focused on making one coherent product instead of separate PyPI, source, and Docker experiences.

### Done In 1.0.x

| Area | Current State |
|------|---------------|
| Packaging | `pip install anteumbra` uses packaged config, templates, translations, static assets, plugins, and YARA rules. |
| Runtime setup | `anteumbra install <dir>` creates a runtime instance with `config.toml`, `.env`, rules, logs, data directories, and an initial admin password. |
| CLI configuration | `anteumbra config init/set/env/wizard/access-log/validate/reload` covers first-run setup and common operator edits. |
| Web workflows | Dashboard, monitoring, scanner, quarantine, restore, false-positive marking, settings, logs, audit entry points, and health checks are wired. |
| Access-log analysis | Nginx, Apache, Tomcat, and custom access-log presets are supported from CLI and web audit views. |
| Log streaming | SSE log stream is quieter, loads historical monitor logs, and exposes notifier delivery state. |
| Docker | Container now starts the full `anteumbra run` runtime, creates Docker-friendly defaults, prints first-start credentials, and passes health checks. |
| Runtime reliability | Multi-site resources have explicit startup/shutdown ownership; poison JSONL events advance through a dead-letter path; bounded queues use backpressure rather than drops; startup baseline scans and degraded capabilities are visible. |
| Rule governance | 27 bundled YARA files compile independently; invalid custom files are isolated, failed reloads retain valid rules, and THOR shards stay independently verifiable. |
| Architecture guardrails | Layer/import boundaries, source-only test imports, and Wheel/source parity are enforced; resolved debt stays out of builds. |
| Runtime ownership | One `RuntimeLifecycle` owns startup, status, reverse-order shutdown, and per-app login throttling without mutable Web/launcher module state. |
| Integration contracts | `RuntimeContainer` exposes required services through focused Domain Protocols; Web routes and plugins no longer reach Metrics, cluster, ThreatGraph, or Notifier private state. |
| Documentation | README, user manual, architecture, roadmap, changelog, release guide, and memory-shell toolkit have explicit English/Chinese navigation. |

### Known Truths

- The project is usable as a single-host security operations tool, but should not be described as a replacement for a production WAF, EDR, SIEM, centralized fleet manager, or distributed HA platform.
- The architecture is a modular monolith: `launcher.py` is the sole composition root, while independently replaceable services implement contracts from `domain/runtime.py` and `domain/service_ports.py`.
- Site ownership is complete in Registry, metrics, notifications, quarantine, scanner history, dashboard summaries, ThreatGraph profiles/reputation, and SQLite shadow keys. Stable `website.id` ownership survives display-name changes; historical unassigned data remains explicitly `legacy`.
- Login-attempt throttling is owned by each app runtime through `LoginRateLimiter`. Its in-memory backend fits the current single-process product; multi-worker or distributed deployment would require a shared backend.
- Docker fuzzy hashing is best-effort: `yara-python` is installed, while `py-tlsh` and `ssdeep` are optional and may degrade gracefully depending on Python/base-image compatibility.

---

## v1.0.20 - v1.0.30 Cleanup Line

| Version | Theme | Status |
|---------|-------|--------|
| 1.0.20 | Refactor baseline and architectural guardrails | Done |
| 1.0.21 | First-run runtime startup reliability | Done |
| 1.0.22 | CLI configuration workflow and configured bind handling | Done |
| 1.0.23 | Web audit entry points, quieter SSE logs, notifier visibility | Done |
| 1.0.24 | Tomcat access-log analyzer and CLI presets | Done |
| 1.0.25 | Docker full-runtime deployment and documentation sync | Done |
| 1.0.26 | Multi-site lifecycle, poison-event handling, transactional quarantine, truthful UI E2E | Released to PyPI |
| 1.0.27 | Runtime observability, bounded backpressure, trusted proxies, SIEM bridge, YARA governance, restore de-duplication | Released to PyPI |
| 1.0.28 | Site-isolated runtime services, site-aware records/metrics/notifications, JSON-authoritative SQLite shadows, architecture guardrails | Released to PyPI |
| 1.0.29 | Stable site identity across renames, instance-owned lifecycle/login throttling, site-isolated ThreatGraph, stable log ownership/history, focused service Protocols, deterministic Waitress shutdown, Docker/CI hardening | Released to PyPI |
| 1.0.30 | Clean Registry recovery boundaries and exact reconciliation of legacy SQLite shadow keys | Released to PyPI |

---

## Release Readiness Checklist

Before a wider user push or PyPI release, complete this checklist.

| Priority | Item | Status |
|----------|------|--------|
| P0 | Update English and Chinese changelog/docs for release source | Done for v1.0.30 |
| P0 | Verify release wheel clean install in a fresh runtime directory | Done: 117 Python / 204 package files; install and detection passed |
| P0 | Verify source editable install in a fresh runtime directory | Done from clean commit clone |
| P0 | Verify Docker build/run/health/detection path | Done: healthy container and site-qualified detection |
| P0 | Confirm README commands match real CLI output | Done during Wheel/source install smoke |
| P1 | Run deployment, architecture, and relevant web regression tests | Done: 499 non-browser; 41 UI; GitHub CI passed |
| P1 | Tag release only after every check above passes from a clean tree | Done for v1.0.30 |
| P1 | Verify trusted PyPI publishing and install the published artifact | Done for v1.0.30 |

---

## Architecture Closure Before v1.1.0

Goal: make the project easier for one AI or one engineer to implement a module independently, without accidentally coupling to global process state.

| Priority | Work Item | Status | Why |
|----------|-----------|--------|-----|
| P0 | Introduce an application/runtime context object | Done | Replace scattered global lookups with explicit dependencies. |
| P0 | Remove the global configuration registry | Done | One `TomlConfigProvider` is owned by each runtime. |
| P0 | Define stable integration contracts for scanner, clusters, ThreatGraph, notifier, SIEM, SSE, WAL, WAF, and plugins | Done on `main` | Independent modules plug in through focused Protocols. |
| P0 | Own launcher resources per runtime and remove module lifecycle facades | Done on `main` | Multiple app/test runtimes no longer share launcher state. |
| P0 | Complete site isolation through threat intelligence and public queries | Done on `main` | Same IP/path/profile data cannot bleed across sites. |
| P1 | Remove cross-module private-state access | Done on `main` | Interfaces use public snapshots and query methods. |
| P1 | Add tests that enforce imports, public ports, docs parity, and strict CI smoke checks | Done on `main` | Keep architecture and governance from drifting backward. |
| P1 | Move login-attempt throttling into an app-owned service | Done on `main` | Independent app/test runtimes no longer share mutable interface-module state. |
| P1 | Normalize old mojibake comments in touched modules | Ongoing | Improve maintainability without risky broad rewrites. |

---

## v1.1.0 - Multi-Site Operations And Extension SDK

Feature work starts only after the architecture-closure release passes the full
wheel/source/Docker/PyPI checklist.

| Priority | Work Item |
|----------|-----------|
| P0 | Add a site selector and complete site-scoped dashboard/navigation state without changing the underlying isolation model. |
| P0 | Publish developer templates for plugins, log analyzers, scanners, and adapters against the existing Protocols. |
| P1 | Add contract tests for third-party modules and validate plugin metadata/configuration before activation. |
| P1 | Add explicit operator-facing migration and backup flows for multi-site instances. |
| P2 | Introduce typed event payload schemas while preserving the current in-process event bus. |

---

## v1.2.0 - Production Hardening

| Priority | Work Item |
|----------|-----------|
| P0 | Fresh PyPI install smoke test in CI |
| P0 | Docker image release workflow and multi-arch build (`linux/amd64`, `linux/arm64`) |
| P1 | Redis/cache-backed session option for production |
| P1 | Prometheus-compatible metrics endpoint or documented scrape path |
| P1 | Reverse-proxy deployment examples for Nginx/Caddy |
| P2 | Live syslog streaming mode for SIEM, beyond file export |
| P2 | Stronger backup/restore documentation for `data/`, `logs/`, `config.toml`, and `.env` |

---

## v1.3.0 - Intelligence Expansion

| Priority | Work Item |
|----------|-----------|
| P1 | Geo-IP enrichment for attacker profiles |
| P1 | AbuseIPDB/MISP-style threat intelligence feed integration |
| P1 | Admin 2FA/TOTP and API key management |
| P2 | Multi-site configuration (`[[website]]`) with clear UI separation |
| P2 | Better report export for security review workflows |

---

## v2.0.0 - Async And Distributed Core

These are future architecture moves, not 1.0.x cleanup tasks.

| Priority | Work Item |
|----------|-----------|
| P0 | Async event bus replacing the current queue/thread model |
| P0 | Typed event schemas for all internal events |
| P1 | Distributed deployment using Redis/pub-sub or equivalent |
| P1 | Plugin marketplace or pip-installable external plugins |
| P2 | GraphQL or richer query API alongside REST |

---

## Archived Trident Lineage

Anteumbra inherits useful pieces from Trident: file monitoring, YARA detection, log heuristics, SIEM export, plugin ideas, memory-shell tooling, and a web dashboard. The 1.0.x line is about turning that inheritance into a coherent installable product with testable module boundaries.
