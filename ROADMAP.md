# Anteumbra Roadmap

> **Current Version**: v1.0.27 (verified release candidate, 2026-07-17)
> **Vision**: Single-host and small-Web-workload security operations: passive file detection, access-log behavior analysis, attacker profiling, operator response, and standard SIEM output.
> **Current Status**: v1.0.27 closes runtime reliability and YARA-governance blockers. Wheel, editable-source, Docker, CLI, non-UI, and browser smoke checks are complete; tag, push, and PyPI publication remain. It is not positioned as a replacement for WAF, EDR, SIEM, centralized fleet management, or distributed HA.

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
| Architecture guardrails | Layer/import boundary tests exist, and resolved debt has been removed from the allowlist. |
| Documentation | README, user manual, architecture docs, and release guide reflect the current install model. |

### Known Truths

- The project is usable as a beta/release-candidate security tool, but should not be described as fully production-hardened yet.
- The architecture is significantly cleaner than the inherited Trident shape, but not fully re-architected.
- The deepest remaining coupling is still around global runtime state, especially `ConfigRegistry`, process-wide paths, and singleton service factories. Launcher resource ownership is cleaner, but the runtime is not yet dependency-injected.
- Docker fuzzy hashing is best-effort: `yara-python` is installed, while `py-tlsh` and `ssdeep` are optional and may degrade gracefully depending on Python/base-image compatibility.
- Some historical comments and older modules still contain encoding damage from earlier development; they do not block runtime, but they hurt maintainability.

---

## v1.0.20 - v1.0.27 Cleanup Line

| Version | Theme | Status |
|---------|-------|--------|
| 1.0.20 | Refactor baseline and architectural guardrails | Done |
| 1.0.21 | First-run runtime startup reliability | Done |
| 1.0.22 | CLI configuration workflow and configured bind handling | Done |
| 1.0.23 | Web audit entry points, quieter SSE logs, notifier visibility | Done |
| 1.0.24 | Tomcat access-log analyzer and CLI presets | Done |
| 1.0.25 | Docker full-runtime deployment and documentation sync | Done |
| 1.0.26 | Multi-site lifecycle, poison-event handling, transactional quarantine, truthful UI E2E | Released to PyPI |
| 1.0.27 | Runtime observability, bounded backpressure, trusted proxies, SIEM bridge, YARA governance, restore de-duplication | Verified; ready to tag |

---

## Release Readiness Checklist

Before a wider user push or PyPI release, complete this checklist.

| Priority | Item | Status |
|----------|------|--------|
| P0 | Update CHANGELOG through the current version | Done for 1.0.27 |
| P0 | Verify release wheel clean install in a fresh runtime directory | Done for 1.0.27 |
| P0 | Verify source editable install in a fresh runtime directory | Done for 1.0.27 |
| P0 | Verify Docker build/run/health/detection path | Done for 1.0.27 |
| P0 | Confirm README commands match real output | Done for 1.0.27 |
| P1 | Run deployment, architecture, and relevant web regression tests | Done: 464 non-UI passed, 1 skipped; 5 current UI smoke passed |
| P1 | Tag release and push only after the final clean install check | Pending |
| P1 | Publish to PyPI from tag using the release workflow | Pending |

---

## v1.1.0 - Configuration And Runtime Decoupling

Goal: make the project easier for one AI or one engineer to implement a module independently, without accidentally coupling to global process state.

| Priority | Work Item | Why |
|----------|-----------|-----|
| P0 | Introduce an application/runtime context object | Replace scattered global lookups with explicit dependencies. |
| P0 | Reduce direct `ConfigRegistry` imports outside infrastructure/config and composition roots | Keep feature modules easier to test and reuse. |
| P0 | Define stable module integration contracts for scanner, monitor, log analyzer, notifier, quarantine, and WAF adapters | Let independent module work plug in without hidden side effects. |
| P1 | Separate startup resource allocation from request handlers | Make web, CLI, Docker, and tests share the same runtime composition path. |
| P1 | Add tests that enforce no new cross-layer imports | Keep the architecture from drifting backward. |
| P1 | Normalize old mojibake comments in touched modules | Improve maintainability without risky broad rewrites. |
| P2 | Create developer module templates for plugins/analyzers/adapters | Make extension work repeatable for humans and AIs. |

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
