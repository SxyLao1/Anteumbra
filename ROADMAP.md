# Anteumbra Roadmap

> **Current Version**: v1.0.4 (2026-07-03)  
> **Vision**: Web Perimeter Threat Intelligence — Passive Detection · Semi-Active Response · File-Level Forensics  
> **Status**: PyPI published, 144/144 tests passing, DDD architecture complete

---

## v1.0.x — DDD Migration + Surgery (Current)

| Milestone | Status | Version |
|-----------|--------|---------|
| Trident v1.9.5 → Anteumbra rename | Done | v1.0.0 |
| DDD four-layer architecture | Done | v1.0.0 |
| `pip install anteumbra` package | Done | v1.0.0 |
| Unified CLI (`anteumbra run|start|stop|status|config`) | Done | v1.0.0 |
| Flask-Babel i18n (en/zh, auto-detect) | Done | v1.0.0 |
| PluginManager + EDA event-driven (95%+ coverage) | Done | v1.0.1 |
| emit/dispatch semantic separation (async Fire-and-Forget) | Done | v1.0.1 |
| Repository bridge (JSON + SQLite dual-write) | Done | v1.0.2–v1.0.3 |
| Block Ledger + Bidirectional Links + Broadcast | Done | v1.0.2–v1.0.3 |
| Blueprint split (admin → 5 route modules) | Done | v1.0.2 |
| SQLite FK constraints (3 FKs) + index optimization (13) | Done | v1.0.4 |
| Docker multi-stage build (3 hash engines active) | Done | v1.0.4 |
| PyPI official publish | Done | v1.0.4 |
| 144/144 tests (88 unit + 21 E2E backend + 34 E2E UI + 1 WAF) | Done | v1.0.4 |

---

## v1.0.5 — Polish & Test Hardening (In Progress)

| Priority | Feature | Status |
|----------|---------|--------|
| P0 | Template `_()` i18n full coverage (34/40 templates) | In Progress |
| P0 | threat_graph dataclass → models.py migration cleanup | ✅ Done |
| P0 | ROADMAP + CHANGELOG update | In Progress |
| P1 | 13 manual tests → automated (deploy 4 + security 4 + profiling 5) | Pending |
| P1 | Full-chain E2E scenario (Mock WAF → Block Ledger) | Pending |
| P2 | CLAUDE.md / PROJECT_MASTER / Memory docs sync | Pending |

---

## v1.1.0 — Multi-Site + Intelligence

| Priority | Feature |
|----------|---------|
| P0 | Multi-site support (`[[website]]` array) |
| P0 | CI/CD pipeline (GitHub Actions: test + build + Docker) |
| P1 | Geo-IP integration (MaxMind GeoLite2) |
| P1 | Java Memory Shell Agent PoC |
| P2 | Admin 2FA (TOTP) + API key management |
| P2 | MISP / AbuseIPDB threat intelligence feed |
| P3 | EventBus (asyncio) + Pydantic Schema migration |

## v1.2.0 — Production Hardening

| Priority | Feature |
|----------|---------|
| P0 | Docker multi-arch image (amd64 + arm64) |
| P1 | Redis session backend |
| P1 | Prometheus metrics endpoint |
| P2 | SIEM syslog live streaming |
| P3 | Multi-tenancy (tenant isolation) |

---

## v2.0.0 — Async Core (Future)

| Priority | Feature |
|----------|---------|
| P0 | asyncio EventBus replacing queue.Queue |
| P0 | Pydantic v2 Schema for all events |
| P1 | Plugin marketplace (pip installable plugins) |
| P1 | GraphQL API alongside REST |
| P2 | Distributed deployment (Redis pub/sub between nodes) |

---

## Trident Legacy (Archived)

See [Trident CHANGELOG](https://github.com/SxyLao1/Trident/blob/main/CHANGELOG.md) for v1.7.9–v1.9.5 details.

**Key accomplishments (2025–2026):**
- Blueprint split (3767→2155 lines), JS modularization (1455→561)
- SQLite backend (WAL mode) + DualWriteRepository
- Plugin Manager + stdout_logger + 4 WAF adapters
- Log Heuristic Engine + SIEM CEF/JSON Lines exporter
- Memory Shell Tracer + reference tools
- 79 core tests + code quality fixes (SQL injection, thread safety, timezone)
