# Anteumbra Roadmap

> **Current Version**: v1.0.7 (2026-07-03)  
> **Vision**: Web Perimeter Threat Intelligence — Passive Detection · Semi-Active Response · File-Level Forensics  
> **Status**: PyPI published, ~217 tests passing, DDD + EDA architecture complete, CI/CD operational, admin blueprint fully modularized

---

## v1.0.x — DDD Migration + Surgery (Current)

| Milestone | Status | Version |
|-----------|--------|---------|
| Trident v1.9.5 → Anteumbra rename | ✅ Done | v1.0.0 |
| DDD four-layer architecture | ✅ Done | v1.0.0 |
| `pip install anteumbra` package | ✅ Done | v1.0.0 |
| Unified CLI (`anteumbra run\|start\|stop\|status\|config`) | ✅ Done | v1.0.0 |
| Flask-Babel i18n (en/zh, auto-detect) | ✅ Done | v1.0.0 |
| PluginManager + EDA event-driven (95%+ coverage) | ✅ Done | v1.0.1 |
| emit/dispatch semantic separation (async Fire-and-Forget) | ✅ Done | v1.0.1 |
| Repository bridge (JSON + SQLite dual-write) | ✅ Done | v1.0.2–v1.0.3 |
| Block Ledger + Bidirectional Links + Broadcast | ✅ Done | v1.0.2–v1.0.3 |
| Blueprint split (admin → 5+ route modules) | ✅ Done | v1.0.2 |
| SQLite FK constraints (3 FKs) + index optimization (13) + auto-migration | ✅ Done | v1.0.4 |
| Docker multi-stage build (3 hash engines active) | ✅ Done | v1.0.4 |
| PyPI official publish (Trusted Publishing OIDC) | ✅ Done | v1.0.4 |

---

## v1.0.5 — Polish & Test Hardening (Released 2026-07-03)

| Priority | Feature | Status |
|----------|---------|:---:|
| P0 | Template i18n full coverage — 36/40 templates, ~490 `{{ _(...) }}` | ✅ |
| P0 | Version unification — `__init__.__version__` single source of truth (PEP 440) | ✅ |
| P0 | ScanResult triple-definition unified → `domain/entities.py` dataclass (10 fields) | ✅ |
| P0 | `html_escape` → `markupsafe.escape()` (Flask standard library) | ✅ |
| P0 | `DummyEngine` (YARA fallback) — explicit `compiled_rules`/`match` replacing `__getattr__` | ✅ |
| P0 | `EmergencyScanner` — `advanced_bypass` import wrapped in try/except safe fallback | ✅ |
| P0 | `FileRecord.from_dict` — filter unknown keys from SQLite rows (`id` column) | ✅ |
| P1 | 73 new automated tests (deployment 11 + security 52 + profiling E2E 8 + full-chain 1) | ✅ |
| P1 | CI/CD — GitHub Actions: test matrix (3.10/3.11/3.12) + Playwright UI + Build + Docker + PyPI publish (OIDC) | ✅ |
| P1 | `threat_graph` dataclasses → `infrastructure/models.py` migration | ✅ |
| P1 | ROADMAP.md + CHANGELOG.md created and updated | ✅ |
| P1 | Docker build fixes — ssdeep/py-tlsh optional fallback, shell redirect escaping | ✅ |
| P2 | Project documentation sync (CLAUDE.md + PROJECT_MASTER + Memory) | ✅ |

---

## v1.0.7 — Registry Test Isolation & Full-Chain E2E (Released 2026-07-03)

| Priority | Feature | Status |
|----------|---------|:---:|
| P0 | Registry test isolation — `_is_tool_script()` native pytest detection + unconditional path override | ✅ |
| P0 | Full-chain E2E fix — `test_full_chain_waf_to_block_ledger` now PASSES | ✅ |
| P1 | Test count: 186 backend + 34 UI = 220 (was ~217 with 1 skip + 1 intermittent) | ✅ |

---

## v1.0.6 — Blueprint Modularization & Security (Released 2026-07-03)

| Priority | Feature | Status |
|----------|---------|:---:|
| P0 | admin_bp split — 2280 lines → admin_bp (776) + settings_bp (350) + monitor_bp (500) + system_bp (450) | ✅ |
| P0 | `/admin/debug/routes` + `/admin/test` @require_auth security fix | ✅ |
| P1 | Unused import cleanup in admin_bp.py after split | ✅ |
| P1 | Version bump + all docs sync (README/ROADMAP/CHANGELOG/memory) | ✅ |

**Zero template changes, zero URL changes** — all routes retain `/admin/*` paths across 4 blueprints.

---

## v1.1.0 — Multi-Site + Intelligence (Planned)

| Priority | Feature |
|----------|---------|
| P0 | Full-chain E2E test fix (Registry data isolation) |
| P1 | UI test stabilization (Playwright parallel run timeouts) |
| P1 | Geo-IP integration (MaxMind GeoLite2) |
| P1 | Admin 2FA (TOTP) + API key management |
| P2 | Multi-site support (`[[website]]` array) |
| P2 | MISP / AbuseIPDB threat intelligence feed integration |

---

## v1.2.0 — Production Hardening (Planned)

| Priority | Feature |
|----------|---------|
| P0 | Docker multi-arch image (amd64 + arm64) |
| P1 | Redis session backend |
| P1 | Prometheus metrics endpoint |
| P2 | SIEM syslog live streaming |
| P2 | ConfigRegistry → dependency injection (Kimi audit P0, 1-week refactor) |
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
