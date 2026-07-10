# Anteumbra Changelog

> All notable changes to Anteumbra, the Web Perimeter Threat Intelligence platform.

---

## [1.0.17] - 2026-07-11

### Fixed
- Bundled the deployment `config.toml` template in the Python package so PyPI installs can create complete runtime instances.
- Changed `anteumbra install` to fail when the config template is missing instead of reporting a partial success.
- Changed `anteumbra start` to launch the installed package entry point instead of requiring source-tree `run.py`.
- Aligned CLI `run`/`start` default port with the bundled config and launcher default (`8080`).

### Docs
- Clarified PyPI install as the normal user/deployment path and source editable install as the developer/test path.

---

## [1.0.16] - 2026-07-10

### Fixed
- Changed manual scanner startup from GET side effect to POST job creation plus authenticated SSE stream subscription.
- Added scanner regression coverage for GET method rejection and POST input validation.

---

## [1.0.15] - 2026-07-10

### Fixed
- Removed dead `require_auth_except_sse` helpers that were no longer used and conflicted with the current credential/session model.
- Marked short config/template MD5 hashes as non-security display digests, reducing Bandit noise without changing UI output.
- Tightened the architecture import-boundary ratchet after removing `_shared.py`'s stale direct `ConfigRegistry` dependency.

---

## [1.0.10] — 2026-07-05

### Fixed
- **Critical: plugins/ not in package tree** — `plugins/` moved to `src/anteumbra/plugins/`, fixing silent failure of all 4 built-in plugins (quarantine, notifier, threat_graph, stdout_logger) on pip installs. Import path in `plugin_manager.py` updated from `plugins.{name}` to `anteumbra.plugins.{name}`.
- **Quarantine page 500** — field normalization: SQLite records with `created_at` but no `quarantine_time` now normalized in `get_quarantine_list()`; template uses defensive `.get()` for both fields
- **Password change 415** — `/admin/settings/password` now accepts both JSON (`request.get_json(silent=True)`) and HTML form data (`request.form.to_dict()`)
- **FileMonitorHandler** — added missing `website` attribute causing AttributeError
- **SSE crash on first run** — monitor.log existence check before opening

### Changed
- **Plugin diagnostics** — `quarantine_handler` and `notifier_handler` now write to `logs/Anteumbra/plugins.log` via `RotatingFileHandler` (10MB × 3 backups)
- **Password config** — `config.toml` now uses `${ANTEUMBRA_PASSWORD_HASH:-}` referencing `.env` instead of hardcoded hash
- **.env template** — added all notification fields (email/wechat/webhook)

---

## [1.0.9] — 2026-07-05

### Added
- **`anteumbra install [path]`** — single-machine deployment command with global registry lock (`~/.anteumbra/installs.json`)
- **Launcher module** — extracted startup logic from `run.py` and `cli/main.py` into `application/launcher.py`

### Fixed
- **Packaging: missing non-Python files** — wheel now includes templates (43 HTML), static (20 CSS/JS), translations (2 .po/.mo), YARA rules (18 .yar) via `[tool.setuptools.package-data]`
- **Resource path resolution** — 6 files using `__file__` multi-level traversal replaced with `Path(anteumbra.__file__).parent` relative paths
- **Dockerfile** — removed stale `COPY translations/` and `COPY rules/` (now bundled in package)

### Changed
- **Resources moved into package** — `rules/webshell/` → `src/anteumbra/rules/webshell/`, `translations/` → `src/anteumbra/translations/`

---

## [1.0.8] — 2026-07-04

### Fixed
- **Registry test isolation**: `_is_tool_script()` now natively detects pytest via `PYTEST_CURRENT_TEST`; `_ensure_initialized()` unconditionally overrides production path in test mode — fixes import-timing bug where `wal_manager` import chain locked production path before env vars were set
- **Full-chain E2E**: `test_full_chain_waf_to_block_ledger` now PASSES (was skipped since v1.0.5) — fixed path lookup to use `path_to_key()` matching stored registry format
- **Test count**: 186 backend + 34 UI = 220 tests passing (was ~217, full_chain skipped, 1 intermittent fail)

---

## [1.0.6] — 2026-07-03

### Changed
- **admin_bp modularization**: 2280-line monolith split into 4 blueprints:
  - `admin_bp.py` (776 lines, 12 routes) — core: login/dashboard/overview/threats/metrics/account/health
  - `settings_bp.py` (350 lines, 13 routes) — settings editor, .env, notifications, SIEM, plugin status
  - `monitor_bp.py` (500 lines, 18 routes) — SSE log stream, WAL, registry, session, config watcher
  - `system_bp.py` (450 lines, 9 routes) — four-quadrant system management, compact/replay/cleanup/reload
- **Zero breaking changes**: all routes retain `/admin/*` URL prefix; zero template changes; `url_for('admin.login')` unchanged

### Fixed
- **Security**: `/admin/debug/routes` and `/admin/test` now require `@require_auth` (previously accessible without login)
- **Unused imports**: cleaned up ~10 dead imports in admin_bp.py after split

### Security
- `/admin/debug/routes` — route table exposure prevented for unauthenticated users
- `/admin/test` — debug endpoint now protected by authentication

---

## [1.0.5] — 2026-07-03

### Added
- **CI/CD (GitHub Actions)**: test matrix (Python 3.10/3.11/3.12) + Playwright UI tests + Docker build + PyPI publish via Trusted Publishing (OIDC)
- **73 new automated tests**: deployment (11) + security (52) + profiling E2E (8) + full-chain SOP (1)
- **i18n full coverage**: 36/40 templates → ~490 `{{ _(...) }}` markers (Flask-Babel, en/zh)
- **CHANGELOG.md**: full changelog v1.0.0 → present

### Changed
- **Version: single source of truth** — `anteumbra.__version__` (PEP 440) is the only place to change; `pyproject.toml` reads via `attr` directive; `config.toml` version field removed
- **ROADMAP.md**: rewritten to reflect v1.0.4 reality + v1.0.5/v1.1.0/v2.0.0 roadmap
- **threat_graph dataclasses**: deduplicated — canonical definitions in `infrastructure/models.py`

### Fixed
- **ScanResult definitions unified** — three separate definitions (`domain/entities.py`, `domain/detector.py`, `infrastructure/models.py`) merged into single dataclass in `domain/entities.py` with all 10 fields
- **html_escape** — custom implementation replaced with `markupsafe.escape()` (Flask standard library)
- **EmergencyScanner** — `advanced_bypass` module import wrapped in try/except to prevent crash when module is unavailable
- **DummyEngine (YARA fallback)** — replaced `__getattr__` catch-all with explicit `compiled_rules`/`match` methods for safer fallback behavior
- **Jinja2 syntax errors** × 2: nested `{{ }}` in notify_config.html, `_()` inside string literal in monitor_content.html
- **Version drift**: config.toml (1.0.1) / __init__.py (1.0.2) / pyproject.toml (1.0.4) → all unified

---

## [1.0.4] — 2026-07-03

### Added
- **SQLite FK foreign key constraints** (3): `registry.quarantine_id → quarantine.quarantine_id`, `registry.profile_id → threat_profiles.profile_id`, `block_ledger.profile_id → threat_profiles.profile_id` — all `ON DELETE SET NULL`
- **SQLite index optimization** (13 column indexes): added `idx_registry_profile`, `idx_registry_deleted`, `idx_block_ledger_time`, `idx_threat_profiles_status`, `idx_threat_profiles_last_seen`
- **Auto schema migration**: `_run_migrations()` — detect FK missing → CREATE temp → INSERT data → DROP old → RENAME, no manual DB rebuild needed
- **Dockerfile**: multi-stage build (Python 3.12-slim builder → runtime), non-root user `anteumbra`, HEALTHCHECK, gunicorn 4 workers
- **`.dockerignore`**: exclude git/cache/tests/IDE files/data/*.db/logs
- **`.gitignore`**: added `*_log.txt` and `screenshots/` patterns

### Changed
- SCHEMA table creation order rearranged: `quarantine → threat_profiles → registry → block_ledger → scan_history → wal_events` (FK dependency order)
- `pyproject.toml`: Python >=3.8 → >=3.10, classifiers improved, full/dev optional-deps, playwright added to dev deps
- `README.md` + `README_zh.md`: badges v1.0.1→v1.0.4, tests 79→144, Docker deployment section, bidirectional links/Block Ledger added to key capabilities
- E2E UI tests: all migrated to `tests/e2e_ui/`, function-scoped Flask server

### Fixed
- **SSE blocking Playwright navigation**: `about:blank` → settle → target URL pattern, 5 timeout tests fixed
- **Settings page timeout**: try/except removed, about:blank timeout raised to 10s
- **Login test**: werkzeug hash monkey-patch fixed authentication

---

## [1.0.3] — 2026-07-02

### Added
- **Storage layer Repository bridge full coverage**: `block_ledger` connected to unified Repository interface
- **Block Ledger**: block audit trail JSON persistence (`data/block_ledger.json`), IP audit tracking
- **Blocklist page**: inline note editing, JSON/CSV export, source filtering (auto/manual)
- **Bidirectional links**: Profile ↔ Records ↔ Quarantine cross-navigation
- **Broadcast config**: `[ip_blocker]` enabled by default, stdout device

### Changed
- `admin_bp.py`: Blueprint split → records_bp / profiles_bp / blocklist_bp
- `profile_detail.html`: added "LINKED DETECTION RECORDS" section
- `record_detail.html`: linked Profile navigation
- Navbar: Blocklist entry added between Profiles and Settings

---

## [1.0.2] — 2026-07-01

### Added
- **suspicious_registry event-driven**: 6 write operations (add/update/mark_false_positive/delete/quarantine/restore) all use `pm.emit()`
- **monitor dual-track bridge**: 7 direct calls → emit + 3 bridge plugins
  - `quarantine_handler`: listen → auto quarantine
  - `notifier_handler`: listen → alert notification
  - `threat_graph_handler`: listen → profile update
- **dispatch timeout**: sync events 30s timeout protection
- **E2E backend test suite**: 21 tests (detect→quarantine 5, IP block 8, WAF profiling 4, file clustering 4)
- **Playwright UI test suite**: 34 tests (Dashboard/System/Settings/Login/Navigation/Smoke)
- **Compatibility tests**: 9 tests (v1.7.8 API compatibility)
- WAL Manager page + Session Manager page
- Config Watcher SSE real-time push

### Changed
- `admin_bp.py` (~3500 lines) Blueprint split: admin_bp / quarantine_bp / yara_bp / metrics
- Registry format standardized: dict→list conversion
- Quarantine logging: "isolating" hint + DELETE → QUARANTINE FILE

### Fixed
- Quarantine/false positive silent failure (Registry format inconsistency)
- Test module-level side effect isolation (sys.path/os.chdir pollution)
- `e2e_test.py` pytest collection conflict (def test → def run_test)

---

## [1.0.1] — 2026-06-30

### Added
- **PluginManager**: emit() async Fire-and-Forget (queue.Queue worker thread), dispatch() sync call
- **count() whitelist**: anti-enumeration + registry_adapter migration
- **App factory pattern**: `create_app()` Flask factory

### Changed
- emit/dispatch semantic separation (async Fire-and-Forget vs sync)
- Version: 2.0.0.dev0 → 1.0.0.dev0

### Fixed
- PluginManager worker thread deadlock (RLock nesting)
- `mark_false_positive` then Registry not refreshing

---

## [1.0.0] — 2026-06-28

### Added
- **Trident → Anteumbra rename**: pip package `anteumbra`
- **DDD four-layer architecture**: domain/ application/ infrastructure/ interfaces/
- **EDA event-driven**: PluginManager + event subscribe/dispatch
- Unified CLI: `anteumbra run|start|stop|status|config`
- Flask-Babel i18n (en/zh, auto-detect)
- Registry format standardization (dict/list consistent)
- Quarantine logging + status tracking
- Batch operation CSRF + stats refresh
- Audit Log status badges (FP/DEL/ALERT/ACTIVE)
- Scanner cross-page selection + quarantine UX
- Bilingual README (EN/ZH)
- SVG logo

### Removed
- Old Trident scripts (start.bat / stop.bat / install.py) — replaced by CLI

---

## [Trident v1.9.5] — 2026-06-28 (Archived)

Final Trident release before DDD migration. See `legacy-trident-v1.9.5` git tag.

**Key accomplishments (2025–2026):**
- Blueprint split (3767→2155 lines), JS modularization (1455→561)
- SQLite backend (WAL mode) + DualWriteRepository
- Plugin Manager + stdout_logger + 4 WAF adapters
- Log Heuristic Engine + SIEM CEF/JSON Lines exporter
- Memory Shell Tracer + reference tools
- Gunicorn production config + core test suite (79 tests)
- Code quality fixes: SQL injection, thread safety, timezone handling

---

## Version Scheme

Anteumbra follows CalVer-inspired versioning:

```
v<major>.<minor>.<patch>

major: Architecture migration milestone
minor: Feature group / surgery cycle
patch: Bug fix / optimization
```

- **v1.0.x**: DDD migration + surgery cycle (2026-06/07)
- **v1.1.x**: Multi-site + Geo-IP (planned)
- **v2.0.x**: Async EventBus + Pydantic Schema (planned)
