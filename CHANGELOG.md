# Anteumbra Changelog

> All notable changes to Anteumbra, the Web Perimeter Threat Intelligence platform.

[中文](CHANGELOG_cn.md)

---

## [Unreleased]

No changes yet.

---

## [1.0.31] - 2026-07-19

### Fixed
- Made bare `anteumbra config` display subcommand help without entering the
  template-creation flow, preventing an accepted prompt from replacing a
  runtime's `config.toml` and `.env`.
- Limited `anteumbra install --force` to registration and non-empty-directory
  checks while always preserving existing config and secrets. Intentional
  resets now require `anteumbra config init --force`.
- Prevented an unmarked Git source checkout from shadowing the host's registered
  runtime when using the installed CLI. Explicit `--home` remains the highest
  priority.

### Changed
- Added `-h` and `--home INSTANCE_DIR` at the top-level CLI. Help now separates
  Python package installation from the explicitly located runtime and includes
  complete first-install examples.
- Removed the legacy `start.bat` and `stop.bat`, which hard-coded a local Python
  path and killed processes by port. Governance tests prevent them from
  returning; `anteumbra start/stop` is the only supported lifecycle CLI.

### Tests
- Added regressions for CLI help, side-effect-free bare config, explicit
  runtime-home precedence, force-install config preservation, and architecture
  documentation accuracy.
- Final source passes 507 non-browser tests, all 41 Playwright UI tests, Ruff,
  a 116-module import sweep, and Wheel/source parity. Clean Wheel and editable
  source installs both passed instance startup checks.
- The 1.0.31 Docker image passed health, admin login, file-monitor detection,
  site-qualified Registry, Web quarantine, and restore checks.
- The official PyPI Wheel matches its published SHA-256 metadata and passed
  the 204-file package inventory, clean dependency install, 116-module import,
  config-preservation, and independent-port startup checks.

---

## [1.0.30] - 2026-07-19

### Fixed
- Removed SQLite-only identity and serialization fields while normalizing
  Registry recovery records, so adapter metadata can no longer leak into the
  authoritative JSON dataset.
- Reconciled the SQLite shadow's actual stored keys before writing current
  site-qualified Registry identities. Upgrades from path-only keys no longer
  collide on the shadow table's auto-increment `id` or leave stale recovery
  rows behind.

### Tests
- Current source passes `499` non-browser tests, all `41` Playwright UI tests,
  Ruff, `git diff --check`, and an import sweep of `116` package modules.
- Added a real SQLite recovery regression covering legacy-key deletion,
  canonical site-key creation, clean JSON output, and warning-free shadow sync.

---

## [1.0.29] - 2026-07-19

### Fixed
- Discovered the container's exact local gateway during Docker startup and
  added it only when the admin allowlist still has its localhost default; the
  documented loopback port mapping can now log in from the host without opening
  the dashboard to a wildcard network.
- Ignored delayed filesystem delete events when the same path already exists,
  so a quick quarantine/restore cycle cannot overwrite the restored Registry
  state with `file_exists=false`.
- Forced POSIX line endings for shell assets and normalized the Docker
  entrypoint during image construction, so images built from Windows clones no
  longer fail at startup with a misleading "no such file" error.
- Disabled Waitress' `Server` identifier in addition to stripping application
  headers, preventing the production HTTP response from advertising Anteumbra.
- Keyed monitor logger ownership, `[site=<id>]` attribution, and
  `logs/<site_id>/monitor.log` paths by stable site ID; display-name log
  directories from both historical raw and sanitized layouts are migrated and
  retained as history, so renaming a site no longer hides logs or creates a
  second stream.
- Canonicalized configured site display names by stable `website.id`, so a
  rename refreshes Registry/quarantine metadata without changing ownership.
- Reserved the `legacy` site ID for unassigned records and made config
  validation warn when an older config derives a rename-sensitive ID from name.
- Prevented deleted modules in a stale local `build/lib` tree from silently
  re-entering Wheels; CI and publishing now reject files absent from `src`.
- Rejected login forms with a missing password before hash verification and
  rate accounting, preventing malformed POSTs from raising a Werkzeug 500.
- Isolated ThreatGraph profiles, IP/file reputation, persistence, WAF ingestion,
  Registry linking, and public queries by `site_id`; ambiguous cross-site lookups
  no longer guess a site.
- Closed partially initialized plugin resources and made startup failures
  explicit instead of leaking worker state or returning a successful CLI exit.
- Made Waitress shutdown close SSE and keep-alive channels, wake the event loop,
  and stop its task dispatcher; browser-driven runtimes no longer consume the
  full shutdown timeout or leave server workers behind.
- Centralized memory-probe degradation inside Metrics and removed Web/plugin
  access to Metrics, cluster, ThreatGraph, and Notifier private state.

### Changed
- Routed dashboard and SSE history through runtime logging/SSE ports instead
  of hard-coded `logs/` and `data/` paths.
- Guarded scripted `website.id` changes behind an explicit acknowledgement;
  legacy `website.site_id` aliases are canonicalized, and changing
  `website.name` remains the supported rename operation.
- Replaced module-global launcher lifecycle state and `start_all`/`stop_all`
  facades with one instance-owned `RuntimeLifecycle` and typed `RuntimeState`.
- Moved login-attempt throttling from mutable Web blueprint globals into a
  `RuntimeContainer`-owned `LoginRateLimiter`; independent app/test runtimes no
  longer share counters, and successful authentication resets only that client.
- Added focused Domain Protocols for plugins, scanner/YARA, file clusters,
  ThreatGraph, notifier, SIEM, SSE, WAL, and WAF; `RuntimeContainer` now marks
  required services as required and retains `None` only for disabled capabilities.
- Removed unused runtime retention of HashEngine and MemoryShellTracer objects;
  FileClusterEngine now exposes immutable, thread-safe snapshots.
- Standardized active Chinese documentation names on `*_cn.md`, added Chinese
  roadmap/changelog/release/toolkit documents, and added documentation/link
  governance tests.
- Made CI run Ruff and fail on broken wheel CLI or Docker health smoke checks.
- Pinned pytest to the `src` layout and made test startup reject an installed
  `site-packages` copy, so source regressions cannot pass against an old Wheel.

### Tests
- Current source passes `498` non-browser tests, all `41` Playwright UI tests,
  Ruff, `git diff --check`, and an import sweep of `116` package modules.
- Added regressions for instance-owned lifecycle shutdown, service boundaries,
  site-qualified file/profile lookup, immutable cluster views, notification API,
  WAF source metadata, documentation parity, strict CI, and Waitress shutdown
  with an open keep-alive connection.
- Added deterministic unit and HTTP regressions for login attempt windows,
  per-client reset, independent runtimes, successful-login reset, and GET bypass.
- Added regressions for stable-ID site renames, canonical historical display
  names, reserved/derived ID validation, and explicit CLI identity changes.
- Added regressions for stable site log paths, legacy migration conflicts,
  multi-site history attribution/order, escaped rendering, and an absent
  production `Server` header; deployment tests also enforce Docker's POSIX
  entrypoint, loopback port binding, and gateway allowlist contracts.
- Added a monitor regression proving that delayed delete events cannot hide a
  file which quarantine restore has already put back.

---

## [1.0.28] - 2026-07-18

### Fixed
- Made Registry identity site-qualified so the same file path in two websites
  can be recorded, marked, restored, or quarantined without cross-site
  mutation.
- Routed moved-file detection through the normal queued scan path, preserving
  attribution, alerting, metrics, quarantine, and SIEM behavior.
- Partitioned notification batches, metrics, dashboard summaries, scanner
  history, and quarantine operations by explicit site ownership.
- Corrected JSON/SQLite persistence semantics: valid JSON is authoritative,
  SQLite is a shadow and recovery source, and site-qualified SQLite keys can
  no longer corrupt JSON Registry paths.
- Removed stale SQLite-primary reads from the block ledger and threat graph;
  old shadow data can no longer replace healthy JSON state.
- Imported the `datetime` type used by model forward annotations so reflective
  type resolution is valid.
- Made CLI background startup wait for a successful HTTP health response,
  rather than treating a pre-startup Waitress socket bind as readiness.
- Fixed SSE shutdown on Windows by preserving the stream termination signal
  until the generator consumes it before Waitress closes its trigger.
- Bounded SQLite shadow lock waits and serialized in-process schema setup so
  a shadow-store contention cannot stall authoritative JSON workflows.

### Changed
- Added `SiteIdentity`, `SiteResolver`, runtime service ports/adapters, and a
  dashboard read-model service for explicit multi-site composition.
- Added SQLite site metadata and indexes while preserving full raw record data
  for compatibility.
- Documented site ownership, runtime composition, event propagation, and
  JSON-authoritative persistence in both architecture and user manuals.
- Added Ruff as a development dependency with a project-wide fatal/undefined
  name quality gate; broader legacy style cleanup is now touch-on-change.

### Tests
- Added regression coverage for site-qualified Registry identity, per-site
  scan options, notification batching, dashboard summaries, moved-file queue
  handling, restore isolation, JSON-authoritative ledger/graph reads, and
  SQLite shadow storage.
- Added HTTP startup-readiness and graceful-SSE-disconnect regressions.
- Passed `488` non-browser tests with one intentional live-WAF skip and all
  `41` browser tests. Built a wheel, completed clean wheel installation and
  editable-source installation, and verified both live health endpoints.

## [1.0.27] - 2026-07-17

### Fixed
- Made Docker consume the bundled `src/anteumbra/config.toml` template and added a regression guard that keeps the source-runtime and packaged templates identical. Default Docker instances now load the SIEM event bridge instead of reporting SIEM enabled while keeping detection events local.
- Made Windows background startup use unbuffered daemon output and require two consecutive listener checks before reporting success, so `data/anteumbra.log` is useful during real startup failures.
- Resolved runtime-root precedence so a local `config.toml` owns its instance before any registered global installation can be selected.
- Made file-monitor and plugin queues bounded with synchronous backpressure fallbacks; timed-out plugin handlers are capped and skipped while unhealthy instead of accumulating daemon threads.
- Added startup baseline scanning for existing monitored scripts and explicit monitor-worker shutdown.
- Prevented a site with disabled access-log monitoring from generating a missing-default-Nginx-log warning for every file detection.
- Prevented an operator-restored file from being scanned, alerted, exported to SIEM, registered, or re-quarantined again during the 30-second restore guard window.
- Restricted forwarded-header trust to configured proxy peers/CIDRs and made allowed-IP checks CIDR-aware.

### Changed
- Replaced the obsolete Gunicorn runtime path with Waitress in package metadata, Docker, CLI deployment guidance, and user manuals.
- Added `siem_handler`, which bridges `record_added` events to the configured SIEM exporter and reports a degraded runtime capability if that bridge is disabled.
- Reworked YARA loading to compile every `.yar` file independently, retain the last valid ruleset on failed reload, and isolate per-file runtime failures. The large THOR ruleset is split into nine verified shards; the bundled set now contains 27 rule files.
- Added generic PHP, ASP, ASPX, and JSP behavior rules while narrowing the generic `eval` rule to avoid normal JSP false positives.
- Updated deployment, architecture, and configuration guidance for bounded queues, baseline scans, trusted proxies, Waitress, and explicit YARA reload behavior.

### Tests
- Added regression coverage for daemon readiness, local-runtime root resolution, proxy validation, Waitress lifecycle, YARA fault isolation, monitor queue backpressure, disabled-log-monitor attribution, restored-file de-duplication, SIEM bridging, and runtime health.
- Validated a real Windows clean runtime: background start/health/stop, PHP YARA detection, Registry record, local alert path, JSON Lines SIEM export, automatic quarantine, CSRF-protected restore, and restore de-duplication.
- Rebuilt and ran the Docker image after the template fix: default health is healthy, the SIEM bridge is ready, and a PHP test sample produced a YARA hit, Registry record, and JSON Lines SIEM event without executing the sample.
- Validated a fresh editable source install with a new venv and runtime instance, including force-migration, rule copying, background start, health, and stop. Passed `464` non-UI tests with one explicit skip and `5` current Playwright UI smoke tests.

## [1.0.26] - 2026-07-17

### Fixed
- Reworked startup orchestration so every enabled website receives its own file and access-log monitor, startup failures are reported, and all started resources are stopped deterministically.
- Added an acknowledged JSONL event tailer with cursor persistence, file rotation/truncation handling, and dead-letter output so malformed or unprocessable WAF events cannot stall profiling.
- Made quarantine, restore, and permanent-delete workflows compensate file operations when Registry updates fail; batch APIs now report per-item failures with HTTP `207`.
- Made auto-quarantine fail conservatively when configuration or the recently-restored guard is unavailable.
- Removed normal SSE connection noise, merged historical logs across enabled sites, added heartbeats, and exposed notification delivery state through metrics and the dashboard.
- Disabled outbound notification channels in fresh templates until both configuration and credentials are complete; enabled TLS verification for WeChat delivery by default.
- Made background CLI startup wait for both the PID and HTTP listener, log daemon output consistently, and return non-zero when readiness fails.
- Made `anteumbra stop` verify the Windows `taskkill` result and actual process exit; failed termination now returns non-zero and preserves the PID file for diagnosis or retry.
- Generated a persistent high-entropy Flask secret and 16-character initial password for both `install` and `config init` without overwriting unrelated `.env` values.
- Mapped legacy Flask-Session `filesystem` configuration to the supported `cachelib` backend.
- Made manual scanner states explicit, restored the scan form after terminal states, refreshed history automatically, and preserved zero-second durations.
- Made scanner cancellation wait for backend confirmation, reported invalid targets as failures, and applied the extension filter entered in the UI.
- Prevented delayed or stale dashboard navigation responses from replacing the page most recently selected by the operator.
- Kept a complete instance installation usable when the optional user-level instance registry is read-only, with a clear warning instead of a traceback.
- Corrected successful monitor startup and configuration diagnostics that were incorrectly recorded as `CRITICAL` events.
- Forced UTF-8 for the background runtime process so Windows daemon logs preserve Chinese diagnostics instead of writing local-code-page mojibake.
- Aligned Docker's manually installed runtime dependencies with `pyproject.toml`, including `cachelib`, and quoted version constraints so the shell cannot treat `>` as output redirection.

### Changed
- Added application services for runtime health, access-log analysis, transactional quarantine, and resilient JSONL consumption.
- Added Nginx, Apache, and Tomcat access-log analysis per configured site instead of coupling web routes directly to parser infrastructure.
- Included `yara-python` in the base package; the legacy `yara` extra remains an empty compatibility alias, while `full` adds only `ssdeep` and `py-tlsh`.
- Added runtime capability reporting that distinguishes optional degraded features from critical configuration, Registry, and WAL failures.
- Unified public metrics, minimal load-balancer, and authenticated diagnostic health endpoints through one Application health assessment; optional degradation stays HTTP `200`, while critical probes return `503`.

### Tests
- Replaced mocked-success browser batch tests with real backend workflows that verify source files, Registry records, and Quarantine state.
- Added lifecycle, multi-site, JSONL poison-message, notification-safety, runtime-health, log-analysis, and quarantine compensation regression coverage.
- Passed `428` non-UI tests with one explicit live-WAF skip and all `41` Playwright UI tests (`469` passed total).
- Verified the final wheel through a fresh non-editable install, instance creation, configuration validation, YARA loading, background start/health/stop, UTF-8 daemon logs, and in-app browser workflows.
- Built and ran the v1.0.26 Docker image as the non-root `anteumbra` user, passed dependency and health checks, and confirmed a monitored PHP webshell produced a two-rule YARA hit, Registry record, alert metrics, and duplicate-event suppression.

## [1.0.25] - 2026-07-11

### Fixed
- Rebuilt the Docker runtime around `/opt/venv` so the non-root `anteumbra` user can execute installed console scripts.
- Changed the container default command to start the full `anteumbra run` runtime instead of only a bare Gunicorn web app.
- Added a Docker entrypoint that creates first-start runtime defaults, prints the initial admin password, and keeps non-runtime commands such as `anteumbra --version` clean.
- Adjusted Docker defaults to monitor `/app/sites/default` and disable the demo MockWAF poller to avoid noisy connection failures.

### Verified
- Built the Docker image, started a container on host port `18080`, checked `/api/v1/health`, and confirmed the reported version is `1.0.25`.
- Copied a PHP webshell probe into the container's monitored directory and verified a YARA hit with `scan_total=1` and `scan_suspicious=1`.

### Docs
- Updated README and user manuals with the working Docker deployment flow and clarified optional fuzzy hash engine behavior.

---

## [1.0.24] - 2026-07-11

### Fixed
- Added Tomcat access-log analysis support, including `localhost_access_log.*.txt` style date-rotated logs.
- Added CLI access-log presets for `nginx`, `apache`, `tomcat`, `custom`, and `none`.
- Added regression coverage for Tomcat log parsing and deployment configuration behavior.

### Docs
- Documented access-log setup commands in the user manuals and README.

---

## [1.0.23] - 2026-07-11

### Fixed
- Exposed access-log analysis status and audit-facing signals in the web dashboard.
- Reduced noisy SSE log stream behavior and exposed notifier delivery state for operators.
- Added regression coverage for log-stream behavior.

---

## [1.0.22] - 2026-07-11

### Fixed
- Made CLI startup honor the configured admin bind host and port.
- Added first-run configuration commands and validation-oriented setup flow.
- Improved documentation for the unified PyPI/source runtime model.

---

## [1.0.21] - 2026-07-11

### Fixed
- Made first-run runtime startup more reliable from a fresh instance directory.
- Aligned launcher behavior, bundled config defaults, and CLI startup paths.
- Added deployment regression coverage around fresh instance startup.

---

## [1.0.20] - 2026-07-11

### Changed
- Established the 1.0.20 cleanup baseline before larger architecture work.
- Tightened architecture/import boundary expectations.
- Cleaned up release documentation, plugin contracts, static/module organization, and several inherited project edges.

---

## [1.0.19] - 2026-07-11

### Fixed
- Made `yara-python` an actual optional dependency by allowing the web app and YARA management routes to boot without it.
- Added regression coverage for creating the Flask app when `yara-python` is absent.

### Docs
- Documented `anteumbra[yara]` and `anteumbra[full]` for users who need compiled YARA validation/scanning.

---

## [1.0.18] - 2026-07-11

### Fixed
- Updated package license metadata to the modern SPDX string form and removed the deprecated license classifier.
- Raised the build backend requirement to `setuptools>=77.0` to match the license metadata format.

### Docs
- Updated the user manuals to use the unified `anteumbra install <instance-dir>` flow for both PyPI and source installs.

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

Anteumbra uses milestone.feature.bugfix versioning:

```
v<milestone>.<feature>.<bugfix>

milestone: Architecture or product generation
feature: User-facing feature group
bugfix: Bug fix, reliability, optimization, or compatible cleanup
```

- **v1.0.x**: DDD migration + surgery cycle (2026-06/07)
- **v1.1.x**: Multi-site operations + extension SDK (planned)
- **v2.0.x**: Async EventBus + Pydantic Schema (planned)
