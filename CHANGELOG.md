# Anteumbra Changelog

> All notable changes to Anteumbra, the Web Perimeter Threat Intelligence platform.

---

## [1.0.5-dev] — 2026-07-03

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
- **P0-3: ScanResult triple definition** — `domain/entities.py`, `domain/detector.py`, `infrastructure/models.py` → unified dataclass in `domain/entities.py` (10 fields merged)
- **P2-3: html_escape** — custom implementation → `markupsafe.escape()` (Flask standard)
- **P2-4: EmergencyScanner** — `advanced_bypass` module ImportError → safe fallback
- **P2-5: DummyEngine** — `__getattr__` implicit return → explicit `compiled_rules`/`match` methods
- **Jinja2 syntax errors** × 2: nested `{{ }}` in notify_config.html, `_()` inside string literal in monitor_content.html
- **Version drift**: config.toml (1.0.1) / __init__.py (1.0.2) / pyproject.toml (1.0.4) → all unified

---

## [1.0.4] — 2026-07-03

### Added
- **SQLite FK 外键约束** (3 条): `registry.quarantine_id → quarantine.quarantine_id`, `registry.profile_id → threat_profiles.profile_id`, `block_ledger.profile_id → threat_profiles.profile_id` — 全部 `ON DELETE SET NULL`
- **SQLite 索引优化** (13 列索引): 新增 `idx_registry_profile`, `idx_registry_deleted`, `idx_block_ledger_time`, `idx_threat_profiles_status`, `idx_threat_profiles_last_seen`
- **自动 Schema 迁移**: `_run_migrations()` — 检测 FK 缺失 → CREATE temp → INSERT data → DROP old → RENAME, 无需手动重建数据库
- **Dockerfile**: 多阶段构建 (Python 3.12-slim builder → runtime), 非 root 用户 `anteumbra`, HEALTHCHECK, gunicorn 4 workers
- **`.dockerignore`**: 排除 git/cache/tests/IDE 文件/data/*.db/logs
- **`.gitignore`**: 新增 `*_log.txt` 和 `screenshots/` 模式

### Changed
- SCHEMA 表创建顺序重排: `quarantine → threat_profiles → registry → block_ledger → scan_history → wal_events` (满足 FK 依赖)
- `pyproject.toml`: Python >=3.8 → >=3.10, classifiers 完善, full/dev optional-deps, playwright 加入 dev deps
- `README.md` + `README_zh.md`: badges v1.0.1→v1.0.4, tests 79→144, Docker 部署章节, 双向链接/Block Ledger 加入关键能力
- E2E UI 测试: 全部迁移至 `tests/e2e_ui/`, function-scoped Flask server

### Fixed
- **SSE 阻塞 Playwright 导航**: `about:blank` → settle → target URL 模式, 5 个超时测试修复
- **Settings 页面超时**: try/except 移除, about:blank timeout 提升至 10s
- **Login 测试**: werkzeug hash monkey-patch 修复认证

---

## [1.0.3] — 2026-07-02

### Added
- **存储层 Repository bridge 全覆盖**: `block_ledger` 接入统一 Repository 接口
- **Block Ledger**: 封禁台账 JSON 持久化 (`data/block_ledger.json`), IP 审计追踪
- **Blocklist 页面**: 内联编辑备注, JSON/CSV 导出, 来源过滤 (auto/manual)
- **双向链接**: Profile ↔ Records ↔ Quarantine 交叉导航
- **广播配置**: `[ip_blocker]` 默认启用, stdout 设备

### Changed
- `admin_bp.py`: Blueprint 拆分 → records_bp / profiles_bp / blocklist_bp
- `profile_detail.html`: 新增 "LINKED DETECTION RECORDS" 区域
- `record_detail.html`: 关联 Profile 跳转
- 导航栏: Profiles 和 Settings 之间新增 Blocklist 入口

---

## [1.0.2] — 2026-07-01

### Added
- **suspicious_registry 事件化**: 6 写操作 (add/update/mark_false_positive/delete/quarantine/restore) 全部走 `pm.emit()`
- **monitor 双轨弥合**: 7 处直接调用 → emit + 3 bridge 插件
  - `quarantine_handler`: 监听 → 自动隔离
  - `notifier_handler`: 监听 → 告警通知
  - `threat_graph_handler`: 监听 → 画像更新
- **dispatch 超时机制**: 同步事件 30s 超时保护
- **E2E 后端测试套件**: 21 测试 (detect→quarantine 5, IP block 8, WAF profiling 4, file clustering 4)
- **Playwright UI 测试套件**: 34 测试 (Dashboard/System/Settings/Login/Navigation/Smoke)
- **兼容性测试**: 9 测试 (v1.7.8 API 兼容)
- WAL Manager 页面 + Session Manager 页面
- Config Watcher SSE 实时推送

### Changed
- `admin_bp.py` (~3500 行) Blueprint 拆分: admin_bp / quarantine_bp / yara_bp / metrics
- Registry 格式标准化: dict→list 转换
- 隔离日志: "隔离中" 提示 + DELETE → QUARANTINE FILE

### Fixed
- 隔离/误报静默失败 (Registry 格式不一致)
- 测试模块级副作用隔离 (sys.path/os.chdir 污染)
- `e2e_test.py` pytest 收集冲突 (def test → def run_test)

---

## [1.0.1] — 2026-06-30

### Added
- **PluginManager**: emit() 异步 Fire-and-Forget (queue.Queue worker thread), dispatch() 同步调用
- **count() 白名单**: 防枚举 + registry_adapter 迁移
- **应用工厂模式**: `create_app()` Flask factory

### Changed
- emit/dispatch 语义分离 (异步 Fire-and-Forget vs 同步)
- 版本号: 2.0.0.dev0 → 1.0.0.dev0

### Fixed
- PluginManager worker thread 死锁 (RLock 嵌套)
- `mark_false_positive` 后 Registry 不刷新

---

## [1.0.0] — 2026-06-28

### Added
- **Trident → Anteumbra 重命名**: pip 包 `anteumbra`
- **DDD 四层架构**: domain/ application/ infrastructure/ interfaces/
- **EDA 事件驱动**: PluginManager + 事件订阅/分发
- 统一 CLI: `anteumbra run|start|stop|status|config`
- Flask-Babel i18n (en/zh, auto-detect)
- Registry 格式标准化 (dict/list 一致)
- Quarantine logging + 状态追踪
- 批量操作 CSRF + stats 刷新
- Audit Log 状态 badges (FP/DEL/ALERT/ACTIVE)
- Scanner 跨页面选择 + quarantine UX
- 双语 README (EN/ZH)
- SVG logo

### Removed
- 旧 Trident 脚本 (start.bat / stop.bat / install.py) — 由 CLI 替代

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
