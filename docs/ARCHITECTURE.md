# Anteumbra Technical White Paper v1.0.25

> **Target audience**: Developers, architects, security engineers. This document describes Anteumbra's internal architecture, design decisions, data model, and extension guide.

[中文](ARCHITECTURE_zh.md)

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [DDD Four-Layer Architecture](#2-ddd-four-layer-architecture)
3. [Event-Driven Architecture (EDA)](#3-event-driven-architecture-eda)
4. [Database Design](#4-database-design)
5. [Data Flow Panorama](#5-data-flow-panorama)
6. [Plugin System](#6-plugin-system)
7. [Key Algorithms](#7-key-algorithms)
8. [Security Design](#8-security-design)
9. [Development Decision Guide](#9-development-decision-guide)

---

## 1. Architecture Overview

Anteumbra adopts a hybrid model of **Domain-Driven Design (DDD) four-layer architecture** + **Event-Driven Architecture (EDA)**.

```
┌──────────────────────────────────────────────────┐
│                  INTERFACES Layer                  │
│  Flask Blueprints / CLI / Templates / SSE         │
│  ┌─────────┐ ┌──────────┐ ┌──────────────────┐   │
│  │ admin_bp │ │records_bp│ │  ... 11 blueprints │   │
│  └────┬─────┘ └────┬─────┘ └────────┬─────────┘   │
│       │             │               │              │
├───────┼─────────────┼───────────────┼──────────────┤
│       ▼             ▼               ▼              │
│              APPLICATION Layer                       │
│  ┌──────────────┐ ┌──────────────┐ ┌───────────┐  │
│  │PluginManager │ │ 16 Services  │ │ Event Bus │  │
│  │ (singleton)  │ │ (thin facade)│ │ (emit/dis)│  │
│  └──────┬───────┘ └──────┬───────┘ └─────┬─────┘  │
│         │                │               │         │
├─────────┼────────────────┼───────────────┼─────────┤
│         ▼                ▼               ▼         │
│              INFRASTRUCTURE Layer                    │
│  ┌──────────┐ ┌──────────┐ ┌──────────────────┐   │
│  │Detection │ │Monitoring│ │Persistence       │   │
│  │ YARA     │ │ FileWatch│ │ JSON / SQLite    │   │
│  │ Clustering│ │ LogMon  │ │ DualWrite        │   │
│  │ Scanner  │ │ Notifier │ │ WAL Manager      │   │
│  └──────────┘ └──────────┘ └──────────────────┘   │
│                                                     │
├─────────────────────────────────────────────────────┤
│                   DOMAIN Layer                        │
│  ┌──────────┐ ┌──────────┐ ┌──────────────────┐   │
│  │ Entities │ │ Ports    │ │ Value Objects    │   │
│  │FileRecord│ │Plugin ABC│ │ ScanResult       │   │
│  │Attacker  │ │Repository│ │ DomainEvent      │   │
│  │Profile   │ │Detector  │ │ AlertMessage     │   │
│  └──────────┘ └──────────┘ └──────────────────┘   │
└─────────────────────────────────────────────────────┘
```

### Core Design Principles

1. **Dependency direction**: Interfaces → Application → Infrastructure; all layers may depend on Domain
2. **Domain has zero external dependencies**: The Domain layer does not import any Anteumbra modules
3. **Application is the orchestration layer**: Contains no business logic, only module orchestration and event routing
4. **Infrastructure implements Domain interfaces**: Repository, Detector, Notifier are all implementations of ABCs defined in Domain
5. **Event bus decoupling**: Infrastructure modules communicate with each other via EDA events, never through direct calls

---

## 2. DDD Four-Layer Architecture

### 2.1 Domain Layer

**Responsibility**: Define business entities, value objects, domain events, and port interfaces.

**Files**:
```
domain/
├── entities.py       # FileRecord, ScanResult, QuarantineRecord, DetectionSource
├── plugin.py         # Plugin (ABC), DomainEvent (frozen dataclass)
├── detector.py       # Detector (ABC), ScanRequest
├── notifier.py       # Notifier (ABC), AlertMessage, AlertLevel
├── event_source.py   # EventSource, PollableEventSource, StreamEventSource (ABCs)
├── waf_source.py     # WAFEvent
└── repository.py     # Repository, EventRepository (ABCs)
```

**Core entity relationships**:

```
FileRecord ──→ DetectionSource (PASSIVE | ACTIVE | WAF | LOG | MEMORY)
    │
    └── FileStatus (ACTIVE | QUARANTINED | DELETED | FALSE_POSITIVE)

ScanResult ──→ FileRecord (via to_record())

DomainEvent (frozen)
    ├── event_type: str
    ├── timestamp: float
    ├── source: str
    └── payload: Dict[str, Any]
```

**Design constraints**:
- The Domain layer **must never** import from infrastructure, application, or interfaces
- All domain types are exported uniformly through `domain/__init__.py`
- `DomainEvent` is a frozen dataclass — events are immutable

### 2.2 Application Layer

**Responsibility**: Orchestrate business processes, manage plugin lifecycle, provide service facades for Infrastructure.

**Core components**:

#### PluginManager (Event Bus Core)

```python
class PluginManager:
    """Singleton, thread-safe"""
    _instance: Optional[PluginManager]
    _rwlock: threading.RLock         # protects all dicts
    _plugins: Dict[str, Plugin]      # all registered plugins
    _detectors: Dict[str, Detector]  # detectors
    _notifiers: Dict[str, Notifier]  # notifiers
    _event_sources: Dict[str, EventSource]
    _event_handlers: Dict[str, List[Plugin]]  # event_type → handlers
    _event_queue: queue.Queue        # Fire-and-Forget queue
    _abandoned_threads: List[Thread] # timed-out zombie thread tracking
```

**API**:
- `emit(event_type, source, payload) → None` — Async Fire-and-Forget (pushes to queue, returns immediately)
- `dispatch(event) → List[DomainEvent]` — Synchronous distribution (each handler has a 30s timeout)
- `register(plugin) / unregister(name)` — Plugin lifecycle management

#### 16 Application Service Modules

Each service is a thin facade that re-exports public APIs from infrastructure:

```python
# application/sse_service.py (example)
from anteumbra.infrastructure.utils.sse_manager import (
    register_sse_client, unregister_sse_client,
    trigger_registry_update, persist_log_line, ...
)
__all__ = ["register_sse_client", ...]
```

**Purpose**: Fix DDD dependency direction. The Interfaces layer accesses Infrastructure through the Application layer instead of importing directly.

### 2.3 Infrastructure Layer

**Responsibility**: Implement the port interfaces defined in Domain, providing concrete technical capabilities.

**Sub-modules**:

| Sub-module | Files | Responsibility |
|------------|-------|---------------|
| **Detection** | scanner, yara_engine, file_cluster, hash_engine, manual_scanner, decoder, memory_shell_tracer | File scanning, YARA matching, similarity clustering |
| **Monitoring** | monitor, log_monitor, log_analyzer, metrics, notifier, siem_exporter | File monitoring, log analysis, alerting, SIEM export |
| **Persistence** | json_repository, sqlite_repository, `__init__` | Dual storage backends + factory |
| **Config** | registry (ConfigRegistry), loader (TOML+env), version | Configuration management |
| **Utils** | sse_manager, password_utils, platform_utils, logger_factory, path_utils | Utility library |
| **Core** | suspicious_registry, quarantine, threat_graph, block_ledger, wal_manager, ip_blocker, decay_engine | Core business modules |

### 2.4 Interfaces Layer

**Responsibility**: Expose HTTP APIs, web interface, and CLI commands to the outside world.

**Web Blueprints (12)**:

| Blueprint | URL Prefix | Route Count | Responsibility |
|-----------|------------|:-----------:|---------------|
| `admin_bp` | `/admin` | ~12 | Dashboard, authentication, account management |
| `records_bp` | `/admin` | ~8 | Detection record CRUD + batch operations |
| `quarantine_bp` | `/admin` | ~10 | Quarantined file management |
| `profiles_bp` | `/admin` | ~7 | Threat profiling + file clustering |
| `blocklist_bp` | `/admin` | ~6 | IP block ledger |
| `yara_bp` | `/admin/yara` | ~8 | YARA rule management |
| `scanner_bp` | `/admin` | ~7 | Active scanning |
| `settings_bp` | `/admin` | ~13 | Settings + SIEM export |
| `monitor_bp` | `/admin` | ~18 | Real-time monitoring + log streaming |
| `system_bp` | `/admin` | ~9 | System management (4 quadrants) |
| `metrics_bp` | `/api/v1` | ~5 | Health checks + metrics API |
| `_shared.py` | — | — | Shared utility functions |

---

## 3. Event-Driven Architecture (EDA)

### 3.1 Event Bus

Anteumbra uses an **implicit event bus** pattern — `PluginManager` serves as both the plugin container and the event router.

```
Emitter (Infrastructure modules)                  Consumer (Plugin)

pm.emit("alert_requested", ...)  ──→  stdout_logger.on_event()
                                   ├─→  notifier_handler.on_event()

pm.emit("file_quarantined", ...) ──→  stdout_logger.on_event()
                                   ├─→  quarantine_handler.on_event()

pm.emit("record_added", ...)     ──→  threat_graph_handler.on_event()

pm.emit("registry_changed", ...) ──→  threat_graph_handler.on_event()

pm.emit("block_executed", ...)   ──→  stdout_logger.on_event()

pm.emit("wal_archived", ...)     ──→  stdout_logger.on_event()
pm.emit("wal_replayed", ...)     ──→  stdout_logger.on_event()
```

### 3.2 emit() vs dispatch()

| Feature | `emit()` | `dispatch()` |
|---------|---------|-------------|
| Semantics | Fire-and-Forget | Synchronous request-response |
| Returns | `None` (immediately) | `List[DomainEvent]` (waits for completion) |
| Execution | Async (queue → worker thread) | Sync (calling thread) |
| Timeout | None (unbounded queue) | 30s per handler |
| Use case | Notifications, state changes | Queries, chained events |

### 3.3 Event Flow

```
1. Infrastructure module detects an event
   monitor.py: _emit_alert()
        │
2. Lazy-import PluginManager (avoids circular imports)
   from anteumbra.application.plugin_manager import get_plugin_manager
        │
3. Emit event
   pm.emit("alert_requested", "monitor", {...})
        │
4. Event enqueued
   DomainEvent → _event_queue (queue.Queue)
        │
5. Worker thread picks up event
   _event_worker(): event = _event_queue.get()
        │
6. Dispatch to registered handlers
   dispatch(event):
     for plugin in _event_handlers[event.event_type]:
         t = Thread(plugin.on_event, event)
         t.start()
         t.join(timeout=30.0)
        │
7. Handle
   plugin.on_event(event) → Optional[List[DomainEvent]]
```

### 3.4 Event Type Catalog

| Event Type | Emitter | Handlers |
|------------|---------|----------|
| `alert_requested` | monitor.py, quarantine_handler | stdout_logger, notifier_handler |
| `file_quarantined` | monitor.py | stdout_logger, quarantine_handler |
| `file_scanned` | monitor.py | stdout_logger |
| `block_executed` | block_ledger.py | stdout_logger |
| `record_added` | suspicious_registry.py | threat_graph_handler |
| `registry_changed` | suspicious_registry.py (6 sites) | threat_graph_handler |
| `threat_graph_updated` | threat_graph_handler | stdout_logger |
| `wal_archived` | wal_manager.py | stdout_logger |
| `wal_replayed` | wal_manager.py | stdout_logger |

---

## 4. Database Design

### 4.1 Storage Architecture

```
Config-Driven Backend Selection
        │
        ├── "json"    → JsonRepository
        ├── "sqlite"  → SqliteRepository
        └── "both"    → DualWriteRepository
                            ├── JsonRepository (write + fallback)
                            └── SqliteRepository (preferred read)
```

### 4.2 ER Diagram

```
┌─────────────────┐
│   quarantine    │
│─────────────────│
│ PK id           │
│ UK quarantine_id│◄──────────────────────┐
│    original_path│                      │
│ quarantine_path │                      │ FK (ON DELETE SET NULL)
│    rule_name    │                      │
│    features     │              ┌───────┴──────────┐
│    file_size    │              │     registry      │
│    status       │              │───────────────────│
│    created_at   │              │ PK id             │
│    restored_at  │              │ UK record_id      │
└─────────────────┘              │    file_path      │
                                 │    display_name   │
                                 │    detected_at    │
┌─────────────────┐              │    features       │
│ threat_profiles │              │    file_exists    │
│─────────────────│              │    file_size      │
│ PK id           │              │    comm_count     │
│ UK profile_id   │◄─────────────│    first_seen_ip  │
│ ua_fingerprint  │   FK (SET    │    alerted        │
│ tool_signature  │    NULL)     │    marked_fp      │
│ risk_score      │              │ FK quarantine_id  │──→ quarantine
│ ip_pool         │              │ FK profile_id     │──→ threat_profiles
│ target_files    │              │    detection_src  │
│ target_urls     │              │    deleted_at     │
│ attack_chain    │              │    raw_json       │
│ status          │              │    created_at     │
│ decay_factor    │              │    updated_at     │
│ last_seen       │              └───────────────────┘
│ created_at      │
│ updated_at      │              ┌───────────────────┐
└─────────────────┘              │   block_ledger    │
       │                         │───────────────────│
       │ FK (SET NULL)           │ PK id             │
       └────────────────────────→│ UK ip             │
                                 │    source         │
                                 │    reason         │
                                 │    notes          │
                                 │ FK profile_id     │──→ threat_profiles
                                 │    blocked_by     │
                                 │    broadcast_devs │
                                 │    blocked_at     │
                                 └───────────────────┘

┌─────────────────┐     ┌───────────────────┐
│  scan_history   │     │    wal_events     │
│─────────────────│     │───────────────────│
│ PK id           │     │ PK id             │
│ UK scan_id      │     │    event_type     │
│    target_dir   │     │    timestamp      │
│    start_time   │     │    source         │
│    end_time     │     │    payload        │
│    status       │     │    created_at     │
│    total_files  │     └───────────────────┘
│    scanned_files│
│    new_findings │
│    known_find   │
│    clean        │
│    errors       │
│    duration     │
│    findings     │
│    created_at   │
└─────────────────┘
```

### 4.3 Foreign Key Relationships

| Child Table | Column | Parent Table | Parent Column | ON DELETE |
|-------------|--------|--------------|---------------|-----------|
| `registry` | `quarantine_id` | `quarantine` | `quarantine_id` | SET NULL |
| `registry` | `profile_id` | `threat_profiles` | `profile_id` | SET NULL |
| `block_ledger` | `profile_id` | `threat_profiles` | `profile_id` | SET NULL |

### 4.4 Index Strategy (13 Indexes)

| Table | Indexes | Purpose |
|-------|---------|---------|
| `registry` | `file_path`, `quarantine_id`, `profile_id`, `detected_at`, `deleted_at` | Record queries, relationship navigation, time sorting |
| `threat_profiles` | `risk_score`, `status`, `last_seen` | High-risk sorting, status filtering, decay calculation |
| `block_ledger` | `ip`, `source`, `blocked_at` | IP lookup, source filtering, timeline |
| `quarantine` | `status` | Quarantine status filtering |
| `scan_history` | `start_time` | Scan history sorting |

### 4.5 Namespace Mapping

| Namespace | JSON Path | SQLite Table | Key Column |
|-----------|-----------|--------------|------------|
| `registry` | `data/suspicious_registry.json` | `registry` | `record_id` |
| `quarantine` | `data/quarantine/quarantine.json` | `quarantine` | `quarantine_id` |
| `block_ledger` | `data/block_ledger.json` | `block_ledger` | `ip` |
| `threat_profiles` | `data/threat_graph.json` | `threat_profiles` | `profile_id` |

---

## 5. Data Flow Panorama

### 5.1 Main Data Flow: File Detection

```
Web Server (Nginx/Apache/IIS)
        │
        │ File create/modify events
        ▼
┌─────────────────────────┐
│ FileMonitorHandler      │  infrastructure/monitoring/monitor.py
│ (watchdog Observer)     │
│                         │
│ Windows: ReadDirectoryChangesW (PollingObserver, 50ms delay)
│ Linux:   InotifyObserver (kernel-level, 0 delay)
└───────────┬─────────────┘
            │
            │ Event deduplication (LRU dir_cache 100 items, 60s TTL)
            │ Extension filtering (.php, .asp, .jsp, etc.)
            │ Exclusion directory filtering (cache, logs, temp, data)
            ▼
┌─────────────────────────┐
│ Magic Byte Detection    │  infrastructure/monitoring/monitor.py
│ (reads first 10MB of    │
│  file header)           │
│                         │
│ Identifies: PHP, ASP,   │
│   JSP                  │
│ Failure: → error log    │
└───────────┬─────────────┘
            │
            ▼
┌─────────────────────────┐
│ Detection Chain         │  infrastructure/detection/scanner.py
│                         │
│ 1. YARA Scan (18+ rules)│
│ 2. Hash Engine          │
│ 3. Decoder              │
│                         │
│ → ScanResult (unified   │
│   structure)           │
└───────────┬─────────────┘
            │
            │ is_suspicious?
            │
     ┌──────┴──────┐
     │             │
     YES           NO
     │             │
     ▼             ▼
┌─────────────┐  ┌──────────┐
│ Registry    │  │  Skip    │
│ .add()      │  │ (safe)   │
│ (dedup +    │  └──────────┘
│  merge)     │
└──────┬──────┘
       │
       ├── suspicious_registry.add()
       │   → Save to JSON / SQLite
       │   → Write to WAL
       │   → emit("record_added", ...)
       │
       ├── If quarantine.auto_quarantine_enabled:
       │   → emit("file_quarantined", ...)
       │
       └── emit("alert_requested", ...)
            → notifier_handler → email/WeChat/webhook
```

### 5.2 Threat Profiling Data Flow

```
┌──────────────────────┐    ┌──────────────────────┐
│ WAF Events            │    │ Registry Events       │
│ (waf_source adapter)  │    │ (record_added,         │
│                      │    │  registry_changed)    │
└──────────┬───────────┘    └──────────┬───────────┘
           │                            │
           │ pm.emit()                  │ pm.emit()
           ▼                            ▼
┌──────────────────────────────────────────────────┐
│            threat_graph_handler                   │
│                                                  │
│  on_event(event):                                │
│    entry = extract_fields(event.payload)          │
│    graph.ingest_registry_entry(entry)             │
│    if new_profile_created:                       │
│        emit("threat_graph_updated", ...)          │
└──────────────────────┬───────────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────────┐
│              ThreatGraph                          │
│                                                  │
│  1. UA normalization → tool_signature            │
│  2. URL normalization → path patterns            │
│  3. Profile ID generation (UA + time_window)     │
│  4. IP → Profile association                     │
│  5. IP merging (proxy pool detection)            │
│  6. Risk scoring (event frequency × severity)    │
│  7. Decay (24h → ×0.5, 72h → dormant)           │
└──────────────────────────────────────────────────┘
```

### 5.3 Log Analysis Data Flow

```
Web Access Log (access.log)
        │
        ▼
┌─────────────────────────┐
│ LogHeuristicEngine       │  infrastructure/monitoring/log_monitor.py
│                         │
│ Detection patterns:     │
│ • Brute force (high-freq 404)│
│ • Scanners (path traversal)│
│ • Error storms (500 burst)│
│ • Tool fingerprints      │
│   (UA matching)         │
│ • Suspicious paths       │
│   (/admin, etc.)        │
└───────────┬─────────────┘
            │
            │ Anomaly detected
            ▼
┌─────────────────────────┐
│ Notifier                 │
│                         │
│ • Exponential backoff   │
│   cooldown              │
│ • Circuit breaker       │
│ • Email / WeChat /       │
│   Webhook               │
└─────────────────────────┘
```

### 5.4 SSE Real-Time Push Flow

```
Flask View → SSE EventStream
     │
     │ register_sse_client() → Queue
     │
     ├── Monitor Log lines → persist_log_line() → LogBuffer
     ├── Registry Updates → trigger_registry_update()
     └── Client disconnect → unregister_sse_client()
            │
            ▼
     Browser (EventSource API)
     HTMX: hx-ext="sse"
```

---

## 6. Plugin System

### 6.1 Plugin Types

| Type | ABC | Purpose | Example |
|------|-----|---------|---------|
| **Plugin** | `domain/plugin.py` | General-purpose event handler | stdout_logger, threat_graph_handler |
| **Detector** | `domain/detector.py` | File scan engine | YARA engine |
| **Notifier** | `domain/notifier.py` | Alert channel | email, wechat, webhook |
| **EventSource** | `domain/event_source.py` | External event source | WAF adapters |

### 6.2 Plugin Lifecycle

```
config.toml [plugins].builtin = ["stdout_logger", ...]
        │
        ▼
PluginManager.init_from_config(config)
        │
        ├── For each builtin name:
        │   _load_builtin(name)
        │   ├── import plugins.<name>
        │   ├── find Plugin subclass
        │   ├── instance = PluginClass()
        │   └── register(instance)
        │
        ▼
register(plugin):
    ├── plugin.activate(config[plugin.name])
    ├── classify by type (detector/notifier/event_source)
    └── register event_type → handler mapping

At runtime:
    emit/dispatch → plugin.on_event(event)

shutdown():
    ├── stop worker thread
    └── plugin.deactivate() + unregister() for each plugin
```

### 6.3 Writing a New Plugin

```python
# plugins/my_plugin.py
from anteumbra.domain import Plugin, DomainEvent

class MyPlugin(Plugin):
    @property
    def name(self) -> str:
        return "my_plugin"

    @property
    def supported_events(self) -> List[str]:
        return ["alert_requested", "file_scanned"]

    def activate(self, config):
        self.webhook_url = config.get("webhook_url")

    def deactivate(self):
        pass

    def on_event(self, event: DomainEvent):
        if event.event_type == "alert_requested":
            self._send_webhook(event.payload)
        return None
```

Configuration:
```toml
[plugins]
builtin = ["my_plugin", ...]

[plugins.my_plugin]
webhook_url = "https://hooks.example.com/alerts"
```

---

## 7. Key Algorithms

### 7.1 Risk Decay Engine

```
Decay model (exponential backoff):

decay_factor:
  < 1h:   1.0  (no decay)
  1-24h:  0.5  (half-life)
  24-72h: 0.25 (accelerated decay)
  > 72h:  0.1  (dormant)

Cooldown (adaptive):
  cooldown = base × (1 + alpha)^events × beta^level × gamma^same_ip × delta^combo
  where:
    alpha = 0.1   (+10% per event)
    beta  = 1.5   (×1.5 per level increase)
    gamma = 1.2   (same IP, multiple files)
    delta = 1.3   (WebShell + brute-force combo)
```

### 7.2 File Clustering Algorithm

```
Three-track hashing:
  ssdeep: CTPH (Context-Triggered Piecewise Hashing) — fuzzy hash
  py-tlsh: Trend Micro Locality Sensitive Hash — locality-sensitive hash
  SimHash: Google near-duplicate detection

Clustering threshold: 0.80 (80% similarity → same group)

Process:
  1. Compute ssdeep + TLSH + SimHash for file
  2. Compare similarity against existing clusters
  3. ≥80% → join existing cluster
  4. <80% → create new cluster
```

### 7.3 Profile Merging Algorithm

```
Proxy pool detection:
  If 100 IPs use the same UA within the same time window:
    → They belong to the same attacker
    → Merge into 1 Profile
    → All IPs join ip_pool

Merge conditions:
  same(ua_fingerprint) AND within(time_window_hours, default=4h)
```

---

## 8. Security Design

| Layer | Measures |
|-------|----------|
| **Authentication** | Scrypt password hashing (werkzeug), IP whitelist |
| **Session** | Flask Session (filesystem), HttpOnly Cookie, SameSite=Lax |
| **CSRF** | Flask-WTF CSRFProtect, all POST requests carry token |
| **Path Traversal** | Whitelist validation, `resolve()` + `relative_to()` double check |
| **File Read** | 512KB cap, registry/quarantine validation, null byte filtering |
| **Server Fingerprint** | WSGI middleware removes Server header, Werkzeug version set to empty |
| **Environment Variables** | `${VAR:-default}` syntax, `.env` file loading |
| **Log Injection** | HTML-escape all user input before writing to log streams |

---

## 9. Development Decision Guide

### 9.1 "Which layer should I put my code in?"

```
┌──────────────────────────────────────────────────────┐
│ Q: Is this defining "what it is"?                     │
│ (entities, value objects, domain concepts)            │
│ → YES: domain/                                       │
│   e.g.: Add AlertRule, RiskScore, DetectionPolicy     │
├──────────────────────────────────────────────────────┤
│ Q: Is this defining an interface for "what it can do"?│
│ (abstract ports, no implementation)                   │
│ → YES: domain/                                       │
│   e.g.: Add domain/scorer.py → Scorer ABC            │
├──────────────────────────────────────────────────────┤
│ Q: Is this a concrete implementation of "how to do it"?│
│ (algorithms, I/O, external system interaction)       │
│ → YES: infrastructure/                               │
│   e.g.: Add MLScorer implementing Scorer ABC         │
├──────────────────────────────────────────────────────┤
│ Q: Is this orchestrating multiple infrastructure modules?│
│ (one operation calling multiple lower-level modules) │
│ → YES: application/ (create new service)             │
│   e.g.: response_service.py orchestrating quarantine + block + alert│
├──────────────────────────────────────────────────────┤
│ Q: Is this exposing a Web API / page?                │
│ → YES: interfaces/web/blueprints/                    │
│   e.g.: Add /admin/threat-intel page                 │
├──────────────────────────────────────────────────────┤
│ Q: Is this cross-module event consumption?            │
│ (needs to listen to multiple event sources and react)│
│ → YES: plugins/                                      │
│   e.g.: slack_notifier.py                            │
└──────────────────────────────────────────────────────┘
```

### 9.2 "Should a new feature use EDA events or direct calls?"

| Scenario | Recommended Approach | Reason |
|----------|---------------------|--------|
| Module A needs Module B's result to proceed | **Direct call** (via application service) | Synchronous dependency; emit cannot guarantee ordering |
| Module A finishes something, notifies other modules | **EDA emit()** | Decoupled, async, extensible |
| Multiple consumers need to react to the same event | **EDA emit()** | Plugin system natively supports this |
| Transactional consistency required | **Direct call** (repository.transaction()) | EDA is Fire-and-Forget |
| Audit/logging operations | **EDA emit()** | Does not block the main flow |
| Real-time response (return value needed) | **Direct call** or **EDA dispatch()** | emit returns no result |

### 9.3 "How does a new module connect to the event bus?"

```
1. If the module is in the infrastructure layer:
   - Lazy-import PluginManager
   - from anteumbra.application.plugin_manager import get_plugin_manager
   - Call pm.emit("event_type", "source_name", payload)
   - This is a known DDD design trade-off (13 lazy-import points)

2. If adding a new event type:
   - Ensure at least one plugin declares it in supported_events
   - Keep payload field naming consistent (see existing event catalog)

3. If adding a new plugin:
   - Implement the Plugin ABC
   - Place it in the plugins/ directory
   - Register it in config.toml [plugins].builtin
```

### 9.4 Version Number Decisions

| Change Type | Version Bump | Example |
|-------------|:------------:|---------|
| New feature (new blueprint, new detection engine, new export format) | MINOR | 1.1.0 |
| Bug fix, code quality, performance optimization, refactoring | PATCH | 1.0.10 |
| Incompatible API changes, architecture rewrite | MAJOR | 2.0.0 |

---

## Appendix A: Key Technology Stack

| Technology | Purpose |
|------------|---------|
| **Python 3.10+** | Primary language |
| **Flask 3.x** | Web framework |
| **HTMX 2.x** | Frontend interactivity (no JS framework dependency) |
| **Jinja2** | Template engine |
| **YARA 4.x** | WebShell rule matching |
| **ssdeep / py-tlsh / SimHash** | Three-track file similarity hashing |
| **SQLite 3.x (WAL)** | Relational persistence |
| **watchdog** | Cross-platform filesystem monitoring |
| **Click** | CLI framework |
| **Werkzeug** | WSGI utility library (password hashing) |
| **Flask-Babel** | i18n internationalization (en/zh) |
| **pytest** | Test framework |
| **Playwright** | E2E UI testing |
| **TOML** | Configuration format |

## Appendix B: Common File Quick Reference

| Looking for... | File |
|----------------|------|
| Version number | `src/anteumbra/__init__.py:__version__` |
| All exception handling | grep `except.*:` → `pass` has been eliminated |
| All event emission points | grep `pm.emit(` |
| All thread locks | grep `Lock()` |
| All database tables | `infrastructure/persistence/sqlite_repository.py:_init_tables()` |
| All blueprint routes | grep `@.*_bp.route(` |
| All configuration keys | `config.toml` (130+ keys, 27 sections) |

---

<div align="center">
  <sub>Anteumbra Architecture White Paper v1.0.25 — Evolving alongside the code</sub>
</div>
