# Anteumbra Technical White Paper v1.0.9

> **面向受众**：开发者、架构师、安全工程师。本文档描述 Anteumbra 的内部架构、设计决策、数据模型和扩展指南。

---

## 目录

1. [架构概览](#1-架构概览)
2. [DDD 四层架构](#2-ddd-四层架构)
3. [事件驱动架构 (EDA)](#3-事件驱动架构-eda)
4. [数据库设计](#4-数据库设计)
5. [数据流全景](#5-数据流全景)
6. [插件系统](#6-插件系统)
7. [关键算法](#7-关键算法)
8. [安全设计](#8-安全设计)
9. [开发决策指南](#9-开发决策指南)

---

## 1. 架构概览

Anteumbra 采用 **领域驱动设计 (DDD) 四层架构** + **事件驱动架构 (EDA)** 的混合模式。

```
┌──────────────────────────────────────────────────┐
│                  INTERFACES 层                     │
│  Flask Blueprints / CLI / Templates / SSE         │
│  ┌─────────┐ ┌──────────┐ ┌──────────────────┐   │
│  │ admin_bp │ │records_bp│ │  ... 11 blueprints │   │
│  └────┬─────┘ └────┬─────┘ └────────┬─────────┘   │
│       │             │               │              │
├───────┼─────────────┼───────────────┼──────────────┤
│       ▼             ▼               ▼              │
│              APPLICATION 层                         │
│  ┌──────────────┐ ┌──────────────┐ ┌───────────┐  │
│  │PluginManager │ │ 16 Services  │ │ Event Bus │  │
│  │ (singleton)  │ │ (thin facade)│ │ (emit/dis)│  │
│  └──────┬───────┘ └──────┬───────┘ └─────┬─────┘  │
│         │                │               │         │
├─────────┼────────────────┼───────────────┼─────────┤
│         ▼                ▼               ▼         │
│              INFRASTRUCTURE 层                      │
│  ┌──────────┐ ┌──────────┐ ┌──────────────────┐   │
│  │Detection │ │Monitoring│ │Persistence       │   │
│  │ YARA     │ │ FileWatch│ │ JSON / SQLite    │   │
│  │ Clustering│ │ LogMon  │ │ DualWrite        │   │
│  │ Scanner  │ │ Notifier │ │ WAL Manager      │   │
│  └──────────┘ └──────────┘ └──────────────────┘   │
│                                                     │
├─────────────────────────────────────────────────────┤
│                   DOMAIN 层                          │
│  ┌──────────┐ ┌──────────┐ ┌──────────────────┐   │
│  │ Entities │ │ Ports    │ │ Value Objects    │   │
│  │FileRecord│ │Plugin ABC│ │ ScanResult       │   │
│  │Attacker  │ │Repository│ │ DomainEvent      │   │
│  │Profile   │ │Detector  │ │ AlertMessage     │   │
│  └──────────┘ └──────────┘ └──────────────────┘   │
└─────────────────────────────────────────────────────┘
```

### 核心设计原则

1. **依赖方向**：Interfaces → Application → Infrastructure，所有层可依赖 Domain
2. **Domain 零外部依赖**：Domain 层不 import 任何 Anteumbra 模块
3. **Application 是编排层**：不包含业务逻辑，只做模块编排和事件路由
4. **Infrastructure 实现 Domain 接口**：Repository、Detector、Notifier 都是 Domain 中 ABC 的实现
5. **事件总线解耦**：基础设施模块通过 EDA 事件相互通信，不直接调用

---

## 2. DDD 四层架构

### 2.1 Domain 层（领域层）

**职责**：定义业务实体、值对象、领域事件和端口接口。

**文件**：
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

**核心实体关系**：

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

**设计约束**：
- Domain 层**绝不能** import infrastructure、application、interfaces
- 所有 domain 类型通过 `domain/__init__.py` 统一导出
- `DomainEvent` 是 frozen dataclass — 事件不可变

### 2.2 Application 层（应用层）

**职责**：编排业务流程，管理插件生命周期，提供 Infrastructure 的服务外观。

**核心组件**：

#### PluginManager（事件总线核心）

```python
class PluginManager:
    """单例，线程安全"""
    _instance: Optional[PluginManager]
    _rwlock: threading.RLock         # 保护所有 dict
    _plugins: Dict[str, Plugin]      # 所有已注册插件
    _detectors: Dict[str, Detector]  # 检测器
    _notifiers: Dict[str, Notifier]  # 通知器
    _event_sources: Dict[str, EventSource]
    _event_handlers: Dict[str, List[Plugin]]  # event_type → handlers
    _event_queue: queue.Queue        # Fire-and-Forget 队列
    _abandoned_threads: List[Thread] # 超时僵尸线程追踪
```

**API**：
- `emit(event_type, source, payload) → None` — 异步 Fire-and-Forget（放队列，立即返回）
- `dispatch(event) → List[DomainEvent]` — 同步分发（每个 handler 有 30s 超时）
- `register(plugin) / unregister(name)` — 插件生命周期管理

#### 16 个 Application Service 模块

每个 service 是一个薄外观，从 infrastructure 重导出公共 API：

```python
# application/sse_service.py（示例）
from anteumbra.infrastructure.utils.sse_manager import (
    register_sse_client, unregister_sse_client,
    trigger_registry_update, persist_log_line, ...
)
__all__ = ["register_sse_client", ...]
```

**目的**：修复 DDD 依赖方向。Interface 层通过 Application 层访问 Infrastructure，而不是直接 import。

### 2.3 Infrastructure 层（基础设施层）

**职责**：实现 Domain 定义的端口接口，提供具体的技术能力。

**子模块**：

| 子模块 | 文件 | 职责 |
|--------|------|------|
| **Detection** | scanner, yara_engine, file_cluster, hash_engine, manual_scanner, decoder, memory_shell_tracer | 文件扫描、YARA 匹配、相似度聚类 |
| **Monitoring** | monitor, log_monitor, log_analyzer, metrics, notifier, siem_exporter | 文件监控、日志分析、告警、SIEM 导出 |
| **Persistence** | json_repository, sqlite_repository, `__init__` | 双存储后端 + 工厂 |
| **Config** | registry (ConfigRegistry), loader (TOML+env), version | 配置管理 |
| **Utils** | sse_manager, password_utils, platform_utils, logger_factory, path_utils | 工具库 |
| **Core** | suspicious_registry, quarantine, threat_graph, block_ledger, wal_manager, ip_blocker, decay_engine | 核心业务模块 |

### 2.4 Interfaces 层（接口层）

**职责**：对外暴露 HTTP API、Web 界面、CLI 命令。

**Web Blueprints（12 个）**：

| Blueprint | URL 前缀 | 路由数 | 职责 |
|-----------|---------|:-----:|------|
| `admin_bp` | `/admin` | ~12 | 仪表板主页、认证、账户管理 |
| `records_bp` | `/admin` | ~8 | 检测记录 CRUD + 批量操作 |
| `quarantine_bp` | `/admin` | ~10 | 隔离文件管理 |
| `profiles_bp` | `/admin` | ~7 | 威胁画像 + 文件聚类 |
| `blocklist_bp` | `/admin` | ~6 | IP 封禁台账 |
| `yara_bp` | `/admin/yara` | ~8 | YARA 规则管理 |
| `scanner_bp` | `/admin` | ~7 | 主动扫描 |
| `settings_bp` | `/admin` | ~13 | 设置 + SIEM 导出 |
| `monitor_bp` | `/admin` | ~18 | 实时监控 + 日志流 |
| `system_bp` | `/admin` | ~9 | 系统管理四象限 |
| `metrics_bp` | `/api/v1` | ~5 | 健康检查 + 指标 API |
| `_shared.py` | — | — | 共享工具函数 |

---

## 3. 事件驱动架构 (EDA)

### 3.1 事件总线

Anteumbra 使用 **隐式事件总线** 模式 — `PluginManager` 同时是插件容器和事件路由器。

```
发射端（Infrastructure 模块）              消费端（Plugin）

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

| 特性 | `emit()` | `dispatch()` |
|------|---------|-------------|
| 语义 | Fire-and-Forget | 同步请求-响应 |
| 返回 | `None`（立即） | `List[DomainEvent]`（等待完成） |
| 执行 | 异步（队列 → 工作线程） | 同步（调用线程） |
| 超时 | 无（队列无界） | 每 handler 30s |
| 用途 | 通知、状态变更 | 查询、需要链式事件 |

### 3.3 事件流

```
1. 基础设施模块检测到事件
   monitor.py: _emit_alert()
        │
2. 惰性导入 PluginManager（避免循环导入）
   from anteumbra.application.plugin_manager import get_plugin_manager
        │
3. 发射事件
   pm.emit("alert_requested", "monitor", {...})
        │
4. 事件入队
   DomainEvent → _event_queue (queue.Queue)
        │
5. 工作线程取事件
   _event_worker(): event = _event_queue.get()
        │
6. 分发到注册的 handlers
   dispatch(event):
     for plugin in _event_handlers[event.event_type]:
         t = Thread(plugin.on_event, event)
         t.start()
         t.join(timeout=30.0)
        │
7. 处理
   plugin.on_event(event) → Optional[List[DomainEvent]]
```

### 3.4 事件类型目录

| Event Type | Emitter | Handlers |
|-----------|---------|----------|
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

## 4. 数据库设计

### 4.1 存储架构

```
Config-Driven Backend Selection
        │
        ├── "json"    → JsonRepository
        ├── "sqlite"  → SqliteRepository
        └── "both"    → DualWriteRepository
                            ├── JsonRepository (写入 + 兜底)
                            └── SqliteRepository (优先读)
```

### 4.2 ER 图

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

### 4.3 外键关系

| 子表 | 列 | 父表 | 父列 | ON DELETE |
|------|-----|------|------|-----------|
| `registry` | `quarantine_id` | `quarantine` | `quarantine_id` | SET NULL |
| `registry` | `profile_id` | `threat_profiles` | `profile_id` | SET NULL |
| `block_ledger` | `profile_id` | `threat_profiles` | `profile_id` | SET NULL |

### 4.4 索引策略（13 个索引）

| 表 | 索引 | 用途 |
|----|------|------|
| `registry` | `file_path`, `quarantine_id`, `profile_id`, `detected_at`, `deleted_at` | 检测记录查询、关联导航、时间排序 |
| `threat_profiles` | `risk_score`, `status`, `last_seen` | 高风险排序、状态过滤、衰减计算 |
| `block_ledger` | `ip`, `source`, `blocked_at` | IP 查询、来源过滤、时间线 |
| `quarantine` | `status` | 隔离状态过滤 |
| `scan_history` | `start_time` | 扫描历史排序 |

### 4.5 命名空间映射

| 命名空间 | JSON 路径 | SQLite 表 | 键列 |
|----------|----------|-----------|------|
| `registry` | `data/suspicious_registry.json` | `registry` | `record_id` |
| `quarantine` | `data/quarantine/quarantine.json` | `quarantine` | `quarantine_id` |
| `block_ledger` | `data/block_ledger.json` | `block_ledger` | `ip` |
| `threat_profiles` | `data/threat_graph.json` | `threat_profiles` | `profile_id` |

---

## 5. 数据流全景

### 5.1 主数据流：文件检测

```
Web Server (Nginx/Apache/IIS)
        │
        │ 文件创建/修改事件
        ▼
┌─────────────────────────┐
│ FileMonitorHandler      │  infrastructure/monitoring/monitor.py
│ (watchdog Observer)     │
│                         │
│ Windows: ReadDirectoryChangesW (PollingObserver, 50ms delay)
│ Linux:   InotifyObserver (kernel-level, 0 delay)
└───────────┬─────────────┘
            │
            │ 事件去重 (LRU dir_cache 100 items, 60s TTL)
            │ 扩展名过滤 (.php, .asp, .jsp, etc.)
            │ 排除目录过滤 (cache, logs, temp, data)
            ▼
┌─────────────────────────┐
│ Magic Byte Detection    │  infrastructure/monitoring/monitor.py
│ (文件头 10MB 读取)       │
│                         │
│ 识别: PHP, ASP, JSP     │
│ 失败: → error 日志       │
└───────────┬─────────────┘
            │
            ▼
┌─────────────────────────┐
│ Detection Chain         │  infrastructure/detection/scanner.py
│                         │
│ 1. YARA Scan (18+ rules)│
│ 2. Hash Engine          │
│ 3. Decoder (编码检测)    │
│                         │
│ → ScanResult (统一结构)  │
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
│ Registry    │  │ 跳过     │
│ .add()      │  │ (safe)   │
│ (去重+合并) │  └──────────┘
└──────┬──────┘
       │
       ├── suspicious_registry.add()
       │   → 保存到 JSON / SQLite
       │   → 写入 WAL
       │   → emit("record_added", ...)
       │
       ├── 如果 quarantine.auto_quarantine_enabled:
       │   → emit("file_quarantined", ...)
       │
       └── emit("alert_requested", ...)
            → notifier_handler → email/WeChat/webhook
```

### 5.2 威胁画像数据流

```
┌──────────────────────┐    ┌──────────────────────┐
│ WAF 事件              │    │ 注册表事件            │
│ (waf_source 适配器)   │    │ (record_added,        │
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
│  1. UA 规范化 → tool_signature                   │
│  2. URL 规范化 → 路径模式                         │
│  3. Profile ID 生成 (UA + time_window)            │
│  4. IP → Profile 关联                            │
│  5. IP 合并 (代理池检测)                          │
│  6. 风险评分 (事件频率 × 严重度)                    │
│  7. 衰减 (24h → ×0.5, 72h → dormant)             │
└──────────────────────────────────────────────────┘
```

### 5.3 日志分析数据流

```
Web 访问日志 (access.log)
        │
        ▼
┌─────────────────────────┐
│ LogHeuristicEngine       │  infrastructure/monitoring/log_monitor.py
│                         │
│ 检测模式:               │
│ • 暴力破解 (高频 404)    │
│ • 扫描器 (路径遍历)      │
│ • 错误风暴 (500 爆发)    │
│ • 工具指纹 (UA 匹配)     │
│ • 可疑路径 (/admin, etc) │
└───────────┬─────────────┘
            │
            │ 检测到异常
            ▼
┌─────────────────────────┐
│ Notifier                 │
│                         │
│ • 指数退避冷却           │
│ • 熔断保护               │
│ • Email / WeChat / Webhook│
└─────────────────────────┘
```

### 5.4 SSE 实时推送流

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

## 6. 插件系统

### 6.1 插件类型

| 类型 | ABC | 用途 | 示例 |
|------|-----|------|------|
| **Plugin** | `domain/plugin.py` | 通用事件处理器 | stdout_logger, threat_graph_handler |
| **Detector** | `domain/detector.py` | 文件扫描引擎 | YARA engine |
| **Notifier** | `domain/notifier.py` | 告警渠道 | email, wechat, webhook |
| **EventSource** | `domain/event_source.py` | 外部事件源 | WAF adapters |

### 6.2 插件生命周期

```
config.toml [plugins].builtin = ["stdout_logger", ...]
        │
        ▼
PluginManager.init_from_config(config)
        │
        ├── 对每个 builtin 名称:
        │   _load_builtin(name)
        │   ├── import plugins.<name>
        │   ├── 找到 Plugin 子类
        │   ├── instance = PluginClass()
        │   └── register(instance)
        │
        ▼
register(plugin):
    ├── plugin.activate(config[plugin.name])
    ├── 按类型分类 (detector/notifier/event_source)
    └── 注册 event_type → handler 映射

运行时:
    emit/dispatch → plugin.on_event(event)

shutdown():
    ├── 停止 worker thread
    └── 逐个 plugin.deactivate() + unregister()
```

### 6.3 编写新插件

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

配置：
```toml
[plugins]
builtin = ["my_plugin", ...]

[plugins.my_plugin]
webhook_url = "https://hooks.example.com/alerts"
```

---

## 7. 关键算法

### 7.1 风险衰减引擎

```
衰减模型（指数退避）：

decay_factor:
  < 1h:   1.0  (无衰减)
  1-24h:  0.5  (半衰)
  24-72h: 0.25 (衰减加速)
  > 72h:  0.1  (休眠)

冷却时间（自适应）：
  cooldown = base × (1 + alpha)^events × beta^level × gamma^same_ip × delta^combo
  其中:
    alpha = 0.1   (每次事件 +10%)
    beta  = 1.5   (每升一级 ×1.5)
    gamma = 1.2   (同 IP 多文件)
    delta = 1.3   (WebShell + 爆破组合)
```

### 7.2 文件聚类算法

```
三轨哈希:
  ssdeep: CTPH (Context-Triggered Piecewise Hashing) — 模糊哈希
  py-tlsh: Trend Micro Locality Sensitive Hash — 局部敏感哈希
  SimHash: Google 近似重复检测

聚类阈值: 0.80 (80% 相似度 → 同组)

流程:
  1. 计算文件 ssdeep + TLSH + SimHash
  2. 与现有聚类比较相似度
  3. ≥80% → 加入现有聚类
  4. <80% → 创建新聚类
```

### 7.3 画像合并算法

```
代理池检测:
  如果 100 个 IP 在同一个时间窗口内使用相同的 UA：
    → 它们属于同一攻击者
    → 合并为 1 个 Profile
    → 所有 IP 加入 ip_pool

合并条件:
  same(ua_fingerprint) AND within(time_window_hours, default=4h)
```

---

## 8. 安全设计

| 层面 | 措施 |
|------|------|
| **认证** | Scrypt 密码哈希 (werkzeug)，IP 白名单 |
| **会话** | Flask Session (filesystem)，HttpOnly Cookie，SameSite=Lax |
| **CSRF** | Flask-WTF CSRFProtect，所有 POST 请求带 token |
| **路径穿越** | 白名单验证，`resolve()` + `relative_to()` 双重检查 |
| **文件读取** | 512KB 上限，注册表/隔离验证，null byte 过滤 |
| **服务器指纹** | WSGI 中间件移除 Server 头，Werkzeug version 置空 |
| **环境变量** | `${VAR:-default}` 语法，`.env` 文件加载 |
| **日志注入** | HTML 转义所有用户输入后再写入日志流 |

---

## 9. 开发决策指南

### 9.1 "我应该把代码放在哪一层？"

```
┌──────────────────────────────────────────────────────┐
│ 问：这是在定义"是什么"吗？                              │
│ （实体、值对象、领域概念）                              │
│ → YES: domain/                                       │
│   例：添加 AlertRule, RiskScore, DetectionPolicy      │
├──────────────────────────────────────────────────────┤
│ 问：这是在定义"能做什么"的接口吗？                       │
│ （抽象端口，无实现）                                   │
│ → YES: domain/                                       │
│   例：添加 domain/scorer.py → Scorer ABC              │
├──────────────────────────────────────────────────────┤
│ 问：这是"怎么做"的具体实现吗？                          │
│ （算法、I/O、外部系统交互）                             │
│ → YES: infrastructure/                               │
│   例：添加 MLScorer 实现 Scorer ABC                   │
├──────────────────────────────────────────────────────┤
│ 问：这是在编排多个 infrastructure 模块吗？              │
│ （一个操作调用多个底层模块）                             │
│ → YES: application/ (新建 service)                   │
│   例：response_service.py 编排 quarantine + block + alert│
├──────────────────────────────────────────────────────┤
│ 问：这是在暴露 Web API / 页面吗？                       │
│ → YES: interfaces/web/blueprints/                    │
│   例：添加 /admin/threat-intel 页面                    │
├──────────────────────────────────────────────────────┤
│ 问：这是跨模块的事件消费吗？                             │
│ （需要监听多个事件源并做出响应）                         │
│ → YES: plugins/                                      │
│   例：slack_notifier.py                               │
└──────────────────────────────────────────────────────┘
```

### 9.2 "新功能应该走 EDA 事件还是直接调用？"

| 场景 | 推荐方式 | 原因 |
|------|---------|------|
| 模块 A 需要模块 B 的结果才能继续 | **直接调用**（通过 application service） | 同步依赖，emit 无法保证顺序 |
| 模块 A 做完某事，通知其他模块 | **EDA emit()** | 解耦，异步，可扩展 |
| 需要多个消费者对同一事件做出反应 | **EDA emit()** | 插件系统天然支持 |
| 需要保证事务一致性 | **直接调用**（repository.transaction()） | EDA 是 Fire-and-Forget |
| 审计/日志类操作 | **EDA emit()** | 不阻塞主流程 |
| 实时响应（需要返回值） | **直接调用** 或 **EDA dispatch()** | emit 不返回结果 |

### 9.3 "新模块如何接入事件总线？"

```
1. 如果模块在 infrastructure 层：
   - 惰性导入 PluginManager
   - from anteumbra.application.plugin_manager import get_plugin_manager
   - 调用 pm.emit("event_type", "source_name", payload)
   - 这是已知的 DDD 设计权衡（13个惰性导入点）

2. 如果新增事件类型：
   - 确保至少一个插件在 supported_events 中声明
   - payload 字段命名保持一致性（见现有事件目录）

3. 如果新增插件：
   - 实现 Plugin ABC
   - 放在 plugins/ 目录
   - 在 config.toml [plugins].builtin 中注册
```

### 9.4 版本号决策

| 变更类型 | 版本位 | 示例 |
|---------|:------:|------|
| 新增功能（新 blueprint、新检测引擎、新导出格式） | MINOR | 1.1.0 |
| Bug 修复、代码质量、性能优化、重构 | PATCH | 1.0.10 |
| 不兼容的 API 变更、架构重写 | MAJOR | 2.0.0 |

---

## 附录 A：关键技术栈

| 技术 | 用途 |
|------|------|
| **Python 3.10+** | 主语言 |
| **Flask 3.x** | Web 框架 |
| **HTMX 2.x** | 前端交互（无 JS 框架依赖） |
| **Jinja2** | 模板引擎 |
| **YARA 4.x** | WebShell 规则匹配 |
| **ssdeep / py-tlsh / SimHash** | 文件相似度三轨哈希 |
| **SQLite 3.x (WAL)** | 关系型持久化 |
| **watchdog** | 跨平台文件系统监控 |
| **Click** | CLI 框架 |
| **Werkzeug** | WSGI 工具库（密码哈希） |
| **Flask-Babel** | i18n 国际化 (en/zh) |
| **pytest** | 测试框架 |
| **Playwright** | E2E UI 测试 |
| **TOML** | 配置格式 |

## 附录 B：常用文件速查

| 想找... | 文件 |
|---------|------|
| 版本号 | `src/anteumbra/__init__.py:__version__` |
| 所有异常处理 | grep `except.*:` → `pass` 已清零 |
| 所有事件发射点 | grep `pm.emit(` |
| 所有线程锁 | grep `Lock()` |
| 所有数据库表 | `infrastructure/persistence/sqlite_repository.py:_init_tables()` |
| 所有蓝图路由 | grep `@.*_bp.route(` |
| 所有配置键 | `config.toml` (130+ keys, 27 sections) |

---

<div align="center">
  <sub>Anteumbra Architecture White Paper v1.0.9 — 随代码一起演进</sub>
</div>
