# Anteumbra 技术架构

> **面向受众**：开发者、架构师、安全工程师。本文档描述 Anteumbra 的内部架构、设计决策、数据模型和扩展指南。

[English](ARCHITECTURE.md)

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
10. [站点隔离与运行时组装](#10-站点隔离与运行时组装)

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
    """Runtime 独享、线程安全的事件路由器"""
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

#### Application 编排与 Service 模块

Application 模块拥有真实用例与运行时工作流状态：

| 模块 | 职责 |
|------|------|
| `launcher.py` | 组合根、多站点资源启动、运行状态和确定性关闭 |
| `runtime_container.py` | 通过 Domain Port 强类型声明必需的运行时服务清单 |
| `jsonl_consumer.py` | JSONL 逐条确认、截断/轮转处理和死信 |
| `quarantine_service.py` | 带文件系统与 Registry 补偿的隔离/恢复事务 |
| `log_analysis_service.py` | 按站点分析访问日志，Web 路由不直接导入解析器 |
| `password_service.py` | Runtime 级凭据校验与 `.env` 原子更新 |
| `scan_state_service.py` | 手动扫描任务、结果保留、取消与关闭 |
| `config_history_service.py` | Runtime 级配置重载审计历史 |
| `runtime_health_service.py` | CLI/Web 共用的可选能力与配置/WAL/Registry 关键健康评估 |

**目的**：Interfaces 通过 Application API 访问具体解析器和存储。有状态服务由
`launcher.py` 构造并通过强类型 `RuntimeContainer` 暴露；Application 模块不会
自行查找进程级服务实例。

#### 运行生命周期

`launcher.py` 中的 `RuntimeLifecycle` 是进程组装与资源所有者。CLI 为每个进程创建
一个生命周期实例并调用 `run()`；实例持有强类型 `RuntimeState`，通过 `status()` 暴露
状态，并由 `stop()` 按反向顺序幂等关闭。项目不再保留模块级 Launcher 状态或兼容门面。
可选能力失败会形成明确告警；一个文件监控器都无法启动则视为致命错误。
`domain/service_ports.py` 定义 Scanner、文件聚类、ThreatGraph、Notifier、SIEM、SSE、
WAL、WAF 和插件系统等可替换服务的接入契约。

### 2.3 Infrastructure 层（基础设施层）

**职责**：实现 Domain 定义的端口接口，提供具体的技术能力。

**子模块**：

| 子模块 | 文件 | 职责 |
|--------|------|------|
| **Detection** | scanner, yara_engine, file_cluster, hash_engine, manual_scanner, decoder, memory_shell_tracer | 文件扫描、YARA 匹配、相似度聚类 |
| **Monitoring** | monitor, log_monitor, log_analyzer, metrics, notifier, siem_exporter | 文件监控、日志分析、告警、SIEM 导出 |
| **Persistence** | json_repository, sqlite_repository, `__init__` | 显式 Repository 实现 |
| **Config** | provider, loader (TOML+env), version | Runtime 独享的配置快照 |
| **Utils** | sse_manager, platform_utils, logger_factory, path_utils | 运行时与平台适配器 |
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
                                   └─→  siem_handler.on_event()

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
| 超时 | 有界队列；溢出时同步回退 | 每 handler 使用配置超时 |
| 用途 | 通知、状态变更 | 查询、需要链式事件 |

### 3.3 事件流

```
1. 组合根注入事件端口
   RuntimeServices.events: EventPublisherPort
        │
2. 基础设施模块检测并发布事件
   services.events.publish("alert_requested", "monitor", {...})
        │
3. Runtime 所有的 EventPublisherRouter 转发到已绑定 PluginManager
        │
4. 事件入队
   DomainEvent → 有界 `_event_queue`
   队列满 → 同步分发并记录过载指标
        │
5. 工作线程取事件
   _event_worker(): event = _event_queue.get()
        │
6. 分发到注册的 handlers
   dispatch(event):
     for plugin in _event_handlers[event.event_type]:
       跳过已知不健康的 handler
     t = Thread(plugin.on_event, event)
     t.start()
     t.join(timeout=配置超时)
     限制遗留 handler 线程数量
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
| `record_added` | suspicious_registry.py | threat_graph_handler, siem_handler |
| `registry_changed` | suspicious_registry.py (6 sites) | threat_graph_handler |
| `threat_graph_updated` | threat_graph_handler | stdout_logger |
| `wal_archived` | wal_manager.py | stdout_logger |
| `wal_replayed` | wal_manager.py | stdout_logger |

---

## 4. 数据库设计

### 4.1 存储架构

```
核心状态存储
        │
        ├── Registry / 隔离 / 封禁台账 / 威胁画像
        │       │
        │       ├── JSON 文件（权威读写）
        │       └── SQLite 影子副本（仅 sqlite / both）
        │               └── 仅在 JSON 不可用时用于恢复
        │
        └── 通用 Repository 使用者
                ├── "json"    -> JsonRepository
                ├── "sqlite"  -> SqliteRepository
                └── "both"    -> DualWriteRepository
```

Registry、隔离、封禁台账和威胁画像模块自行维护 JSON 格式，因为兼容、原子写入和
磁盘恢复都属于其领域行为。它们通过 `get_shadow_repository()` 写入 SQLite，不能使用
通用双写 Repository；否则带站点前缀的 Registry 键可能被写回 JSON 的 `file_path`。

这些核心存储中，只要 JSON 有效就以 JSON 为准；SQLite 仅在 JSON 缺失或不可读时
参与恢复。威胁画像影子库只保存画像记录，不保存完整 IP 信誉表，因此该恢复是明确的
部分恢复，运维人员必须整体备份 JSON 状态。

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
            │ TTL 目录缓存去重（60s，无固定 LRU 上限）
            │ 扩展名过滤 (.php, .asp, .jsp, etc.)
            │ 排除目录过滤 (cache, logs, temp, data)
            │ 有界扫描队列；过载时同步回退
            │ 启动基线扫描会将已有脚本文件加入扫描队列
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
│ 1. YARA Scan (27 个隔离│
│    规则文件)            │
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
       │   → threat_graph_handler + siem_handler
       │
       ├── 如果 quarantine.auto_quarantine_enabled:
       │   → emit("file_quarantined", ...)
       │   → quarantine_handler
       │   → quarantine_service（文件 + Registry 补偿）
       │
       └── emit("alert_requested", ...)
            → notifier_handler → email/WeChat/webhook
```

刚恢复的文件会在创建/修改和移动两条扫描路径之前接受检查。在 30 秒保护窗口内，它不会生成重复的 Registry 事件、告警、SIEM 导出或隔离操作。

### 5.2 威胁画像数据流

追加式 WAF JSONL 输入由 `JsonlEventTailer` 消费。完整记录逐条确认；畸形 JSON
或处理器异常会写入 `data/waf_events.deadletter.jsonl`，随后推进游标。未写完的
尾行留待下次轮询，文件被替换或截断时从字节 0 重新读取。

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

每个启用站点拥有自己的日志配置。`log_analysis_service` 通过站点绑定的分析器
选择 Nginx/Apache/Tomcat 解析逻辑并返回带站点标识的结果；单个站点日志缺失
不会抑制其他站点。

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
所有启用站点日志 → 按时间合并历史
                         │
Flask View → SSE EventStream
     │
     │ register_sse_client() → Queue
     │
     ├── Monitor Log lines → persist_log_line() → LogBuffer
     ├── Registry Updates → trigger_registry_update()
     ├── 15 秒 heartbeat → keepalive
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

### 投递可靠性

`PluginManager.emit()` 使用有界队列（`plugins.event_queue_size`）。事件在
`event_enqueue_timeout_seconds` 内无法入队时会同步分发，并记录
`plugin_queue_overflow`。每个 handler 受 `dispatch_timeout_seconds` 约束；超时
handler 会被跟踪，受 `max_abandoned_handlers` 上限约束，并在其退出前跳过后续
事件。这样可以隔离失败集成，避免无限增长的超时线程。

`siem_handler` 订阅 `record_added` 并调用 SIEM 导出器，因此 Registry 事件是本地
文件检测到 JSON Lines、CEF 或 Syslog 输出的唯一桥梁。

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
1. 如果现有 infrastructure 模块已经发射事件：
   - 由组合根注入 `EventPublisherPort`
   - Infrastructure 不得导入或自行定位 `PluginManager`
   - 同步依赖继续使用显式 Application 调用
   - 事件负载必须携带站点信息并有隔离回归测试

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
| 新里程碑或不兼容产品架构 | 里程碑 | 2.0.0 |
| 面向用户的新功能线 | 功能 | 1.1.0 |
| Bug 修复、清理、可靠性改进、兼容重构 | bug 修复 | 1.0.x -> 1.0.(x+1) |

---

## 10. 站点隔离与运行时组装

### 10.1 所有权模型

`SiteIdentity` 是每个已配置网站的稳定所有权值。`site_id` 来自 `website.id`，
`site_name` 仅用于展示。文件路径不是全局唯一的，两个站点可以合法地记录同一路径；
因此 SQLite 中的 Registry 身份为 `(site_id, file_path)`，JSON、应用服务和事件也都
携带站点信息。

早于该模型的记录会被显式标为 `legacy`。任何模块都不得通过“取第一个已配置站点”的
方式重新解释这些记录。

### 10.2 运行时组装

`launcher.py` 是组合根。单个 `RuntimeLifecycle` 只解析一次站点，创建必需的
`RuntimeContainer` 与共享 `RuntimeServices`，再为每个启用站点启动一个文件监控器和
可选的日志监控器。监控器通过依赖注入得到自身的站点身份和运行时服务，不会导入
全局网站选择。

```
config.toml -> TomlConfigProvider -> RuntimeLifecycle -> RuntimeContainer
                                                      -> SiteResolver
                                                      -> RuntimeServices
                                                      -> monitor(site A)
                                                      -> monitor(site B)
                                                      -> log monitor(site N)
```

关闭顺序沿同一所有权图反向执行，因此单个站点启动失败或被禁用不会阻止其他站点独立
启动和停止。

### 10.3 事件与数据契约

所有文件检测路径，包括移动文件，都会进入同一条排队扫描管道。扫描结果会把 `site_id`
和 `site_name` 传递到 Registry、隔离、指标、通知批处理、SSE 历史、扫描历史和仪表盘
汇总中。通知批次按站点分组；还原或误报操作只会修改匹配站点的记录。

### 10.4 扩展契约

独立开发的模块必须：

- 接受显式 `SiteIdentity` 或具备站点意识的应用服务；
- 发布和消费带站点标记的事件负载；
- 通过构造参数或 Domain Port 接收运行时依赖；
- 在正常流程中避免进程级服务注册表、私有全局变量或“第一个站点”选择；
- 让 Web 路由调用应用服务，而非直接修改持久化模块；以及
- 只要持久化、汇总或修改站点数据，就增加隔离回归测试。

这些约束让当前模块化单体能够持续扩展，而不假装它已经是分布式系统。

---

## 附录 A：关键技术栈

| 技术 | 用途 |
|------|------|
| **Python 3.10+** | 主语言 |
| **Flask 2.3.x** | Web 框架 |
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
| 静默宽泛异常 | `rg -U "except Exception.*\\n\\s+pass" src/anteumbra`（必须无匹配） |
| 所有事件发射点 | `rg "events\\.publish|\\.emit\\(" src/anteumbra` |
| 所有线程锁 | `rg "Lock\\(" src/anteumbra` |
| 所有数据库表 | `src/anteumbra/infrastructure/persistence/sqlite_repository.py` |
| 所有蓝图路由 | `rg "@.*_bp\\.route\\(" src/anteumbra/interfaces/web` |
| 所有配置键 | `src/anteumbra/config.toml` |

---

<div align="center">
  <sub>Anteumbra 技术架构 — 随代码一起演进</sub>
</div>
