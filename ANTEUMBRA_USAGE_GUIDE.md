# Anteumbra Internal Development Guide v1.0.9

> **目标读者**：Anteumbra 项目的开发者和维护者。本文档不公开，不入 GitHub。

---

## 目录

1. [本地开发环境](#1-本地开发环境)
2. [项目结构速查](#2-项目结构速查)
3. [开发工作流](#3-开发工作流)
4. [测试指南](#4-测试指南)
5. [代码规范](#5-代码规范)
6. [DDD 架构开发指南](#6-ddd-架构开发指南)
7. [常见开发任务](#7-常见开发任务)
8. [调试与故障排查](#8-调试与故障排查)
9. [发布流程](#9-发布流程)

---

## 1. 本地开发环境

### 1.1 系统要求

- Windows 10+ 或 Linux (kernel 4.x+)
- Python 3.10 / 3.11 / 3.12
- Git 2.x+
- 推荐：VS Code + Python 插件

### 1.2 开发安装

```bash
git clone https://github.com/SxyLao1/Anteumbra.git
cd Anteumbra
pip install -e ".[dev]"
```

### 1.3 配置本地环境

```bash
# 生成开发用 config.toml
anteumbra config -o config.toml

# 生成管理员密码
python -c "from werkzeug.security import generate_password_hash; print(generate_password_hash('devpass'))"
```

将生成的 hash 写入 `config.toml` 的 `[web_admin].password_hash`。

### 1.4 启动开发服务器

```bash
# 前台运行（推荐开发时使用）
python run.py

# 或通过 CLI
anteumbra run --debug
```

### 1.5 目录约定

| 路径 | 用途 |
|------|------|
| `F:\Home\Github\Anteumbra\` | 源码仓库（主开发目录） |
| `F:\Home\AIWork\ClaudeWorkBench\` | Claude Code 工作区（不提交） |
| `C:\Users\14183\.claude\projects\...` | Memory / 会话持久化 |

---

## 2. 项目结构速查

```
Anteumbra/
├── config.toml                    # 运行时配置（不入仓库）
├── pyproject.toml                 # 构建配置、依赖、pytest 设置
├── run.py                         # 开发启动入口
├── src/anteumbra/                 # 应用源码
│   ├── __init__.py                # __version__ = "1.0.9"
│   ├── domain/                    # 领域层（实体 + 端口接口）
│   │   ├── entities.py            # FileRecord, ScanResult, QuarantineRecord
│   │   ├── plugin.py              # Plugin ABC, DomainEvent
│   │   ├── detector.py            # Detector ABC, ScanRequest
│   │   ├── notifier.py            # Notifier ABC, AlertMessage
│   │   ├── event_source.py        # EventSource ABCs
│   │   ├── waf_source.py          # WAFEvent
│   │   └── repository.py          # Repository ABC, EventRepository ABC
│   ├── application/               # 应用层（编排 + 服务外观）
│   │   ├── plugin_manager.py      # 插件管理器（事件总线核心）
│   │   ├── registry_service.py    # → infrastructure.suspicious_registry
│   │   ├── quarantine_service.py  # → infrastructure.quarantine
│   │   ├── threat_graph_service.py
│   │   ├── block_ledger_service.py
│   │   ├── wal_service.py
│   │   ├── ip_blocker_service.py
│   │   ├── yara_service.py
│   │   ├── file_cluster_service.py
│   │   ├── scanner_service.py
│   │   ├── metrics_service.py
│   │   ├── siem_service.py
│   │   ├── sse_service.py         # v1.0.9 新增
│   │   ├── password_service.py    # v1.0.9 新增
│   │   ├── platform_service.py    # v1.0.9 新增
│   │   ├── config_service.py      # v1.0.9 新增
│   │   └── logging_service.py     # v1.0.9 新增
│   ├── infrastructure/            # 基础设施层
│   │   ├── models.py              # AttackerProfile, IPReputation, Website, etc.
│   │   ├── suspicious_registry.py # 核心：可疑文件注册表
│   │   ├── quarantine.py          # 文件隔离引擎
│   │   ├── threat_graph.py        # 威胁画像引擎
│   │   ├── block_ledger.py        # IP 封禁台账
│   │   ├── wal_manager.py         # WAL 事务日志
│   │   ├── ip_blocker.py          # IP 封禁执行
│   │   ├── decay_engine.py        # 风险衰减算法
│   │   ├── registry_adapter.py    # Registry Repository 适配器
│   │   ├── config/
│   │   │   ├── registry.py        # ConfigRegistry 单例
│   │   │   ├── loader.py          # TOML + 环境变量加载
│   │   │   └── version.py         # 版本号读取
│   │   ├── detection/
│   │   │   ├── scanner.py         # 核心扫描引擎
│   │   │   ├── yara_engine.py     # YARA 规则引擎
│   │   │   ├── file_cluster.py    # 文件聚类（ssdeep/TLSH/SimHash）
│   │   │   ├── hash_engine.py     # 哈希计算
│   │   │   ├── manual_scanner.py  # 主动扫描
│   │   │   ├── decoder.py         # 编码检测
│   │   │   └── memory_shell_tracer.py
│   │   ├── monitoring/
│   │   │   ├── monitor.py         # 文件系统监控主循环
│   │   │   ├── log_monitor.py     # 访问日志监控
│   │   │   ├── log_analyzer.py    # 日志分析
│   │   │   ├── metrics.py         # 指标采集
│   │   │   ├── notifier.py        # 告警通知
│   │   │   └── siem_exporter.py   # SIEM 导出
│   │   ├── persistence/
│   │   │   ├── json_repository.py
│   │   │   ├── sqlite_repository.py
│   │   │   └── __init__.py        # get_repository() 工厂
│   │   └── utils/
│   │       ├── sse_manager.py     # SSE 推送管理
│   │       ├── password_utils.py  # 密码验证
│   │       ├── platform_utils.py  # 平台检测
│   │       ├── logger_factory.py  # 日志工厂
│   │       └── path_utils.py      # 路径规范化
│   ├── interfaces/                # 接口层
│   │   └── web/
│   │       ├── factory.py         # Flask 应用工厂
│   │       ├── auth.py            # 认证装饰器
│   │       └── blueprints/        # 路由蓝图
│   │           ├── admin_bp.py    # 仪表板主页 + 认证 + 账户
│   │           ├── records_bp.py  # 检测记录
│   │           ├── quarantine_bp.py
│   │           ├── profiles_bp.py # 威胁画像 + 文件聚类
│   │           ├── blocklist_bp.py
│   │           ├── yara_bp.py     # YARA 规则管理
│   │           ├── scanner_bp.py  # 主动扫描
│   │           ├── settings_bp.py # 设置 + SIEM
│   │           ├── monitor_bp.py  # 监控面板 + 日志流
│   │           ├── system_bp.py   # 系统管理
│   │           ├── metrics.py     # 健康检查 API
│   │           ├── _shared.py     # 共享工具函数
│   │           └── __init__.py    # register_blueprints()
│   └── cli/
│       └── main.py                # Click CLI
├── plugins/                       # 插件目录
│   ├── stdout_logger.py
│   ├── quarantine_handler.py
│   ├── notifier_handler.py
│   ├── threat_graph_handler.py
│   └── waf_adapters/
├── tests/
│   ├── core/                      # 单元测试（~236 个）
│   ├── e2e/                       # E2E 后端测试（~61 个）
│   ├── e2e_ui/                    # Playwright UI 测试（~34 个）
│   └── compatibility/             # 兼容性测试
├── tools/
│   ├── waf_proxy/                 # 开发用 WAF 代理
│   ├── memory-shell/              # 内存马检测参考工具
│   ├── cleanup_sessions.py
│   └── config_watcher_logger.py
├── rules/webshell/                # YARA 规则库（18+ 文件）
├── docs/
│   ├── USER_MANUAL.md             # 用户手册
│   └── ARCHITECTURE.md            # 技术白皮书
├── templates/                     # Jinja2 模板
└── static/                        # CSS/JS 静态资源
```

---

## 3. 开发工作流

### 3.1 分支策略

```
main          ← 稳定分支（打 tag 发布）
├── dev       ← 日常开发分支
├── fix/*     ← Bug 修复
└── feat/*    ← 功能开发
```

### 3.2 日常开发循环

```bash
# 1. 切到 dev 分支
git checkout dev

# 2. 写代码...

# 3. 跑测试（必须通过）
python -m pytest tests/core/ tests/compatibility/ -v

# 4. 跑 E2E 后端测试（涉及网络/文件的可跳过部分）
python -m pytest tests/e2e/ -v --ignore=tests/e2e_ui

# 5. 提交
git add -A
git commit -m "描述性提交信息"

# 6. 合并到 main 并打 tag
git checkout main
git merge dev
git tag v1.0.10
```

### 3.3 提交信息规范

```
<类型>: <简短描述>

<详细说明>

类型：
  fix      - Bug 修复
  feat     - 新功能
  refactor - 重构（不改变行为）
  test     - 测试相关
  docs     - 文档
  chore    - 构建/依赖/工具
```

### 3.4 版本号规则

**MAJOR.MINOR.PATCH** (SemVer)

- **MAJOR (1)**: 重大架构变更，不向后兼容
- **MINOR (0)**: 新功能，向后兼容
- **PATCH (9)**: Bug 修复、代码质量、性能优化

版本号单一真相来源：`src/anteumbra/__init__.py → __version__`。
`pyproject.toml` 在构建时动态读取，不需要手动同步。

---

## 4. 测试指南

### 4.1 运行测试

```bash
# 全部核心测试（快速，无 I/O）
python -m pytest tests/core/ -v

# 包含兼容性测试
python -m pytest tests/core/ tests/compatibility/ -v

# E2E 后端测试（需要 config.toml）
python -m pytest tests/e2e/ -v --ignore=tests/e2e_ui

# E2E UI 测试（需要 Playwright + 运行中的服务器）
python -m pytest tests/e2e_ui/ -v

# 单个测试文件
python -m pytest tests/core/test_threat_graph.py -v

# 单个测试函数
python -m pytest tests/core/test_threat_graph.py::TestDecayProfiles::test_decay_empty_graph -v

# 停止在第一个失败
python -m pytest tests/core/ -x

# 带覆盖率
pip install pytest-cov
python -m pytest tests/core/ --cov=anteumbra --cov-report=html
```

### 4.2 测试分类

| 目录 | 数量 | 类型 | 速度 |
|------|:--:|------|:--:|
| `tests/core/` | ~234 | 单元测试 | 快（~13s） |
| `tests/e2e/` | ~61 | 后端 E2E | 中（需要文件系统） |
| `tests/e2e_ui/` | ~34 | Playwright UI | 慢（需要浏览器） |
| `tests/compatibility/` | ~9 | API 兼容性 | 快 |

### 4.3 编写测试

```python
import pytest
from anteumbra.infrastructure.threat_graph import get_threat_graph

class TestMyFeature:
    """每个功能一个 TestClass，每个场景一个 test_ 方法"""

    @pytest.fixture(autouse=True)
    def reset_state(self, monkeypatch):
        """每个测试前重置单例状态"""
        from anteumbra.infrastructure import threat_graph as tg
        monkeypatch.setattr(tg, "_graph", None)
        monkeypatch.setattr(tg.ThreatGraph, 'load', lambda self: None)

    def test_normal_case(self):
        graph = get_threat_graph()
        result = graph.do_something("input")
        assert result is not None
        assert result.score > 0

    def test_edge_case_empty_input(self):
        graph = get_threat_graph()
        result = graph.do_something("")
        assert result is None  # Empty input should return None

    def test_error_case(self):
        with pytest.raises(ValueError):
            get_threat_graph().do_something(None)
```

### 4.4 已知问题

- `test_decay_24h_reduces_score_by_half` — 偶发状态污染，重置 fixture 已加固
- `test_waf_proxy` — 需要 WAF 代理在 8081 端口运行
- E2E profiling 测试 — 某些环境会挂起（ThreatGraph 持久化问题）
- ppdeep 相关测试 — 未安装时静默跳过

---

## 5. 代码规范

### 5.1 Import 顺序

```python
# 1. 标准库
import json
import logging
from pathlib import Path

# 2. 第三方库
from flask import Blueprint, render_template

# 3. Anteumbra 内部 — domain
from anteumbra.domain import DomainEvent

# 4. Anteumbra 内部 — application
from anteumbra.application.registry_service import get_all

# 5. Anteumbra 内部 — infrastructure（仅允许在 infrastructure 层内使用）
from anteumbra.infrastructure.config.registry import ConfigRegistry
```

### 5.2 DDD Import 规则（强制）

```
Interfaces ──→ Application ──→ Infrastructure
     │                              │
     └────────── Domain ────────────┘
```

- **Interface 层**：只能 import application 服务和 domain 实体，**禁止**直接 import infrastructure
- **Application 层**：可以 import infrastructure（它是编排层）
- **Infrastructure 层**：只能 import domain 实体/接口，**禁止** import application（除插件事件桥接）
- **Domain 层**：零外部依赖，不 import 任何其他层

### 5.3 异常处理

```python
# ❌ 禁止
except:
    pass

# ❌ 禁止
except Exception:
    pass

# ✅ 正确
except SpecificError:
    logger.debug("Context about why this is OK", exc_info=True)

# ✅ 正确（重新抛出时保留异常链）
except ValueError as e:
    raise RuntimeError("Better message") from e
```

### 5.4 日志

```python
# ✅ 使用 logging 模块
logger = logging.getLogger(__name__)
logger.info("Something happened")
logger.debug("Detailed debug info", exc_info=True)

# ❌ 禁止 print()
# print("debug: got here")  ← NEVER

# ✅ 使用结构化日志（配置了 symbols 时）
from anteumbra.infrastructure.utils.logger_factory import log_with_symbol
log_with_symbol("notice", "info", "Registry compaction done", logger)
```

### 5.5 线程安全

```python
# ✅ 保护共享状态
_lock = threading.Lock()
_shared_dict = {}

def update(key, value):
    with _lock:
        _shared_dict[key] = value

# ✅ 双重检查锁定（单例）
_instance = None
_lock = threading.Lock()

def get_instance():
    global _instance
    if _instance is None:
        with _lock:
            if _instance is None:
                _instance = MyClass()
    return _instance
```

### 5.6 Path 处理

```python
# ✅ 使用 pathlib
from pathlib import Path
filename = Path(file_path).name
parent = Path(file_path).parent

# ❌ 禁止手动拆分路径
filename = file_path.split('\\')[-1].split('/')[-1]  # NEVER
```

---

## 6. DDD 架构开发指南

### 6.1 在哪一层添加代码？

| 如果你在添加... | 放在这里 | 示例 |
|-----------------|---------|------|
| 新的检测算法 | `infrastructure/detection/` | 添加 `entropy_scanner.py` |
| 新的外部服务集成 | `infrastructure/` 然后 `application/` 包装 | WAF 适配器 |
| 新的 Web 页面/API | `interfaces/web/blueprints/` | 添加 `api_bp.py` |
| 新的领域概念（实体） | `domain/entities.py` | 添加 `AlertRule` 数据类 |
| 新的领域接口（端口） | `domain/` 新文件 | 添加 `domain/scorer.py` |
| 编排多个基础设施模块 | `application/` 新服务 | 添加 `response_service.py` |
| 新的 CLI 命令 | `cli/main.py` | 添加 `anteumbra scan` |
| 新的插件 | `plugins/` | 添加 `slack_notifier.py` |

### 6.2 添加新的 Application Service

```python
# application/my_service.py
"""Application Service: My Feature — thin facade over infrastructure."""

from anteumbra.infrastructure.my_module import (
    do_thing,
    get_thing,
    ThingResult,
)

__all__ = ["do_thing", "get_thing", "ThingResult"]
```

### 6.3 添加新的 Blueprint

```python
# interfaces/web/blueprints/my_bp.py
from flask import Blueprint, render_template
from anteumbra.interfaces.web.auth import require_auth
from anteumbra.application.my_service import do_thing  # 走 application！

my_bp = Blueprint('my_feature', __name__, url_prefix='/admin')

@my_bp.route('/my-page')
@require_auth
def my_page():
    result = do_thing()
    return render_template('admin/my_page.html', result=result)
```

然后在 `blueprints/__init__.py` 的 `register_blueprints()` 中注册。

### 6.4 添加新的事件类型

1. 在 `plugins/` 的 `supported_events` 中添加事件名
2. 在 `on_event()` 中处理
3. 在基础设施模块中通过 `pm.emit("new_event_type", source, payload)` 发射

---

## 7. 常见开发任务

### 7.1 添加新的 YARA 规则

1. 在 `rules/webshell/` 创建 `.yar` 文件
2. 通过 Web UI 上传并自动验证语法
3. 或在 YARA 规则页面手动测试

### 7.2 添加新的通知渠道

1. 实现 `Notifier` 接口：`plugins/my_notifier.py`
2. 在 `config.toml` 的 `[plugins]` 中添加配置
3. 修改 `notifier_handler.py` 的 `supported_events`

### 7.3 修改数据库 Schema

1. 编辑 `infrastructure/persistence/sqlite_repository.py` 中的 `_init_tables()`
2. 增量为新的 schema 版本添加 `_migrate_vX_to_vY()` 方法
3. `SqliteRepository.__init__()` 会自动检测并运行迁移
4. 更新 `infrastructure/models.py` 的数据类（如适用）

### 7.4 性能分析

```bash
# 测试运行时间
python -m pytest tests/core/ --durations=10

# 启动时 profiling
python -m cProfile -o profile.out run.py
python -c "import pstats; pstats.Stats('profile.out').sort_stats('cumtime').print_stats(30)"
```

---

## 8. 调试与故障排查

### 8.1 启用 Debug 日志

```toml
[logging]
level = "DEBUG"
```

或在 `.env` 中设置 `ANTEUMBRA_LOG_LEVEL=DEBUG`。

### 8.2 常见开发问题

**ImportError: attempted relative import beyond top-level package**
→ 确保从项目根目录运行，且已 `pip install -e .`

**NameError: name '_WAL_LOCK' is not defined**
→ 检查模块级锁变量的拼写，wal_manager 使用 `_init_lock` 和 `_replay_lock`

**ConfigRegistry._config_path is None**
→ 确保 `config.toml` 存在，且 `ConfigRegistry.initialize()` 已被调用

**Flask 模板找不到**
→ 检查 `blueprints/__init__.py` 中蓝图是否已注册

### 8.3 Memory 恢复

如果 Claude Code 会话丢失：
- 对话历史：`C:\Users\14183\.claude\projects\F--Home-AIWork-ClaudeWorkBench\*.jsonl`
- Memory 文件：`C:\Users\14183\.claude\projects\F--Home-AIWork-ClaudeWorkBench\memory\`
- 项目上下文：`CLAUDE.md`

---

## 9. 发布流程

### 9.1 PyPI 发布前检查

```bash
# 1. 更新版本号
# 编辑 src/anteumbra/__init__.py → __version__

# 2. 全文搜索旧版本号
grep -r "1\.0\.[0-9]" --include="*.py" --include="*.md" --include="*.toml"

# 3. 跑全部测试
python -m pytest tests/core/ tests/compatibility/ -v

# 4. 更新 CHANGELOG.md

# 5. 更新 README.md 中的版本号和测试计数

# 6. 提交并打 tag
git add -A
git commit -m "v1.0.10: <描述>"
git tag v1.0.10
git push origin main --tags
```

### 9.2 构建和发布

```bash
pip install build twine
python -m build
python -m twine upload dist/*
```

### 9.3 Docker 发布

```bash
docker build -t anteumbra:1.0.10 .
docker tag anteumbra:1.0.10 anteumbra:latest
docker push anteumbra:1.0.10
```

---

<div align="center">
  <sub>Anteumbra Internal Dev Guide — 不入 GitHub，本地使用</sub>
</div>
