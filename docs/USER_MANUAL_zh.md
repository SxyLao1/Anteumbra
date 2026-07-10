# Anteumbra 用户手册 v1.0

> **轻量级 Web 边界威胁情报** — 被动检测 · 半主动响应 · 文件级取证

[English](USER_MANUAL.md)

---

## 目录

1. [概述](#1-概述)
2. [安装](#2-安装)
3. [配置](#3-配置)
4. [CLI 命令](#4-cli-命令)
5. [Web 仪表盘](#5-web-仪表盘)
6. [YARA 规则](#6-yara-规则)
7. [威胁画像](#7-威胁画像)
8. [隔离区与封禁台账](#8-隔离区与封禁台账)
9. [SIEM 导出](#9-siem-导出)
10. [插件系统](#10-插件系统)
11. [部署](#11-部署)
12. [故障排查](#12-故障排查)

---

## 1. 概述

Anteumbra 是一个**被动的 Web 边界安全观测平台**。它不会内联阻断流量，而是：

- **监控**你的 Web 根目录，实时检测文件变更
- **扫描**新增/修改的文件，使用 YARA 规则检测 WebShell
- **画像**攻击者，通过 IP、User-Agent 和攻击模式进行聚类
- **隔离**检测到的威胁（手动或自动）
- **告警**通过邮件、微信、Webhook 或 Syslog
- **导出**检测数据到 SIEM 系统

### 架构一览

```
你的 Web 服务器 (Nginx/Apache/IIS)
        │
        ├── 文件变更 ──→ Anteumbra Monitor ──→ YARA 扫描 ──→ Registry
        ├── 访问日志  ──→ 日志启发式分析 ──→ Threat Graph
        └── WAF 事件   ──→ 插件适配器 ──→ 攻击者画像
                                        │
                                Web 仪表盘 (:8080)
```

### 核心概念

| 术语 | 含义 |
|------|------|
| **Registry** | 所有检测到的可疑文件的数据库 |
| **Quarantine** | 检测到的 WebShell 的隔离副本（安全存储） |
| **Threat Graph** | 攻击者行为画像：IP 池、工具签名、风险评分 |
| **Block Ledger** | 所有 IP 封禁/解封操作的审计追踪 |
| **WAL** | 预写日志 — 确保崩溃时的数据持久性 |
| **SSE** | 服务器推送事件 — 实时日志流推送到仪表盘 |

---

## 2. 安装

### 2.1 环境要求

- **Python** 3.10+
- **操作系统**：Windows 10+ 或 Linux（内核 4.x+）
- **可选**：ssdeep、py-tlsh、yara-python（用于完整哈希引擎支持）

### 2.2 从 PyPI 安装

```bash
pip install anteumbra
anteumbra install ./anteumbra-instance
cd ./anteumbra-instance
anteumbra run
```

### 2.3 从源码安装

```bash
git clone https://github.com/SxyLao1/Anteumbra.git
cd Anteumbra
pip install -e ".[dev]"
anteumbra install ./dev-instance --force
cd ./dev-instance
anteumbra run
```

### 2.4 Docker

```bash
docker build -t anteumbra .
docker run -d \
  -p 8080:8080 \
  -v $(pwd)/data:/app/data \
  -v $(pwd)/config.toml:/app/config.toml \
  anteumbra
```

Docker 镜像包含全部三种哈希引擎（ssdeep + py-tlsh + yara-python），已为 Linux 预编译。

### 2.5 首次运行

```bash
anteumbra run
```

首次启动时，Anteumbra 会：
1. 生成一个随机的管理员密码（打印到控制台 — **请保存好**）
2. 如果缺失则创建 `config.toml`（或使用 `anteumbra config`）
3. 启动文件监控器和 Web 仪表盘

打开 `http://127.0.0.1:8080/admin`，使用用户名 `admin` 登录。

---

## 3. 配置

所有设置位于项目根目录的 `config.toml` 中。敏感值使用 `${ENV_VAR:-default}` 语法，从环境变量或 `.env` 文件中解析。

### 3.1 基本设置

```toml
[web_admin]
enabled = true
host = "127.0.0.1"         # 绑定地址 — 为安全起见保持 localhost
port = 8080                # 仪表盘端口
username = "admin"
password_hash = "${ANTEUMBRA_PASSWORD_HASH:-}"  # 使用 werkzeug 生成
allowed_ips = ["127.0.0.1", "192.168.1.0/24"]   # IP 白名单

[website]
name = "My Website"
path = "/var/www/html"     # 要监控的 Web 根目录
port = 80
enabled = true
```

### 3.2 生成密码哈希

```bash
python -c "from werkzeug.security import generate_password_hash; print(generate_password_hash('your-password'))"
```

将输出粘贴到 `config.toml` 中，或在 `.env` 文件中设置 `ANTEUMBRA_PASSWORD_HASH`。

### 3.3 文件监控

```toml
[website.scan_options]
exclude_dirs = ["cache", "logs", "temp", "uploads"]
exclude_files = ["*.log", "*.cache"]

[paths]
monitor_extensions = [".php", ".asp", ".aspx", ".jsp", ".jspx"]
```

### 3.4 告警通知

```toml
[notifier]
enabled = true

[notifier.email]
enabled = true
smtp_host = "smtp.example.com"
smtp_port = 465
username = "${ANTEUMBRA_EMAIL_USERNAME:-}"
password = "${ANTEUMBRA_EMAIL_PASSWORD:-}"
from_addr = "anteumbra@example.com"
to_addrs = ["admin@example.com"]

[notifier.wechat]
enabled = false
send_key = "${ANTEUMBRA_WECHAT_API_KEY:-}"

[notifier.webhook]
enabled = false
```

### 3.5 存储后端

```toml
[storage]
backend = "both"            # "json" | "sqlite" | "both"
db_path = "data/anteumbra.db"
```

- `json` — 简单、人类可读、无依赖
- `sqlite` — 高性能、WAL 模式、外键约束、13 个索引列
- `both` — 双写，SQLite 优先读取（生产环境推荐）

### 3.6 IP 封禁

```toml
[ip_blocker]
enabled = true
auto_block_enabled = false         # 仅在测试后启用
auto_block_min_score = 0.8

[[ip_blocker.devices]]
name = "Main Firewall"
type = "http"
url = "https://firewall.example.com/api/block"
api_key = "${ANTEUMBRA_WAF_API_KEY:-}"
```

### 3.7 完整配置参考

参见 `config.toml` 注释，涵盖 27 个配置节中的 130+ 个配置项。主要配置节：

| 配置节 | 用途 |
|---------|------|
| `[system]` | 项目根目录、发布日期 |
| `[website]` | 要监控的 Web 服务器 |
| `[web_admin]` | 仪表盘设置、分页、SSE 限制 |
| `[monitor]` | Windows/Linux 文件监控器调优 |
| `[registry]` | 异步保存、审计保留策略 |
| `[quarantine]` | 自动隔离开关 |
| `[profiling]` | 攻击者聚类时间窗口 |
| `[ip_blocker]` | 封禁设备和自动封禁规则 |
| `[notifier]` | 邮件、微信、Webhook 告警 |
| `[siem]` | CEF/JSON/Syslog 导出 |
| `[plugins]` | 内置插件和 WAF 适配器 |
| `[storage]` | JSON/SQLite 后端选择 |
| `[thresholds]` | 告警冷却时间、熔断器 |
| `[filesizes]` | WAL 轮转、扫描限制 |
| `[paths]` | YARA 规则、日志目录 |
| `[timeouts]` | HTTP、扫描、配置热加载 |
| `[logging]` | 日志级别、符号、Flask 访问日志 |

---

## 4. CLI 命令

```bash
anteumbra --help          # 显示所有命令
anteumbra --version       # 显示版本

anteumbra run             # 前台启动
anteumbra start           # 以守护进程方式启动（后台）
anteumbra stop            # 停止运行中的实例
anteumbra status          # 检查是否在运行
anteumbra config          # 生成 config.toml 模板
```

### `anteumbra run`
```
选项：
  --host TEXT      绑定地址（默认：127.0.0.1）
  --port INTEGER   绑定端口（默认：5000）
  --debug / --no-debug
```

### `anteumbra start`
```
选项：
  --host TEXT      绑定地址
  --port INTEGER   绑定端口
```

### `anteumbra stop`
停止正在运行的进程。Windows 上使用 `taskkill /F`，Linux 上发送 `SIGTERM` 然后 `SIGKILL`。

### `anteumbra config`
```
选项：
  -o, --output TEXT   输出路径（默认：./config.toml）
```

---

## 5. Web 仪表盘

访问 `http://127.0.0.1:8080/admin`。仪表盘采用深色终端风格主题，使用 HTMX 驱动的 SPA 导航 — 无需页面刷新。

### 5.1 仪表盘（首页）

主仪表盘显示：
- **活跃检测**数量及近期发现
- **威胁画像**及风险评分
- **系统状态**（监控器、WAL、Registry 健康度）
- **实时日志流**通过 SSE

### 5.2 检测记录

`/admin/records` — 所有检测到的可疑文件。

**操作：**
- **查看详情** — 点击任意记录查看完整元数据、关联画像、隔离信息
- **搜索** — 按文件名或特征过滤
- **批量操作** — 选择当前页、跨页保留选择，或用 **All** 选择当前标签页结果集；然后执行隔离 / 标记误报 / 删除
- **文件查看器** — 查看文件内容并高亮语法（最大 512KB）
- **隔离** — 一键隔离检测到的文件
- **标记误报** — 将合法文件从后续告警中排除

### 5.3 隔离区

`/admin/quarantine` — 隔离的 WebShell 副本。

**操作：**
- **恢复** — 将文件移回原始位置（+30 秒白名单，防止重新隔离）
- **删除** — 永久删除
- **批量** — 支持跨页多选后批量恢复/删除隔离记录
- **交叉链接** — 从隔离记录导航回原始检测记录

### 5.4 威胁画像

`/admin/profiles` — 攻击者行为画像。

每个画像显示：
- **风险评分**（0-100）— 该攻击者的危险程度
- **IP 池** — 与该画像关联的所有 IP
- **工具签名** — 识别出的攻击工具（sqlmap、Burp、自定义）
- **攻击链** — 攻击事件的时间线
- **目标文件** — 该攻击者部署了哪些 WebShell
- **状态** — active（活跃）/ dormant（静默，>1h）/ expired（过期，>24h）

点击画像查看完整攻击链时间线、关联记录和文件聚类。

### 5.5 文件聚类

`/admin/file-clusters` — 基于相似度的文件分组。

使用 ssdeep/TLSH/SimHash 将相似度 ≥80% 的文件分组。有助于识别：
- 多态 WebShell 变种
- 同一攻击者部署的多个后门
- 工具生成的载荷模式

### 5.6 封禁台账

`/admin/block-list` — IP 封禁/解封审计追踪。

**功能：**
- 所有封禁操作的完整审计历史
- 内联备注编辑（添加调查备注）
- JSON/CSV 导出，用于合规报告
- 交叉链接到威胁画像

### 5.7 YARA 规则

`/admin/yara/rules` — 规则管理。

**操作：**
- **列表** — 所有 `.yar` 文件及语法验证状态
- **上传** — 添加新规则文件
- **编辑** — 浏览器内编辑器，支持实时语法验证
- **删除** — 软删除到备份目录
- **热加载** — 文件变更时规则自动重新加载

### 5.8 手动扫描器

`/admin/scanner` — 主动目录扫描。

- 选择目标目录
- 通过 SSE 实时显示进度
- 扫描历史，包含结果、耗时、发现数量
- 可打印报告

### 5.9 实时日志流

`/admin` → 日志流面板 — 通过 SSE 实时推送监控日志。

- 级别过滤（可在 `web_admin.sse_log_levels` 中配置）
- 自动滚动，悬停暂停
- 持久化缓冲区（最后 100 行在页面刷新后保留）

### 5.10 设置

`/admin/settings` — 配置管理。

- **配置编辑器** — 在浏览器中编辑 `config.toml`，包含字段说明
- **.env 编辑器** — 管理环境变量
- **通知开关** — 启用/禁用邮件、微信、Webhook
- **SIEM 状态** — 导出统计信息和格式
- **存储状态** — 数据库大小、后端信息
- **插件状态** — 已加载插件及其状态

### 5.11 系统管理

`/admin/system` — 四象限系统视图。

| 象限 | 内容 |
|----------|---------|
| **Registry** | 记录数量、异步保存队列、上次保存时间、压缩 |
| **WAL** | 当前 WAL 大小、归档列表、手动回放 |
| **Sessions** | 活跃会话列表、清理过期会话 |
| **Config** | 热加载触发器、变更历史、YARA 规则统计 |

### 5.12 监控器

`/admin/wal` — 独立的 WAL/监控器视图。

- WAL 状态、归档列表、手动回放
- Registry 压缩触发器
- 会话清理
- 配置热加载历史

---

## 6. YARA 规则

### 6.1 规则目录

默认：`rules/webshell/`。包含 18+ 个规则文件，涵盖：
- PHP WebShell（中国菜刀、蚁剑等）
- ASP/ASPX WebShell
- JSP WebShell（哥斯拉、冰蝎）
- 通用 WebShell 模式

### 6.2 编写自定义规则

```yara
rule My_Custom_WebShell {
    meta:
        description = "检测自定义 WebShell 模式"
        author = "Security Team"
        severity = "high"
    strings:
        $eval1 = "eval($_POST["
        $eval2 = "assert($_REQUEST["
        $cmd1 = "shell_exec("
        $cmd2 = "system("
    condition:
        2 of ($eval*) or any of ($cmd*)
}
```

### 6.3 语法验证

规则在以下时机进行验证：
- 上传时（无效则拒绝）
- 编辑时（实时验证按钮）
- 启动时（无效规则在 UI 中标记）

### 6.4 热加载

YARA 规则通过文件监控器进行监控。变更在 10 秒内生效（可通过 `timeouts.config_reload_delay` 配置）。

---

## 7. 威胁画像

### 7.1 画像工作原理

1. WAF 事件（或日志启发式分析）提供攻击数据：IP、User-Agent、URL、攻击类型
2. 画像按 **UA 指纹** + **时间窗口**（默认 4 小时）进行聚类
3. 在同一时间窗口内使用相同工具的 IP 合并为一个画像
4. 风险评分随重复攻击增加，随时间衰减（半衰期：24 小时）

### 7.2 画像状态

| 状态 | 条件 | 含义 |
|-------|-----------|---------|
| `active` | 最近 1 小时内活跃 | 正在攻击 |
| `dormant` | 最近 1-24 小时内活跃 | 暂停或休眠 |
| `expired` | 最近 > 24 小时未活跃 | 可能已离开 |

### 7.3 衰减引擎

- **24 小时**：风险评分 × 0.5
- **72 小时**：画像标记为静默，评分 × 0.1
- **管理 IP**（在 `[management].ips` 中配置）：不参与画像，但如果部署 WebShell 仍会触发告警

### 7.4 管理 IP

配置属于你安全团队的 IP：
```toml
[management]
ips = ["127.0.0.1", "::1", "10.0.0.5"]
```

这些 IP 的攻击不会污染攻击者画像，但检测告警仍然会触发。

---

## 8. 隔离区与封禁台账

### 8.1 隔离流程

```
检测 → 标记到 Registry → （自动/手动）隔离
                                    │
                          ┌─────────┴──────────┐
                          │  复制到隔离目录    │
                          │  使用随机 ID 命名   │
                          │  更新 Registry     │
                          │  发出告警事件      │
                          └────────────────────┘
```

隔离文件存储在 `quarantine/` 目录中，使用随机 ID 命名 — 原始文件名不会暴露。

### 8.2 自动隔离

```toml
[quarantine]
auto_quarantine_enabled = false   # 谨慎启用
```

启用后，检测到的 WebShell 会自动隔离。默认禁用 — 我们建议先进行人工审查。

### 8.3 封禁台账

每次 IP 封禁/解封操作都会被记录：
- **谁**触发了封禁（系统/用户名）
- **为什么**（原因、关联画像）
- **在哪里**（哪些设备收到了封禁指令）
- **何时**（时间戳）

可导出为 JSON 或 CSV，用于合规审计。

---

## 9. SIEM 导出

### 9.1 配置

```toml
[siem]
enabled = true
format = "json_lines"          # "json_lines" | "cef" | "syslog"
export_file = "data/siem/events.jsonl"
rotate_mb = 100
syslog_host = "192.168.1.100"  # syslog 格式时使用
syslog_port = 514
include_raw_sample = false     # 包含文件的前 256 字节
```

### 9.2 格式

| 格式 | 适用场景 |
|--------|----------|
| **JSON Lines** | Splunk、ELK、自定义管道（推荐） |
| **CEF** | ArcSight、QRadar、HP Enterprise |
| **Syslog** | 传统 SIEM、rsyslog、syslog-ng |

### 9.3 手动导出

从设置页面：`/admin/settings` → SIEM 面板中的"导出"按钮。

---

## 10. 插件系统

### 10.1 内置插件

```toml
[plugins]
enabled = true
builtin = [
    "stdout_logger",
    "quarantine_handler",
    "notifier_handler",
    "threat_graph_handler"
]
```

| 插件 | 功能 |
|--------|----------|
| `stdout_logger` | 将所有事件打印到控制台（调试/开发用） |
| `quarantine_handler` | 执行隔离及隔离后账务处理 |
| `notifier_handler` | 通过邮件/微信/Webhook 发送告警 |
| `threat_graph_handler` | 从检测事件更新攻击者画像 |

### 10.2 WAF 适配器

```toml
[plugins.modsecurity]
enabled = false
audit_log_path = "data/modsec_audit.log"
poll_interval = 5

[plugins.cloudflare]
enabled = false
zone_id = "${CLOUDFLARE_ZONE_ID:-}"
api_token = "${CLOUDFLARE_API_TOKEN:-}"
poll_interval = 60
```

可用适配器：`modsecurity`、`cloudflare`、`aws_waf`、`syslog_waf`。全部默认禁用。

### 10.3 事件流

```
基础设施模块（monitor、registry、block_ledger 等）
        │
        │  pm.emit("event_type", source, payload)
        ▼
PluginManager._event_queue（异步 Fire-and-Forget）
        │
        ▼
PluginManager.dispatch()
        │  每个处理器一个守护线程，30 秒超时
        ▼
Plugin.on_event(event) → Optional[List[DomainEvent]]
```

---

## 11. 部署

### 11.1 使用 Gunicorn 生产部署

```bash
pip install gunicorn
gunicorn -w 4 -b 127.0.0.1:8080 "anteumbra.interfaces.web.factory:create_app()"
```

### 11.2 systemd 服务

```ini
# /etc/systemd/system/anteumbra.service
[Unit]
Description=Anteumbra Web Perimeter Security
After=network.target

[Service]
Type=simple
User=anteumbra
WorkingDirectory=/opt/anteumbra
ExecStart=/opt/anteumbra/venv/bin/python -m anteumbra run --host 127.0.0.1 --port 8080
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
```

### 11.3 Docker Compose

```yaml
services:
  anteumbra:
    build: .
    ports: ["8080:8080"]
    volumes:
      - ./data:/app/data
      - ./config.toml:/app/config.toml
      - ./rules:/app/rules
    environment:
      - ANTEUMBRA_PASSWORD_HASH=${ANTEUMBRA_PASSWORD_HASH}
      - ANTEUMBRA_SECRET_KEY=${ANTEUMBRA_SECRET_KEY}
    restart: unless-stopped
```

### 11.4 安全加固

1. **绑定到 localhost**，除非在带认证的反向代理之后
2. **使用强密码**（通过 werkzeug 的 scrypt 哈希）
3. **IP 白名单**（`web_admin.allowed_ips`）
4. **CSRF 保护**（默认启用）
5. **通过反向代理启用 HTTPS**（前方放置 Nginx/Caddy）
6. **定期备份** `data/` 和 `config.toml`

### 11.5 反向代理（Nginx）

```nginx
server {
    listen 443 ssl;
    server_name security.example.com;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_buffering off;  # SSE 日志流必需
    }
}
```

---

## 12. 故障排查

### 12.1 常见问题

**"ConfigRegistry not initialized"**
→ 确保 `config.toml` 存在。运行 `anteumbra config` 生成模板。

**"端口已被占用"**
→ 另一个 Anteumbra 实例正在运行。使用 `anteumbra stop` 或在 `config.toml` 中更改端口。

**YARA 规则未加载**
→ 检查 `rules/webshell/` 是否存在且包含 `.yar` 文件。检查配置中的 `paths.yara_rules_path`。

**SSE 日志流不工作**
→ 检查 `web_admin.sse_log_levels` — DEBUG 级别默认被排除。确保 Nginx 设置了 `proxy_buffering off`。

**内存占用过高**
→ 降低 `monitor.dir_cache_size` 和 `filesizes.wal_cleanup_count`。检查 `web_admin.sse_max_total_clients`。

**Windows：文件变更未被检测**
→ 确保 `monitor.windows_verify_delay_ms` 至少为 50ms。检查 `paths.monitor_extensions` 是否包含你的文件类型。

### 12.2 日志文件

| 日志 | 路径 | 内容 |
|-----|------|---------|
| Monitor | `logs/{site}/monitor.log` | 文件变更事件、扫描结果、告警 |
| Access | `logs/Anteumbra/access.log` | Flask HTTP 访问日志 |
| System | `logs/Anteumbra/system.log` | 启动、配置热加载、错误 |

### 12.3 健康检查

```
GET /api/v1/health          # 公开健康检查（无需认证）
GET /admin/health            # 需认证的健康检查，含诊断信息
```

### 12.4 获取帮助

- **GitHub Issues**：https://github.com/SxyLao1/Anteumbra/issues
- **README**：项目概览与架构
- **ARCHITECTURE.md**：面向开发者的技术深入文档
- **ANTEUMBRA_USAGE_GUIDE.md**：内部开发指南

---

<div align="center">
  <sub>Anteumbra v1.0.18 — MIT License</sub>
</div>
