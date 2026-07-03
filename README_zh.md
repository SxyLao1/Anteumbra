<div align="center">

<img src="assets/anteumbra-logo.svg" width="120" alt="Anteumbra">

# Anteumbra · 本影

<img src="https://img.shields.io/badge/version-1.0.7-blue?style=flat-square" alt="Version">
<img src="https://img.shields.io/badge/python-3.10%2B-green?style=flat-square" alt="Python">
<img src="https://img.shields.io/badge/platform-Windows%20%7C%20Linux-lightgrey?style=flat-square" alt="Platform">
<img src="https://img.shields.io/badge/license-MIT-yellow?style=flat-square" alt="License">
<img src="https://img.shields.io/badge/tests-217%2F217-brightgreen?style=flat-square" alt="Tests">

**轻量级 Web 边界威胁情报** — 被动检测 · 半主动响应 · 文件级取证

> *"Anteumbra 是部署在 Web 边界的日环食观测站。每一道试图穿透边界的光芒都被记录、度量、溯源。伪装的威胁在自身的炽烈中显形。"*

[English](README.md) | [PyPI](https://pypi.org/project/anteumbra/) | [Issues](https://github.com/SxyLao1/Anteumbra/issues)

</div>

---

Anteumbra（前身 Trident）是一款面向 Linux 和 Windows 的**生产级 Web 边界威胁情报系统**。它实时监控文件系统变化，通过内嵌 YARA 规则引擎检测 WebShell，对攻击者行为进行画像分析，并提供 Web 管理面板——全程不进行内联阻断。它是部署在边界层的一座**安全观测站**。

核心能力：

- **实时文件监控** — Linux Inotify / Windows ReadDirectoryChangesW 自适应切换
- **主动扫描器** — 目录主动扫描，SSE 实时进度推送，扫描历史，可打印报告
- **YARA 规则引擎** — 18+ 规则文件覆盖 PHP/ASP/JSP/ASPX/哥斯拉/冰蝎，支持热重载
- **威胁画像** — 攻击者行为聚类（UA/时间分桶），IP 池合并，衰减引擎
- **文件相似度聚类** — ssdeep/TLSH/SimHash 哈希引擎，0.80 阈值分组
- **IP 封禁台账** — 所有封禁/解封操作审计追踪，内联备注编辑，JSON/CSV 导出
- **双向链接** — 画像 ↔ 检测记录 ↔ 隔离文件交叉导航，攻击链时间线
- **日志启发引擎** — 行为级检测：暴力破解、扫描器、错误风暴、工具指纹、可疑路径
- **内存马检测** — Java/ASP.NET 参考工具 + 访问日志追踪器，关联 WebShell 来源
- **批量操作** — 跨页多选 Records/Quarantine，批量隔离/恢复/删除
- **SIEM 导出** — CEF/JSON Lines/Syslog 格式，文件轮转，实时 UDP 流
- **插件系统** — 配置驱动插件管理器，生命周期管理，事件分发，4 个 WAF 适配器
- **双存储引擎** — JSON + SQLite（WAL 模式，外键约束，13 列索引），可配置后端切换
- **WAL 事务日志** — 异步批量写入，自动轮转，文件锁下最小数据丢失
- **智能告警** — 指数退避 + 自适应阈值，降低误报噪音
- **Web 管理面板** — 暗色终端风界面，SSE 实时日志流，HTMX 驱动，SPA 导航
- **企业安全** — CSRF 防护，IP 白名单，Scrypt 密码哈希，静态 JS 鉴权守卫
- **生产部署** — Docker 多阶段构建，Gunicorn 多 Worker，systemd 服务，`pip install -e .` 开发模式
- **全面测试** — ~217 个测试：88 单元 + 94 E2E 后端 + 34 E2E UI (Playwright) + 1 WAF 代理

## 快速开始

```bash
pip install anteumbra
anteumbra --help
```

### 从源码安装

```bash
git clone https://github.com/SxyLao1/Anteumbra.git
cd Anteumbra
pip install -e .
python -m pytest tests/core/ -v
```

### Windows

```powershell
git clone https://github.com/SxyLao1/Anteumbra.git
cd Anteumbra
.\run_tests.bat
```

### Docker

```bash
docker build -t anteumbra .
docker run -d -p 8080:8080 -v $(pwd)/data:/app/data -v $(pwd)/config.toml:/app/config.toml anteumbra
```

Docker Compose:

```yaml
services:
  anteumbra:
    build: .
    ports: ["8080:8080"]
    volumes:
      - ./data:/app/data
      - ./config.toml:/app/config.toml
    restart: unless-stopped
```

Docker 镜像包含全部三轨哈希引擎（ssdeep + py-tlsh + yara-python），在 Linux 下编译并激活。

然后打开 `http://127.0.0.1:5000/admin`。默认用户名 `admin`，密码在首次启动时打印在控制台中。

## 架构

```
src/anteumbra/
├── domain/               # 领域层：实体 + 端口接口（Plugin, Repository, Detector, Notifier, EventSource）
├── application/          # 应用层：PluginManager（生命周期、事件分发）
├── infrastructure/       # 基础设施：持久化（JSON/SQLite）、检测、监控、配置、工具
└── interfaces/           # 接口层：Flask 蓝图、模板、静态资源
```

架构采用领域驱动设计，四层分离。事件驱动架构（EDA）通过隐式事件总线（PluginManager emit/dispatch 语义）覆盖 85%+ 数据流。SQLite 存储层支持外键约束（ON DELETE SET NULL）和 13 列索引。

## 生态与相关项目

Anteumbra 与以下优秀开源工具互补：

**内存马检测**：
- [c0ny1/java-memshell-scanner](https://github.com/c0ny1/java-memshell-scanner) — 基于 JSP 的 Tomcat/Jetty/WebLogic 扫描器
- [yzddmr6/As-Exploits](https://github.com/yzddmr6/As-Exploits) — ASP.NET 内存马扫描器
- [private-xss/memory-shell-detector](https://github.com/private-xss/memory-shell-detector) — Java GUI+CLI 检测器 (MIT)

**WAF / 日志分析**：
- [SpiderLabs/ModSecurity](https://github.com/SpiderLabs/ModSecurity) — WAF 引擎
- [SpiderLabs/owasp-modsecurity-crs](https://github.com/SpiderLabs/owasp-modsecurity-crs) — OWASP 核心规则集

**哈希与相似度**：
- [ssdeep-project/ssdeep](https://github.com/ssdeep-project/ssdeep) — CTPH 模糊哈希
- [trendmicro/tlsh](https://github.com/trendmicro/tlsh) — Trend Micro 局部敏感哈希

## 附赠工具

`tools/` 目录包含：

- **WAF 代理** (`tools/waf_proxy/`) — 轻量级 HTTP 反向代理，内置 WAF 规则（SQLi、XSS、路径遍历、WebShell 上传、命令注入）。以 JSON Lines 格式生成攻击事件，供威胁画像引擎消费。适用于测试和开发。

```bash
python tools/waf_proxy/waf_proxy.py            # :8081 → :80
python tools/waf_proxy/waf_proxy.py 8081 8080  # 自定义端口
```

## 从 Trident 迁移

Anteumbra 是 [Trident](https://github.com/SxyLao1/Trident) (v1.9.5) 的继任者。如果你正在使用 Trident：

```bash
# 1. 卸载 Trident
cd Trident
.\uninstall.bat      # Windows
# bash uninstall.sh  # Linux

# 2. 安装 Anteumbra
pip install anteumbra

# 3. 复制配置和数据
cp /path/to/Trident/config.toml /path/to/Anteumbra/
cp -r /path/to/Trident/data/ /path/to/Anteumbra/
```

你的 `config.toml` 和 `data/` 目录兼容。

## 许可证

MIT License。自由用于生产环境、学术研究和个人使用。

`tools/` 中捆绑的第三方工具保留其原始许可证。

---

<div align="center">
  <sub>Anteumbra v1.0.7 — MIT License</sub>
</div>
