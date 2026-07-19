# Anteumbra 更新日志

> Anteumbra Web 边界威胁情报平台的主要变更记录。

[English](CHANGELOG.md)

---

## [未发布]

### 修复
- 在清除应用响应头之外禁用 Waitress 的 `Server` 标识，生产 HTTP 响应不再暴露
  Anteumbra 产品指纹。
- Monitor Logger 所有权、`[site=<id>]` 归属标签与 `logs/<site_id>/monitor.log`
  路径改用稳定站点 ID；旧版原始站名和清洗站名两种日志目录都会迁移并保留为历史，
  站点改名不再隐藏日志或创建第二条日志流。
- 配置中的站点显示名按稳定 `website.id` 规范化；站点改名会刷新 Registry/隔离元数据，
  但不会改变数据归属。
- `legacy` 仅保留给未归属记录；旧配置缺少 ID、从名称推导易受改名影响时，配置校验会
  明确警告。
- 本地残留 `build/lib` 中已删除的模块不再悄悄混入 Wheel；CI 与发布流程会拒绝
  源码中不存在的包文件。
- 缺少密码的登录表单会在 Hash 校验与限流计数前返回 400，不再让畸形 POST 在
  Werkzeug 中触发 500。
- ThreatGraph 的画像、IP/文件信誉、持久化、WAF 摄入、Registry 关联和公开查询全部按
  `site_id` 隔离；跨站点歧义查询不再猜测站点。
- 部分初始化的插件资源会被关闭；启动失败明确返回错误，不再泄漏 Worker 或让 CLI
  错误地成功退出。
- Waitress 关闭时会断开 SSE 与 keep-alive Channel、唤醒事件循环并停止任务调度器；
  浏览器驱动的 Runtime 不再耗尽关闭超时或遗留服务线程。
- 内存采样降级统一由 Metrics 处理；Web/插件不再读取 Metrics、聚类、ThreatGraph 或
  Notifier 私有状态。

### 变更
- 仪表盘与 SSE 历史统一通过 Runtime Logging/SSE Port 读取，不再硬编码 `logs/` 和
  `data/` 路径。
- CLI 脚本修改 `website.id` 必须显式确认，并会规范化旧 `website.site_id` 别名；正常
  站点改名只修改 `website.name`。
- 用实例所有的 `RuntimeLifecycle` 与强类型 `RuntimeState` 替换 Launcher 模块全局状态及
  `start_all`/`stop_all` 门面。
- 将登录失败限流从 Web 蓝图可变全局状态移入 `RuntimeContainer` 所有的
  `LoginRateLimiter`；App/测试 Runtime 不再共享计数，登录成功只重置当前客户端。
- 为插件、Scanner/YARA、文件聚类、ThreatGraph、Notifier、SIEM、SSE、WAL 和 WAF
  增加聚焦 Domain Protocol；`RuntimeContainer` 只对真正可禁用的能力保留 `None`。
- 删除 Runtime 对 HashEngine 与 MemoryShellTracer 无效引用；FileClusterEngine 改为输出
  不可变、线程安全快照。
- 中文文档统一使用 `*_cn.md`，补齐中文路线图、更新日志、发布指南和内存马工具说明，
  并增加文档配对/链接治理测试。
- CI 显式执行 Ruff，Wheel CLI 或 Docker 健康冒烟失败不再被放行。
- Pytest 固定从 `src` 布局导入，测试启动时会拒绝已安装的 `site-packages` 副本，
  源码回归不能再对旧 Wheel 产生假通过。

### 测试
- 当前源码通过 496 项非浏览器测试、41 项 Playwright UI 测试、Ruff、
  `git diff --check` 和 116 个包模块导入扫描。
- 新增 Runtime 实例所有权、服务边界、站点文件/画像查询、不可变聚类快照、通知公开
  API、WAF 源信息、文档治理、严格 CI 和打开 keep-alive 时关闭 Waitress 的回归测试。
- 新增确定性的登录限流单元与 HTTP 回归，覆盖窗口、单客户端重置、Runtime 隔离、
  登录成功重置和 GET 不计数。
- 新增稳定 ID 站点改名、历史显示名规范化、保留/派生 ID 校验和 CLI 显式身份变更回归。
- 新增稳定站点日志路径、旧日志迁移冲突、多站点历史归属与顺序、转义渲染及生产环境
  不返回 `Server` 头的回归。

---

## [1.0.28] - 2026-07-18

### 修复
- Registry 身份改为站点限定，同一路径可在两个网站独立记录、标记、还原或隔离。
- 移动文件进入统一排队扫描链，保留站点归属、告警、指标、隔离和 SIEM 行为。
- 通知批次、指标、仪表盘、扫描历史和隔离操作按明确站点所有权分区。
- 明确 JSON 为权威数据，SQLite 为影子与恢复来源；站点限定 SQLite 键不再污染 JSON 路径。
- Block Ledger 与 ThreatGraph 不再优先读取过期 SQLite 影子数据。
- 补齐模型前向注解所需的 `datetime` 导入。
- CLI 后台启动必须获得成功 HTTP 健康响应，不能只因 Waitress 绑定 Socket 就判定就绪。
- Windows SSE 关闭会保留终止信号，直到生成器消费后再关闭 Waitress Trigger。
- SQLite 影子锁等待有界，进程内 Schema 初始化串行化，影子争用不会阻塞 JSON 主流程。

### 变更
- 增加 `SiteIdentity`、`SiteResolver`、运行时 Port/Adapter 与站点仪表盘读模型。
- SQLite 增加站点元数据和索引，同时保留完整原始记录。
- 中英文架构与用户手册补充站点所有权、运行时组装、事件传播和 JSON 权威存储。
- Ruff 成为开发依赖，并启用全项目致命语法/未定义名称门禁。

### 测试
- 覆盖 Registry 站点身份、站点扫描选项、通知分批、仪表盘、移动文件、还原隔离、
  JSON 权威读取和 SQLite 影子存储。
- 发布时完成非浏览器/UI、Wheel、全新安装、源码安装和健康端点验证。

## [1.0.27] - 2026-07-17

### 修复
- Docker 使用包内配置模板，默认容器加载 SIEM 事件桥。
- Windows 后台启动使用无缓冲输出，并以连续监听检查提高失败日志可用性。
- 本地 `config.toml` 优先拥有运行实例，不再被已登记全局实例覆盖。
- 文件监控与插件队列改为有界背压；超时插件 Handler 数量受限并暂停不健康插件。
- 启动时扫描既有脚本，并显式关闭 Monitor Worker。
- 禁用日志监控的站点不会为每次检测重复输出 Nginx 日志缺失告警。
- 人工还原文件在保护窗口内不会再次扫描、告警、导出、登记或隔离。
- 仅信任配置的代理 IP/CIDR 转发头，允许 IP 检查支持 CIDR。

### 变更
- 用 Waitress 替换过期 Gunicorn 路径。
- 增加 `siem_handler`，把 `record_added` 事件发送到 SIEM。
- YARA 逐文件编译、错误隔离、失败重载保留有效规则；THOR 拆为九个分片，共 27 个规则文件。
- 补充 PHP/ASP/ASPX/JSP 通用行为规则并收紧通用 `eval` 误报。

### 测试
- 覆盖后台就绪、本地 Runtime Root、代理、Waitress、YARA 故障隔离、队列背压、还原去重、
  SIEM 和健康检查；同时验证 Windows 全新实例、Docker 与可编辑源码安装。

## [1.0.26] - 2026-07-17

### 修复
- 每个启用网站独立启动文件/访问日志 Monitor，所有成功资源可确定关闭。
- JSONL Tailer 支持逐条确认、游标、轮转/截断与死信，毒消息不会阻塞画像。
- 隔离、还原、永久删除在 Registry 失败时补偿文件操作；批量接口逐项报告失败。
- 自动隔离在配置或还原保护不可用时保守失败。
- 去除 SSE 连接噪音、合并站点历史日志、增加心跳并展示通知状态。
- 新模板默认关闭不完整外部通知通道，并验证 WeChat TLS。
- CLI 启停、PID、监听和 Windows `taskkill` 失败语义改为明确非零退出。
- 安装与 `config init` 生成持久高熵 Flask Secret 和 16 位初始密码。
- 修复 Flask-Session 后端、Scanner 终态/取消/扩展名和导航竞态等问题。
- 只读安装注册表不再让完整实例安装失败；后台日志强制 UTF-8。

### 变更
- 增加 Runtime Health、访问日志分析、事务隔离和可靠 JSONL Application Service。
- Nginx、Apache、Tomcat 日志按站点分析。
- 基础包包含 `yara-python`；`full` 仅增加 `ssdeep` 与 `py-tlsh`。
- 健康端点统一区分可选降级（200）和关键配置/Registry/WAL 失败（503）。

### 测试
- 浏览器批量测试改为真实后端流程，覆盖源文件、Registry 与 Quarantine 状态。
- 发布时通过全链路 Wheel、Docker、Windows 运行与 41 项 UI 测试。

## [1.0.25] - 2026-07-11

### 修复
- Docker 使用 `/opt/venv`，非 root `anteumbra` 用户可执行 Console Script。
- 默认命令运行完整 `anteumbra run`，Entrypoint 生成首次配置并输出密码。
- Docker 默认监控 `/app/sites/default`，关闭演示 MockWAF。

### 验证
- 构建并启动镜像，健康检查成功；PHP 探针产生 YARA 命中和可疑指标。

## [1.0.24] - 2026-07-11

- 支持 Tomcat `localhost_access_log.*.txt` 日期轮转日志。
- CLI 增加 `nginx`、`apache`、`tomcat`、`custom`、`none` 预设及回归测试。

## [1.0.23] - 2026-07-11

- Web 仪表盘增加访问日志分析状态与审计信号。
- 降低 SSE 噪音并展示 Notifier 投递状态。

## [1.0.22] - 2026-07-11

- CLI 启动遵循配置的 Admin Host/Port。
- 增加首次配置、验证流程，并统一 PyPI/源码 Runtime 文档。

## [1.0.21] - 2026-07-11

- 提高全新实例首次启动可靠性，统一 Launcher、内置配置与 CLI 启动路径。

## [1.0.20] - 2026-07-11

- 建立大规模架构工作前的清理基线，收紧导入边界并清理发布、插件和静态资源组织。

## [1.0.19] - 2026-07-11

- YARA 缺失时 Web 与规则管理仍可启动，`yara-python` 成为真实可选依赖。
- 补充无 YARA 创建 Flask App 的回归与安装文档。

## [1.0.18] - 2026-07-11

- 包元数据改为 SPDX License 字符串，`setuptools>=77.0` 与该格式保持一致。
- 用户手册统一 PyPI 与源码使用 `anteumbra install <instance-dir>`。

## [1.0.17] - 2026-07-11

- Wheel 包含部署 `config.toml`，缺失模板时安装明确失败。
- `anteumbra start` 使用已安装包入口，不再依赖源码 `run.py`。
- CLI/配置/Launcher 默认端口统一为 8080。

## [1.0.16] - 2026-07-10

- 手动扫描由 GET 副作用改为 POST 创建 Job，并通过认证 SSE 订阅结果。

## [1.0.15] - 2026-07-10

- 删除失效 `require_auth_except_sse`；短 MD5 明确仅作展示摘要。
- `_shared.py` 删除直接 `ConfigRegistry` 依赖并收紧架构守卫。

## [1.0.10] - 2026-07-05

### 修复
- 将四个内置插件移动进 `src/anteumbra/plugins/`，修复 pip 安装后插件静默失效。
- 修复隔离页字段兼容、密码修改 415、FileMonitorHandler 缺少 website 和首次 SSE 日志崩溃。

### 变更
- 插件诊断进入轮转日志；密码 Hash 由 `.env` 提供；`.env` 模板补全通知字段。

## [1.0.9] - 2026-07-05

- 增加 `anteumbra install [path]` 与 Launcher 模块。
- Wheel 包含模板、静态资源、翻译和 YARA；资源统一移动到包目录。

## [1.0.8] - 2026-07-04

- 修复 pytest Registry 路径隔离和 WAF 到 Block Ledger 全链路路径键。

## [1.0.6] - 2026-07-03

- 将 2280 行 `admin_bp.py` 拆为 admin/settings/monitor/system 四个 Blueprint，URL 不变。
- `/admin/debug/routes` 与 `/admin/test` 增加认证，清理拆分后的无效 import。

## [1.0.5] - 2026-07-03

- 增加 Python 3.10/3.11/3.12、Playwright、Docker 和 Trusted Publishing CI/CD。
- 增加 73 项自动化测试和模板 i18n，建立单一版本来源。
- 统一 ScanResult、HTML Escape、EmergencyScanner、YARA Fallback 与 Jinja 模板错误。

## [1.0.4] - 2026-07-03

- SQLite 增加外键、索引和自动 Schema Migration。
- Docker 多阶段、非 root、Healthcheck；开发依赖与 Python 下限更新。
- 修复 SSE/Playwright 导航、Settings 超时和登录 Hash 测试。

## [1.0.3] - 2026-07-02

- Block Ledger 接入 Repository，增加 JSON 审计、Blocklist 编辑/导出和画像/记录/隔离双向链接。
- Admin Blueprint 继续拆分为 records/profiles/blocklist。

## [1.0.2] - 2026-07-01

- Suspicious Registry 六类写操作事件化；Monitor 通过隔离/通知/画像桥接插件解耦。
- 增加同步 Dispatch 超时、后端 E2E、34 项 UI、兼容测试、WAL/Session 页面和配置 SSE。
- 修复隔离/误报静默失败和测试模块级副作用。

## [1.0.1] - 2026-06-30

- PluginManager 增加异步 `emit()` 与同步 `dispatch()`，引入 App Factory。
- 修复 Worker RLock 死锁和误报标记后 Registry 不刷新。

## [1.0.0] - 2026-06-28

- Trident 正式更名为 Anteumbra，建立 Domain/Application/Infrastructure/Interfaces 四层目录。
- 增加事件驱动 PluginManager、统一 CLI、Flask-Babel、Registry/Quarantine/批量流程、审计状态、
  Scanner 跨页选择、中英文 README 和 SVG Logo。
- 删除旧 Trident `start.bat`、`stop.bat`、`install.py`，统一使用 CLI。

## [Trident v1.9.5] - 2026-06-28（归档）

DDD 迁移前最后一个 Trident 版本，对应 `legacy-trident-v1.9.5` Tag。其成果包括 Blueprint/JS
拆分、SQLite WAL 与 DualWriteRepository、Plugin/WAF Adapter、日志启发式、SIEM、内存马
Tracer、Gunicorn 配置和 79 项核心测试。

---

## 版本规则

```text
v<里程碑>.<功能>.<bug修复>

里程碑：架构或产品代际
功能：一组面向用户的新能力
bug修复：Bug、可靠性、优化和兼容清理
```

- **v1.0.x**：DDD 迁移与技术债务收口。
- **v1.1.x**：多站点运营界面与扩展 SDK（计划）。
- **v2.0.x**：异步 EventBus 与分布式核心（远期）。
