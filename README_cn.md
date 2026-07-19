<div align="center">

<img src="assets/anteumbra-logo.svg" width="120" alt="Anteumbra">

# Anteumbra · 本影

<img src="https://img.shields.io/badge/version-1.0.31-blue?style=flat-square" alt="Version">
<img src="https://img.shields.io/badge/python-3.10%2B-green?style=flat-square" alt="Python">
<img src="https://img.shields.io/badge/platform-Windows%20%7C%20Linux-lightgrey?style=flat-square" alt="Platform">
<img src="https://img.shields.io/badge/license-MIT-yellow?style=flat-square" alt="License">

**轻量级 Web 边界安全平台**<br>
被动检测、半主动响应、文件级取证与攻击者画像。

[English](README.md) | [用户手册](docs/USER_MANUAL_cn.md) | [架构文档](docs/ARCHITECTURE_cn.md) | [路线图](ROADMAP_cn.md) | [发布指南](docs/RELEASE_cn.md) | [PyPI](https://pypi.org/project/anteumbra/) | [Issues](https://github.com/SxyLao1/Anteumbra/issues)

</div>

---

Anteumbra 是面向 Windows 与 Linux 的 Web 边界威胁情报和 WebShell 检测平台。它监控站点目录，使用 YARA 规则检测可疑 PHP/ASP/JSP/ASPX 文件，关联访问日志，建立攻击者画像，并提供 Web 面板完成研判、隔离、还原、误报标记、审计和报告。

Anteumbra 按一个产品交付。PyPI 用户和源码安装开发者都使用同一套 `anteumbra install` 与 `anteumbra config` 流程创建运行实例。

## 使用边界

Anteumbra 面向单机或小规模 Web 负载：提供文件完整性监控、WebShell 检测、本地研判与响应，并向既有安全体系输出标准告警或 SIEM 事件。它不替代内联 WAF、EDR、SIEM、集中化主机管理或分布式高可用平台。

## 文档导航

| 需求 | 中文 | English |
| --- | --- | --- |
| 安装、配置、日常使用 | [用户手册](docs/USER_MANUAL_cn.md) | [User Manual](docs/USER_MANUAL.md) |
| 内部架构、扩展点、模块边界 | [架构文档](docs/ARCHITECTURE_cn.md) | [Architecture](docs/ARCHITECTURE.md) |
| 当前状态与后续计划 | [路线图](ROADMAP_cn.md) | [Roadmap](ROADMAP.md) |
| 版本变更历史 | [更新日志](CHANGELOG_cn.md) | [Changelog](CHANGELOG.md) |
| 发布与 PyPI 推送 | [发布指南](docs/RELEASE_cn.md) | [Release Guide](docs/RELEASE.md) |
| 内存马响应参考工具 | [工具说明](tools/memory-shell/README_cn.md) | [Toolkit](tools/memory-shell/README.md) |

## 快速开始

```bash
pip install anteumbra
anteumbra install ./anteumbra-instance
cd ./anteumbra-instance
anteumbra config wizard
anteumbra config validate
anteumbra run
```

`pip install` 将程序代码安装到当前 Python 环境；`anteumbra install INSTANCE_DIR`
创建可明确指定位置的运行实例，其中保存 `config.toml`、`.env`、数据、日志、规则和
隔离文件。两者不是两套产品。生产或日常使用建议把程序装入专用虚拟环境，而不是与
其他 Python 工具共用全局环境。

在任何工作目录都可以显式选择运行实例：

```bash
anteumbra --home /opt/anteumbra config wizard
anteumbra --home /opt/anteumbra start
```

Windows 路径同样可直接指定，例如
`anteumbra install E:\Software\Anteumbra`。

打开 `http://127.0.0.1:8080/admin`。默认用户名是 `admin`；初始密码由 `anteumbra install` 打印。也可以在 `anteumbra config wizard` 中输入新密码。

基础安装已包含 YARA 扫描。需要相似度引擎时安装 `full` 扩展：

```bash
pip install anteumbra           # 已包含 yara-python
pip install "anteumbra[full]"  # 增加 ssdeep 和 py-tlsh
```

`anteumbra[yara]` 仍可作为兼容旧命令的别名使用，但不会在基础包之外增加依赖。

## 常用配置

首次配置推荐使用向导：

```bash
anteumbra config wizard
anteumbra config validate
```

访问日志分析推荐使用预设命令，避免手写平台路径和 Tomcat 通配符：

```bash
anteumbra config access-log nginx
anteumbra config access-log apache
anteumbra config access-log tomcat --base /opt/tomcat
anteumbra config access-log custom --path /path/to/access.log
anteumbra config access-log none
```

仍然可以使用底层脚本式配置命令：

```bash
anteumbra config set website.path /var/www/html
anteumbra config set web_admin.port 8080
anteumbra config env set ANTEUMBRA_WECHAT_API_KEY your-send-key
anteumbra config reload
```

`config reload` 会完整解析所选部署配置，但不会修改正在运行的服务。
需要从 Web 系统页应用运行时配置，或重启服务。

直接运行 `anteumbra config` 只显示子命令帮助，不会创建或覆盖文件。初始化必须显式
使用 `anteumbra config init`；只有 `config init --force` 才会无提示替换现有
`config.toml` 和 `.env`。

完整命令参考见 [CLI 命令](docs/USER_MANUAL_cn.md#4-cli-命令)。

## 核心能力

- Windows / Linux 多站点文件监控
- 手动扫描、扫描历史和可打印报告
- 基于 YARA 的 PHP、ASP、JSP、ASPX、哥斯拉、冰蝎等 WebShell 检测
- 内置 27 个独立编译的 YARA 规则文件；单个自定义规则文件错误不会禁用其他规则
- Nginx、Apache、Tomcat 访问日志行为分析
- 攻击者画像、IP 信誉、攻击链时间线和跨页批量操作
- 隔离、还原、误报标记和审计流
- JSON 与 SQLite 双存储后端，支持 WAL
- CEF、JSON Lines、Syslog 格式 SIEM 导出
- 带历史/实时合并 SSE 日志、运行能力状态和配置管理的 Web 面板
- 插件管理器与 WAF / 事件源扩展接口

## 源码安装

源码安装适合开发、测试或本地改代码。运行实例的创建方式仍然与 PyPI 流程一致。

```bash
git clone https://github.com/SxyLao1/Anteumbra.git
cd Anteumbra
pip install -e ".[dev]"
anteumbra install ./dev-instance --force
cd ./dev-instance
anteumbra config wizard
anteumbra run
```

在仓库根目录运行测试：

```bash
python -m pytest
```

## Docker

```bash
docker build -t anteumbra .
docker run -d --name anteumbra \
  -p 127.0.0.1:18080:8080 \
  -v $(pwd)/anteumbra-data:/app/data \
  -v $(pwd)/anteumbra-logs:/app/logs \
  anteumbra
docker logs anteumbra
```

容器会启动与 `anteumbra run` 相同的完整运行时，首次启动自动生成 Docker 友好的默认配置，
将本机 Docker 网关加入后台 IP 白名单，并在 `docker logs` 中打印初始管理员密码。打开
`http://127.0.0.1:18080/admin`。

## 架构

Anteumbra 采用分层结构：

```text
src/anteumbra/
  domain/          # 实体与端口
  application/     # 用例与编排
  infrastructure/  # 持久化、检测、监控、配置、工具
  interfaces/      # CLI、Flask 蓝图、模板、静态资源
```

模块边界、扩展指南和集成契约见 [架构文档](docs/ARCHITECTURE_cn.md)。

## 从 Trident 迁移

Anteumbra 是 Trident 的后继项目。现有 `config.toml` 和 `data/` 目录设计上保持兼容；安装 Anteumbra、创建运行实例后，再复制旧配置和数据。生产迁移前建议先阅读 [用户手册](docs/USER_MANUAL_cn.md)。

## 许可证

MIT License。`tools/` 下捆绑的第三方工具保留其原始许可证。

---

<div align="center">
  <sub>Anteumbra v1.0.31 · MIT License</sub>
</div>
