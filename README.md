<div align="center">

<img src="assets/anteumbra-logo.svg" width="120" alt="Anteumbra">

# Anteumbra

<img src="https://img.shields.io/badge/version-1.0.28-blue?style=flat-square" alt="Version">
<img src="https://img.shields.io/badge/python-3.10%2B-green?style=flat-square" alt="Python">
<img src="https://img.shields.io/badge/platform-Windows%20%7C%20Linux-lightgrey?style=flat-square" alt="Platform">
<img src="https://img.shields.io/badge/license-MIT-yellow?style=flat-square" alt="License">

**Lightweight Web Perimeter Security**<br>
Passive detection, semi-active response, file-level forensics, and attacker profiling.

[中文](README_zh.md) | [User Manual](docs/USER_MANUAL.md) | [Architecture](docs/ARCHITECTURE.md) | [Release Guide](docs/RELEASE.md) | [PyPI](https://pypi.org/project/anteumbra/) | [Issues](https://github.com/SxyLao1/Anteumbra/issues)

</div>

---

Anteumbra is a web perimeter threat-intelligence and WebShell detection platform for Windows and Linux. It watches website directories, detects suspicious PHP/ASP/JSP/ASPX files with YARA rules, correlates access logs, profiles attacker behavior, and provides a web dashboard for triage, quarantine, restoration, audit, and reporting.

Anteumbra is installed as one product. PyPI users and source-install developers both create runtime instances with the same `anteumbra install` and `anteumbra config` workflow.

## Operational Scope

Anteumbra is designed for one host or a small web workload: filesystem integrity monitoring, WebShell detection, local triage and response, and export to an existing security stack. It is not a replacement for an inline WAF, endpoint detection and response, a SIEM, centralized fleet management, or distributed high availability.

## Documentation

| Need | English | Chinese |
| --- | --- | --- |
| Install, configure, operate | [User Manual](docs/USER_MANUAL.md) | [用户手册](docs/USER_MANUAL_zh.md) |
| Internal architecture and extension points | [Architecture](docs/ARCHITECTURE.md) | [架构文档](docs/ARCHITECTURE_zh.md) |
| Release and PyPI publishing | [Release Guide](docs/RELEASE.md) | - |

## Quick Start

```bash
pip install anteumbra
anteumbra install ./anteumbra-instance
cd ./anteumbra-instance
anteumbra config wizard
anteumbra config validate
anteumbra run
```

Open `http://127.0.0.1:8080/admin`. The default username is `admin`; the initial password is printed by `anteumbra install`. You can set a new password in `anteumbra config wizard`.

YARA scanning is included in the base install. Optional similarity engines are
available through the `full` extra:

```bash
pip install anteumbra           # includes yara-python
pip install "anteumbra[full]"  # adds ssdeep and py-tlsh
```

`anteumbra[yara]` remains accepted as a compatibility alias but adds no
dependencies beyond the base package.

## Common Configuration

Use the wizard for first-run setup:

```bash
anteumbra config wizard
anteumbra config validate
```

Use preset commands for access-log analysis. This avoids hand-writing platform-specific paths and Tomcat wildcards:

```bash
anteumbra config access-log nginx
anteumbra config access-log apache
anteumbra config access-log tomcat --base /opt/tomcat
anteumbra config access-log custom --path /path/to/access.log
anteumbra config access-log none
```

Low-level scripted edits are still available:

```bash
anteumbra config set website.path /var/www/html
anteumbra config set web_admin.port 8080
anteumbra config env set ANTEUMBRA_WECHAT_API_KEY your-send-key
anteumbra config reload
```

For the full command reference, see [CLI Commands](docs/USER_MANUAL.md#4-cli-commands).

## Core Capabilities

- Multi-site file monitoring on Windows and Linux
- Manual scans with scan history and printable reports
- YARA-based WebShell detection for PHP, ASP, JSP, ASPX, Godzilla, Behinder, and related families
- 27 packaged YARA files compiled independently, so one invalid custom rule file does not disable the remaining rules
- Access-log behavior analysis for Nginx, Apache, and Tomcat
- Attacker profiling, IP reputation, attack chain timelines, and cross-page batch actions
- Quarantine, restore, false-positive marking, and audit trail workflows
- JSON and SQLite storage backends with WAL support
- SIEM export in CEF, JSON Lines, and Syslog formats
- Web dashboard with merged historical/live SSE logs, runtime capability status, and configuration management
- Plugin manager and WAF/event-source integration points

## Source Install

Use a source install for development, testing, or local code changes. Runtime setup remains the same as the PyPI flow.

```bash
git clone https://github.com/SxyLao1/Anteumbra.git
cd Anteumbra
pip install -e ".[dev]"
anteumbra install ./dev-instance --force
cd ./dev-instance
anteumbra config wizard
anteumbra run
```

Run tests from the repository root:

```bash
python -m pytest
```

## Docker

```bash
docker build -t anteumbra .
docker run -d --name anteumbra \
  -p 18080:8080 \
  -v $(pwd)/anteumbra-data:/app/data \
  -v $(pwd)/anteumbra-logs:/app/logs \
  anteumbra
docker logs anteumbra
```

The container starts the same full runtime as `anteumbra run`, creates a Docker-friendly default config on first start, and prints the initial admin password in `docker logs`. Open `http://127.0.0.1:18080/admin`.

## Architecture

Anteumbra follows a layered structure:

```text
src/anteumbra/
  domain/          # Entities and ports
  application/     # Use cases and orchestration
  infrastructure/  # Persistence, detection, monitoring, config, utilities
  interfaces/      # CLI, Flask blueprints, templates, static assets
```

See [Architecture](docs/ARCHITECTURE.md) for module boundaries, extension guidance, and integration contracts.

## Migration From Trident

Anteumbra is the successor to Trident. Existing `config.toml` and `data/` directories are intended to remain compatible; install Anteumbra, create a runtime instance, then copy your existing configuration and data into that instance. See the [User Manual](docs/USER_MANUAL.md) before production migration.

## License

MIT License. Third-party tools bundled under `tools/` retain their original licenses.

---

<div align="center">
  <sub>Anteumbra v1.0.28 · MIT License</sub>
</div>
