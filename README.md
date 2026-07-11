<div align="center">

<img src="assets/anteumbra-logo.svg" width="120" alt="Anteumbra">

# Anteumbra

<img src="https://img.shields.io/badge/version-1.0.20-blue?style=flat-square" alt="Version">
<img src="https://img.shields.io/badge/python-3.10%2B-green?style=flat-square" alt="Python">
<img src="https://img.shields.io/badge/platform-Windows%20%7C%20Linux-lightgrey?style=flat-square" alt="Platform">
<img src="https://img.shields.io/badge/license-MIT-yellow?style=flat-square" alt="License">
<img src="https://img.shields.io/badge/tests-394%20passing-brightgreen?style=flat-square" alt="Tests">

**Lightweight Web Perimeter Security** — Passive Detection · Semi-Active Response · File-Level Forensics

> *"Anteumbra is an annular eclipse observatory at the web perimeter. Every ray that tries to pierce the boundary is recorded, measured, and traced back to its source. Disguised threats reveal themselves in their own blazing intensity."*

[中文文档](README_zh.md) | [PyPI](https://pypi.org/project/anteumbra/) | [Issues](https://github.com/SxyLao1/Anteumbra/issues)

</div>

---

Anteumbra (formerly Trident) is a production-grade **web perimeter threat intelligence** system for Linux and Windows. It monitors file system changes in real time, detects WebShells using an embedded YARA rule engine, profiles attacker behavior, and provides a web-based management dashboard — all without inline blocking. Think of it as a **security observatory** at the boundary layer.

Key capabilities:

- **Real-time file monitoring** — Linux Inotify / Windows ReadDirectoryChangesW adaptive switching
- **Manual scanner** — Active directory scanning with SSE real-time progress, scan history, printable reports
- **YARA rule engine** — 18+ rule files covering PHP, ASP, JSP, ASPX, Godzilla, Behinder; hot-reload supported
- **Threat profiling** — Attacker behavior clustering via UA/time-bucket, IP pool merging, decay engine
- **File similarity clustering** — ssdeep/TLSH/SimHash hash engine with 0.80 threshold grouping
- **IP block ledger** — Audit trail for all block/unblock operations, inline note editing, JSON/CSV export
- **Bidirectional linking** — Profile ↔ Records ↔ Quarantine cross-navigation, attack chain timeline
- **Log heuristic engine** — Behavior-level detection: brute force, scanner, error storm, tool signature, suspicious path
- **Memory shell detection** — Java/ASP.NET reference tools + access log tracer for WebShell origin correlation
- **Batch operations** — Cross-page multi-select for Records/Quarantine with batch quarantine/restore/delete
- **SIEM export** — CEF/JSON Lines/Syslog formats with file rotation and real-time UDP streaming
- **Plugin system** — Config-driven plugin manager with lifecycle, event dispatch, 4 WAF adapters
- **Dual storage** — JSON + SQLite (WAL mode, FK constraints, indexed) with configurable backend switching
- **WAL transaction logs** — Async batch writes with auto rotation, minimal data loss under file locking
- **Smart alerting** — Exponential backoff with adaptive thresholds to reduce false positives
- **Web dashboard** — Dark theme terminal-style interface, SSE real-time log stream, HTMX-driven, SPA navigation
- **Enterprise security** — CSRF protection, IP whitelist, Scrypt password hashing, static JS auth guard
- **Production deployment** — PyPI install, Docker multi-stage build, Gunicorn multi-worker, systemd service
- **Comprehensive test suite** — ~340 tests: 88 unit + 94 E2E backend + 34 E2E UI (Playwright) + 1 WAF proxy

## Quick Start

```bash
pip install anteumbra
anteumbra install ./anteumbra-instance
cd ./anteumbra-instance
anteumbra run
```

Then open `http://127.0.0.1:8080/admin`. Default username is `admin`; password is printed by `anteumbra install`.

Install `anteumbra[yara]` to enable compiled YARA rule validation and scanning, or `anteumbra[full]` for YARA plus optional similarity hash engines.

### Source Install

Use source install only for development, testing, or local code changes. It still creates runtime instances through the same `anteumbra install` command:

```bash
git clone https://github.com/SxyLao1/Anteumbra.git
cd Anteumbra
pip install -e ".[dev]"
anteumbra install ./dev-instance --force
cd ./dev-instance
anteumbra run
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

The Docker image includes all three hash engines (ssdeep + py-tlsh + yara-python) compiled and active for Linux.

## Architecture

```
src/anteumbra/
├── domain/               # Domain layer: entities + ports (Plugin, Repository, Detector, Notifier, EventSource)
├── application/          # Application layer: PluginManager (lifecycle, event dispatch)
├── infrastructure/       # Infrastructure: persistence (JSON/SQLite), detection, monitoring, config, utils
└── interfaces/           # Interfaces: Flask blueprints, templates, static assets
```

Architecture follows Domain-Driven Design with four separated layers. Event-driven architecture (EDA) covers 85%+ of the data flow via implicit event bus (PluginManager with emit/dispatch semantics). SQLite storage layer features foreign key constraints (ON DELETE SET NULL) and 13 indexed columns.

## Ecosystem & Related Projects

Anteumbra is designed to complement these excellent open-source tools:

**Memory Shell Detection**:
- [c0ny1/java-memshell-scanner](https://github.com/c0ny1/java-memshell-scanner) — JSP-based Tomcat/Jetty/WebLogic scanner
- [yzddmr6/As-Exploits](https://github.com/yzddmr6/As-Exploits) — ASP.NET memory shell scanner
- [private-xss/memory-shell-detector](https://github.com/private-xss/memory-shell-detector) — Java GUI+CLI detector (MIT)

**WAF / Log Analysis**:
- [SpiderLabs/ModSecurity](https://github.com/SpiderLabs/ModSecurity) — WAF engine
- [SpiderLabs/owasp-modsecurity-crs](https://github.com/SpiderLabs/owasp-modsecurity-crs) — OWASP Core Rule Set

**Hashing & Similarity**:
- [ssdeep-project/ssdeep](https://github.com/ssdeep-project/ssdeep) — CTPH fuzzy hashing
- [trendmicro/tlsh](https://github.com/trendmicro/tlsh) — Trend Micro Locality Sensitive Hash

## Tools

The `tools/` directory includes:

- **WAF Proxy** (`tools/waf_proxy/`) — Lightweight HTTP reverse proxy with built-in WAF rules (SQLi, XSS, traversal, webshell upload, command injection). Generates attack events in JSON Lines format for the threat profiling engine. Useful for testing and development.

```bash
python tools/waf_proxy/waf_proxy.py            # :8081 → :80
python tools/waf_proxy/waf_proxy.py 8081 8080  # custom ports
```

## Migration from Trident

Anteumbra is the successor to [Trident](https://github.com/SxyLao1/Trident) (v1.9.5). If you were using Trident:

```bash
# 1. Uninstall Trident
cd Trident
.\uninstall.bat      # Windows
# bash uninstall.sh  # Linux

# 2. Install Anteumbra
pip install anteumbra
anteumbra install /path/to/Anteumbra

# 3. Copy your config and data
cp /path/to/Trident/config.toml /path/to/Anteumbra/
cp -r /path/to/Trident/data/ /path/to/Anteumbra/
```

Your `config.toml` and `data/` directory are compatible.

## License

MIT License. Free for production, academic research, and personal use.

Third-party tools bundled in `tools/` retain their original licenses.

---

<div align="center">
  <sub>Anteumbra v1.0.20 — MIT License</sub>
</div>
