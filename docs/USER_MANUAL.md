# Anteumbra User Manual v1.0

> **Lightweight Web Perimeter Threat Intelligence** — Passive Detection · Semi-Active Response · File-Level Forensics

[中文](USER_MANUAL_zh.md)

---

## Table of Contents

1. [Overview](#1-overview)
2. [Installation](#2-installation)
3. [Configuration](#3-configuration)
4. [CLI Commands](#4-cli-commands)
5. [Web Dashboard](#5-web-dashboard)
6. [YARA Rules](#6-yara-rules)
7. [Threat Profiling](#7-threat-profiling)
8. [Quarantine & Block Ledger](#8-quarantine--block-ledger)
9. [SIEM Export](#9-siem-export)
10. [Plugin System](#10-plugin-system)
11. [Deployment](#11-deployment)
12. [Troubleshooting](#12-troubleshooting)

---

## 1. Overview

Anteumbra is a **passive Web perimeter security observatory**. It does not block traffic inline. Instead, it:

- **Monitors** your web root for file changes in real time
- **Scans** new/modified files with YARA rules to detect WebShells
- **Profiles** attackers by clustering IPs, User-Agents, and attack patterns
- **Quarantines** detected threats (manual or automatic)
- **Alerts** via email, WeChat, webhook, or syslog
- **Exports** detection data to SIEM systems

### Architecture at a Glance

```
Your Web Server (Nginx/Apache/IIS)
        │
        ├── File changes ──→ Anteumbra Monitor ──→ YARA Scan ──→ Registry
        ├── Access logs  ──→ Log Heuristics  ──→ Threat Graph
        └── WAF events   ──→ Plugin Adapters ──→ Attacker Profiles
                                        │
                                Web Dashboard (:8080)
```

### Key Concepts

| Term | Meaning |
|------|---------|
| **Registry** | Database of all detected suspicious files |
| **Quarantine** | Isolated copies of detected WebShells (safe storage) |
| **Threat Graph** | Attacker behavior profiles: IP pools, tool signatures, risk scores |
| **Block Ledger** | Audit trail of all IP block/unblock operations |
| **WAL** | Write-Ahead Log — ensures data durability during crashes |
| **SSE** | Server-Sent Events — real-time log streaming to the dashboard |

---

## 2. Installation

### 2.1 Requirements

- **Python** 3.10+
- **OS**: Windows 10+ or Linux (kernel 4.x+)
- **Optional**: ssdeep, py-tlsh, yara-python (for full hash engine support)

### 2.2 From PyPI

```bash
pip install anteumbra
anteumbra install ./anteumbra-instance
cd ./anteumbra-instance
anteumbra config wizard
anteumbra config validate
anteumbra run
```

PyPI install is the normal path for users and deployments. The `install` command creates the runtime instance, writes `config.toml` and `.env`, copies bundled YARA rules, and prints the initial admin password.

Install `anteumbra[yara]` to enable compiled YARA rule validation and scanning, or `anteumbra[full]` for YARA plus optional similarity hash engines.

### 2.3 From Source

```bash
git clone https://github.com/SxyLao1/Anteumbra.git
cd Anteumbra
pip install -e ".[dev]"
anteumbra install ./dev-instance --force
cd ./dev-instance
anteumbra config wizard
anteumbra run
```

Source install is for development and testing only. It uses the same runtime instance flow as PyPI installs.

### 2.4 Docker

```bash
docker build -t anteumbra .
docker run -d \
  -p 8080:8080 \
  -v $(pwd)/data:/app/data \
  -v $(pwd)/config.toml:/app/config.toml \
  anteumbra
```

The Docker image includes all three hash engines (ssdeep + py-tlsh + yara-python) pre-compiled for Linux.

### 2.5 First Run

```bash
anteumbra run
```

Run this command from the instance directory created by `anteumbra install`.

Before startup, `anteumbra install` creates `config.toml`, `.env`, bundled rules, and a default monitored directory. It also prints the initial admin password; save it.

On startup, Anteumbra:
1. Loads `config.toml` and `.env` from the runtime instance directory
2. Verifies at least one enabled website path exists
3. Starts the file monitor, background workers, and web dashboard

Open `http://127.0.0.1:8080/admin` and log in with username `admin`.

---

## 3. Configuration

All settings live in `config.toml` at the project root. Sensitive values use `${ENV_VAR:-default}` syntax resolved from environment variables or `.env`.

### 3.1 Essential Settings

```toml
[web_admin]
enabled = true
host = "127.0.0.1"         # Bind address — keep localhost for security
port = 8080                # Dashboard port
username = "admin"
password_hash = "${ANTEUMBRA_PASSWORD_HASH:-}"  # Generate with werkzeug
allowed_ips = ["127.0.0.1", "192.168.1.0/24"]   # IP whitelist

[website]
name = "My Website"
path = "/var/www/html"     # Web root to monitor
port = 80
enabled = true
```

### 3.2 Generate Password Hash

```bash
python -c "from werkzeug.security import generate_password_hash; print(generate_password_hash('your-password'))"
```

Paste the output into `config.toml` or set `ANTEUMBRA_PASSWORD_HASH` in your `.env` file.

### 3.3 CLI Configuration

Use `anteumbra config wizard` for first-run setup, or scripted subcommands for repeatable deployments:

```bash
anteumbra config init --output ./config.toml
anteumbra config wizard
anteumbra config set website.path /var/www/html
anteumbra config set web_admin.port 8080
anteumbra config env set ANTEUMBRA_WECHAT_API_KEY your-send-key
anteumbra config validate
```

`config set` rewrites `config.toml` using structured TOML output. Keep sensitive values in `.env` through `config env set`.

For web access log analysis, keep one product flow and only change the log path
for your web server:

```bash
# Nginx / Apache fixed file
anteumbra config set website.log_config.log_monitor_enabled true
anteumbra config set website.log_config.access_log_path /var/log/nginx/access.log

# Tomcat AccessLogValve date-rotated files
anteumbra config set website.log_config.access_log_path '/opt/tomcat/logs/localhost_access_log.*.txt'
```

On Windows, PowerShell may expand `*` before Anteumbra receives it. For Tomcat
wildcards, prefer `anteumbra config wizard` or the Web Settings page, or edit
`website.log_config.access_log_path` in `config.toml` directly.

### 3.4 File Monitoring

```toml
[website.scan_options]
exclude_dirs = ["cache", "logs", "temp", "uploads"]
exclude_files = ["*.log", "*.cache"]

[paths]
monitor_extensions = [".php", ".asp", ".aspx", ".jsp", ".jspx"]
```

### 3.5 Alerting

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

### 3.5 Storage Backend

```toml
[storage]
backend = "both"            # "json" | "sqlite" | "both"
db_path = "data/anteumbra.db"
```

- `json` — Simple, human-readable, no dependencies
- `sqlite` — High performance, WAL mode, FK constraints, 13 indexed columns
- `both` — Dual-write with SQLite-primary reads (recommended for production)

### 3.6 IP Blocking

```toml
[ip_blocker]
enabled = true
auto_block_enabled = false         # Enable only after testing
auto_block_min_score = 0.8

[[ip_blocker.devices]]
name = "Main Firewall"
type = "http"
url = "https://firewall.example.com/api/block"
api_key = "${ANTEUMBRA_WAF_API_KEY:-}"
```

### 3.7 Full Configuration Reference

See `config.toml` comments for all 130+ keys across 27 sections. Key sections:

| Section | Purpose |
|---------|---------|
| `[system]` | Project root, release date |
| `[website]` | Web server to monitor |
| `[web_admin]` | Dashboard settings, pagination, SSE limits |
| `[monitor]` | Windows/Linux file watcher tuning |
| `[registry]` | Async save, audit retention |
| `[quarantine]` | Auto-quarantine toggle |
| `[profiling]` | Attacker clustering time window |
| `[ip_blocker]` | Block devices and auto-block rules |
| `[notifier]` | Email, WeChat, webhook alerts |
| `[siem]` | CEF/JSON/Syslog export |
| `[plugins]` | Builtin plugins and WAF adapters |
| `[storage]` | JSON/SQLite backend selection |
| `[thresholds]` | Alert cooldown, circuit breaker |
| `[filesizes]` | WAL rotation, scan limits |
| `[paths]` | YARA rules, log directories |
| `[timeouts]` | HTTP, scan, config reload |
| `[logging]` | Log level, symbols, Flask access log |

---

## 4. CLI Commands

```bash
anteumbra --help          # Show all commands
anteumbra --version       # Show version

anteumbra run             # Start in foreground
anteumbra start           # Start as daemon (background)
anteumbra stop            # Stop running instance
anteumbra status          # Check if running
anteumbra config          # Generate config.toml template (compatibility alias)
anteumbra config wizard   # Interactive first-run setup
anteumbra config validate # Validate paths, ports, .env, enabled integrations
```

### `anteumbra run`
```
Options:
  --host TEXT      Bind address (default: config web_admin.host, fallback 127.0.0.1)
  --port INTEGER   Bind port (default: config web_admin.port, fallback 8080)
  --debug / --no-debug
```

### `anteumbra start`
```
Options:
  --host TEXT      Bind address (default: config web_admin.host)
  --port INTEGER   Bind port (default: config web_admin.port)
```

### `anteumbra stop`
Stops the running process. On Windows uses `taskkill /F`, on Linux sends `SIGTERM` then `SIGKILL`.

### `anteumbra config`
```
Options:
  -o, --output TEXT   Output path (default: ./config.toml)

Subcommands:
  init                  Create config.toml, .env, default site dir, rules
  wizard                Interactive setup for website path, admin port, logs, WAF
  set KEY VALUE         Set a dotted config key, e.g. web_admin.port 8080
  env set KEY VALUE     Set one .env variable
  validate              Validate runnable paths and integration settings
  reload                Reload config in the current CLI process
```

`anteumbra config reload` does not reach into an already running background
service. Use the web Settings/System reload action or restart the service for a
running instance.

---

## 5. Web Dashboard

Access at `http://127.0.0.1:8080/admin`. The dashboard uses a dark terminal-style theme with HTMX-driven SPA navigation — no page reloads.

### 5.1 Dashboard (Home)

The main dashboard shows:
- **Active detections** count and recent findings
- **Threat profiles** with risk scores
- **System status** (monitor, WAL, registry health)
- **Real-time log stream** via SSE

### 5.2 Records

`/admin/records` — All detected suspicious files.

**Operations:**
- **View detail** — Click any record for full metadata, linked profiles, quarantine info
- **Search** — Filter by filename or feature
- **Batch actions** — Select visible rows, carry the selection across pages, or use **All** for the current tab result set; then quarantine / mark false positive / delete
- **File viewer** — View file content with syntax highlighting (512KB max)
- **Quarantine** — One-click isolate a detected file
- **Mark False Positive** — Exclude legitimate files from future alerts

### 5.3 Quarantine

`/admin/quarantine` — Isolated WebShell copies.

**Operations:**
- **Restore** — Move file back to original location (+30s whitelist to prevent re-quarantine)
- **Delete** — Permanent removal
- **Batch** — Multi-select across pages, then restore/delete the selected quarantine records
- **Cross-link** — Navigate from quarantine record back to original detection

### 5.4 Threat Profiles

`/admin/profiles` — Attacker behavior profiles.

Each profile shows:
- **Risk Score** (0-100) — How dangerous this attacker is
- **IP Pool** — All IPs associated with this profile
- **Tool Signature** — Identified attack tool (sqlmap, Burp, custom)
- **Attack Chain** — Timeline of attack events
- **Target Files** — Which WebShells this attacker deployed
- **Status** — active / dormant (>1h) / expired (>24h)

Click a profile to see the full attack chain timeline, linked records, and file clusters.

### 5.5 File Clusters

`/admin/file-clusters` — Similarity-based file grouping.

Uses ssdeep/TLSH/SimHash to group files with ≥80% similarity. Helps identify:
- Polymorphic WebShell variants
- Same attacker deploying multiple backdoors
- Tool-generated payload patterns

### 5.6 Block Ledger

`/admin/block-list` — IP block/unblock audit trail.

**Features:**
- Full audit history of all block operations
- Inline note editing (add investigation notes)
- JSON/CSV export for compliance reporting
- Cross-links to threat profiles

### 5.7 YARA Rules

`/admin/yara/rules` — Rule management.

**Operations:**
- **List** — All `.yar` files with syntax validation status
- **Upload** — Add new rule files
- **Edit** — In-browser editor with live syntax validation
- **Delete** — Soft-delete to backup directory
- **Hot-reload** — Rules reload automatically on file change

### 5.8 Manual Scanner

`/admin/scanner` — Active directory scanning.

- Select a target directory
- Real-time progress via SSE
- Scan history with results, duration, findings count
- Printable reports

### 5.9 Live Log Stream

`/admin` → Log Stream panel — Real-time monitor log via SSE.

- Level filtering (configurable in `web_admin.sse_log_levels`)
- Auto-scroll with pause-on-hover
- Persisted buffer (last 100 lines survive page refresh)

### 5.10 Settings

`/admin/settings` — Configuration management.

- **Config Editor** — Edit `config.toml` in-browser with field descriptions
- **.env Editor** — Manage environment variables
- **Notification Toggles** — Enable/disable email, WeChat, webhook
- **SIEM Status** — Export statistics and format
- **Storage Status** — Database size, backend info
- **Plugin Status** — Loaded plugins and their states

Saving config or `.env` from the web Settings page triggers an in-process
config reload. Manual file edits should be followed by the System reload action
or a restart. Restart is still recommended for startup-lifecycle settings such
as web bind host/port, session backend, storage backend, plugin list, and
monitored website path.

### 5.11 System Management

`/admin/system` — Four-quadrant system view.

| Quadrant | Content |
|----------|---------|
| **Registry** | Record counts, async save queue, last save time, compaction |
| **WAL** | Current WAL size, archive list, manual replay |
| **Sessions** | Active session list, cleanup expired |
| **Config** | Hot-reload trigger, change history, YARA rule stats |

### 5.12 Monitor

`/admin/wal` — Dedicated WAL/Monitor views.

- WAL status, archive list, manual replay
- Registry compaction trigger
- Session cleanup
- Config reload history

---

## 6. YARA Rules

### 6.1 Rule Directory

Default: `rules/webshell/`. Contains 18+ rule files covering:
- PHP WebShells (China Chopper, antSword, etc.)
- ASP/ASPX WebShells
- JSP WebShells (Godzilla, Behinder)
- Generic WebShell patterns

### 6.2 Writing Custom Rules

```yara
rule My_Custom_WebShell {
    meta:
        description = "Detects my custom WebShell pattern"
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

### 6.3 Syntax Validation

Rules are validated on:
- Upload (rejected if invalid)
- Edit (live validation button)
- Startup (invalid rules are marked in the UI)

### 6.4 Hot Reload

YARA rules are monitored via file watcher. Changes take effect within 10 seconds (configurable via `timeouts.config_reload_delay`).

---

## 7. Threat Profiling

### 7.1 How Profiling Works

1. WAF events (or log heuristics) provide attack data: IP, User-Agent, URL, attack type
2. Profiles are clustered by **UA fingerprint** + **time window** (default 4h)
3. IPs using the same tool within the window are merged into one profile
4. Risk scores increase with repeated attacks and decay over time (half-life: 24h)

### 7.2 Profile States

| State | Condition | Meaning |
|-------|-----------|---------|
| `active` | Last seen < 1h ago | Currently attacking |
| `dormant` | Last seen 1-24h ago | Paused or sleeping |
| `expired` | Last seen > 24h ago | Likely gone |

### 7.3 Decay Engine

- **24h**: Risk score × 0.5
- **72h**: Profile marked dormant, score × 0.1
- **Management IPs** (configured in `[management].ips`): Not profiled, but still trigger alerts if they deploy WebShells

### 7.4 Management IPs

Configure IPs belonging to your security team:
```toml
[management]
ips = ["127.0.0.1", "::1", "10.0.0.5"]
```

These IPs' attacks won't pollute attacker profiles, but detection alerts still fire.

---

## 8. Quarantine & Block Ledger

### 8.1 Quarantine Flow

```
Detection → Mark in Registry → (Auto/Manual) Quarantine
                                    │
                          ┌─────────┴──────────┐
                          │  Copy to quarantine │
                          │  dir with random ID │
                          │  Update registry    │
                          │  Emit alert event   │
                          └────────────────────┘
```

Quarantined files are stored in `quarantine/` with random IDs — the original filename is never exposed.

### 8.2 Auto-Quarantine

```toml
[quarantine]
auto_quarantine_enabled = false   # Enable with caution
```

When enabled, detected WebShells are automatically quarantined. Disabled by default — we recommend manual review first.

### 8.3 Block Ledger

Every IP block/unblock operation is recorded:
- **Who** triggered the block (system/username)
- **Why** (reason, linked profile)
- **Where** (which devices received the block)
- **When** (timestamp)

Exportable as JSON or CSV for compliance audits.

---

## 9. SIEM Export

### 9.1 Configuration

```toml
[siem]
enabled = true
format = "json_lines"          # "json_lines" | "cef" | "syslog"
export_file = "data/siem/events.jsonl"
rotate_mb = 100
syslog_host = "192.168.1.100"  # for syslog format
syslog_port = 514
include_raw_sample = false     # Include first 256 bytes of file
```

### 9.2 Formats

| Format | Use Case |
|--------|----------|
| **JSON Lines** | Splunk, ELK, custom pipelines (recommended) |
| **CEF** | ArcSight, QRadar, HP Enterprise |
| **Syslog** | Traditional SIEM, rsyslog, syslog-ng |

### 9.3 Manual Export

From the Settings page: `/admin/settings` → "Export" button in SIEM panel.

---

## 10. Plugin System

### 10.1 Built-in Plugins

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

| Plugin | Function |
|--------|----------|
| `stdout_logger` | Prints all events to console (debug/development) |
| `quarantine_handler` | Performs quarantine + post-quarantine bookkeeping |
| `notifier_handler` | Sends alerts via email/WeChat/webhook |
| `threat_graph_handler` | Updates attacker profiles from detection events |

### 10.2 WAF Adapters

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

Available adapters: `modsecurity`, `cloudflare`, `aws_waf`, `syslog_waf`. All disabled by default.

### 10.3 Event Flow

```
Infrastructure modules (monitor, registry, block_ledger, etc.)
        │
        │  pm.emit("event_type", source, payload)
        ▼
PluginManager._event_queue (async Fire-and-Forget)
        │
        ▼
PluginManager.dispatch()
        │  Per-handler daemon thread with 30s timeout
        ▼
Plugin.on_event(event) → Optional[List[DomainEvent]]
```

---

## 11. Deployment

### 11.1 Production with Gunicorn

```bash
pip install gunicorn
gunicorn -w 4 -b 127.0.0.1:8080 "anteumbra.interfaces.web.factory:create_app()"
```

### 11.2 systemd Service

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

### 11.4 Security Hardening

1. **Bind to localhost** unless behind a reverse proxy with auth
2. **Use strong passwords** (scrypt hash via werkzeug)
3. **IP whitelist** (`web_admin.allowed_ips`)
4. **CSRF protection** (enabled by default)
5. **HTTPS via reverse proxy** (Nginx/Caddy in front)
6. **Regular backups** of `data/` and `config.toml`

### 11.5 Reverse Proxy (Nginx)

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
        proxy_buffering off;  # Required for SSE log stream
    }
}
```

---

## 12. Troubleshooting

### 12.1 Common Issues

**"ConfigRegistry not initialized"**
→ Ensure `config.toml` exists. Run `anteumbra config` to generate a template.

**"Port already in use"**
→ Another Anteumbra instance is running. Use `anteumbra stop` or change the port in `config.toml`.

**YARA rules not loading**
→ Check `rules/webshell/` exists and contains `.yar` files. Check `paths.yara_rules_path` in config.

**SSE log stream not working**
→ Check `web_admin.sse_log_levels` — DEBUG level is excluded by default. Ensure Nginx has `proxy_buffering off`.

**High memory usage**
→ Lower `monitor.dir_cache_size` and `filesizes.wal_cleanup_count`. Check `web_admin.sse_max_total_clients`.

**Windows: file changes not detected**
→ Ensure `monitor.windows_verify_delay_ms` is at least 50ms. Check that `paths.monitor_extensions` includes your file types.

### 12.2 Log Files

| Log | Path | Content |
|-----|------|---------|
| Monitor | `logs/{site}/monitor.log` | File change events, scan results, alerts |
| Access | `logs/Anteumbra/access.log` | Flask HTTP access log |
| System | `logs/Anteumbra/system.log` | Startup, config reloads, errors |

### 12.3 Health Check

```
GET /api/v1/health          # Public health (no auth)
GET /admin/health            # Authenticated health with diagnostics
```

### 12.4 Getting Help

- **GitHub Issues**: https://github.com/SxyLao1/Anteumbra/issues
- **README**: Project overview and architecture
- **ARCHITECTURE.md**: Technical deep-dive for developers
- **ANTEUMBRA_USAGE_GUIDE.md**: Internal development guide

---

<div align="center">
  <sub>Anteumbra v1.0.22 — MIT License</sub>
</div>
