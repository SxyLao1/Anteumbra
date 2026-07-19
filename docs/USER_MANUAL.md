# Anteumbra User Manual v1.0.29

> **Lightweight Web Perimeter Threat Intelligence** — Passive Detection · Semi-Active Response · File-Level Forensics

[中文](USER_MANUAL_cn.md)

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

### Operating Boundary

Anteumbra is intended for a single host or a small web workload. It provides
filesystem integrity monitoring, WebShell detection, local triage/response,
and standard alert or SIEM output. It is not an inline WAF, EDR, SIEM,
central-management platform, or distributed HA service.

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
- **Included**: yara-python for compiled YARA detection
- **Optional**: ssdeep and py-tlsh for additional similarity engines

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

The base package includes compiled YARA rule validation and scanning. Install
`anteumbra[full]` only when the optional `ssdeep` and `py-tlsh` similarity
engines are required. `anteumbra[yara]` remains an empty compatibility alias.

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
  --name anteumbra \
  -p 127.0.0.1:18080:8080 \
  -v $(pwd)/anteumbra-data:/app/data \
  -v $(pwd)/anteumbra-logs:/app/logs \
  anteumbra
docker logs anteumbra
```

On first start, the container creates `.env`, uses `/app/sites/default` as the
default monitored directory, disables the demo MockWAF poller to avoid noisy
connection errors, adds the local Docker gateway to the admin IP allowlist, and
prints the initial admin password in `docker logs`. The admin UI is available at
`http://127.0.0.1:18080/admin`.

The Docker image installs `yara-python` and attempts to build optional fuzzy hash engines (`py-tlsh`, `ssdeep`). If an optional engine is incompatible with the current Python base image, Anteumbra logs the skip and continues with the available engines.

### 2.5 First Run

```bash
anteumbra run
```

Run this command from the instance directory created by `anteumbra install`.

Before startup, `anteumbra install` creates `config.toml`, `.env`, bundled rules, and a default monitored directory. It also prints the initial admin password; save it.

On startup, Anteumbra:
1. Loads `config.toml` and `.env` from the runtime instance directory
2. Verifies at least one enabled website path exists
3. Starts one file monitor and, when configured, one access-log monitor per enabled website
4. Reports `STARTED WITH WARNINGS` when optional capabilities are degraded instead of hiding the reason

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
id = "primary"             # Stable identity; do not change when renaming
name = "My Website"
path = "/var/www/html"     # Web root to monitor
port = 80
enabled = true
```

`website.id` is the persistent ownership key used by Registry, quarantine,
metrics, profiles, and audit operations. You may rename `website.name` at any
time while keeping the same ID. Changing the ID creates a separate site and
leaves historical records under the previous ID. `legacy` is reserved and
cannot be used. `anteumbra config validate` warns when an older config omits
the ID and derives it from the display name.

When placing the dashboard behind Nginx, Caddy, or another reverse proxy,
trust only that proxy peer. `trusted_proxy_ips` accepts IPs or CIDRs;
`session_cookie_secure = "auto"` enables secure cookies whenever a trusted
proxy is configured.

```toml
[web_admin]
trusted_proxy_ips = ["127.0.0.1"]
trusted_proxy_hops = 1
session_cookie_secure = "auto"
```

For multiple sites, replace the single `[website]` table with repeated
`[[website]]` tables. Every enabled entry must have a path-safe `name`, an
existing `path`, and a valid `port`; each site receives independent file and
access-log monitors.

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

For web access log analysis, use the preset command when possible. It enables
log analysis and writes the right path shape for the selected server:

```bash
# Nginx / Apache
anteumbra config access-log nginx
anteumbra config access-log apache

# Tomcat AccessLogValve date-rotated files; no wildcard typing required
anteumbra config access-log tomcat --base /opt/tomcat

# Custom file or wildcard
anteumbra config access-log custom --path /path/to/access.log
```

`config set` still works for low-level edits. If PowerShell expands a Tomcat
`localhost_access_log.*.txt` wildcard before Anteumbra receives it, the CLI
collapses the expanded files back to `localhost_access_log.*.txt`.

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

Fresh templates keep the top-level notifier and every outbound channel
disabled. A channel is usable only when both switches are enabled and all
required credentials are present; incomplete credentials do not trigger a
connection attempt. Restart after editing notification credentials.

### 3.6 Storage Backend

```toml
[storage]
backend = "both"            # "json" | "sqlite" | "both"
db_path = "data/anteumbra.db"
```

- `json` — JSON-only storage, simple and human-readable
- `sqlite` — Enables SQLite-backed repository consumers; core state still
  keeps JSON as its authoritative source
- `both` — Writes core state to JSON and a SQLite shadow. JSON remains
  authoritative; SQLite provides indexed inspection and recovery when JSON is
  unavailable (recommended)

Back up `data/` as a unit. Do not edit the SQLite database to repair a
Registry, quarantine, block-ledger, or threat-graph record while its JSON file
is healthy; the next authoritative JSON write can replace that shadow value.

### 3.7 IP Blocking

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

### 3.8 Full Configuration Reference

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

Background startup writes to `data/anteumbra.log` and waits up to 15 seconds
for both the PID file and two consecutive configured HTTP-listener checks. It
uses unbuffered output so startup progress and failures appear in that log
immediately. It exits non-zero and points to that log when the process exits
or never becomes ready.

### `anteumbra stop`
Stops the running process. On Windows it uses `taskkill /F`; on Linux it sends
`SIGTERM` and falls back to `SIGKILL`. The command verifies actual process exit
before deleting the PID file or reporting success. A termination failure returns
non-zero and preserves the PID for diagnosis or retry.

### `anteumbra config`
```
Options:
  -o, --output TEXT   Output path (default: ./config.toml)

Subcommands:
  init                  Create config.toml, .env, default site dir, rules
  wizard                Interactive setup for website path, admin port, logs, WAF
  access-log TYPE       Configure access-log analysis presets
  set KEY VALUE         Set a dotted config key, e.g. web_admin.port 8080
  env set KEY VALUE     Set one .env variable
  validate              Validate runnable paths and integration settings
  reload                Parse and validate the resolved deployment config
```

`anteumbra config reload` loads `.env`, resolves placeholders, parses every
site, and reports the enabled-site count. It does not reach into an already
running service. Use the Web System reload action or restart the service.

---

## 5. Web Dashboard

Access at `http://127.0.0.1:8080/admin`. The dashboard uses a dark terminal-style theme with HTMX-driven SPA navigation — no page reloads.

### 5.1 Dashboard (Home)

The main dashboard shows:
- **Active detections** count and recent findings
- **Threat profiles** with risk scores
- **System status** (monitor, WAL, registry health)
- **Detection and notification capability mode**, including degraded reasons
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
- **Restore** — Move file back to its original location (30-second guard suppresses duplicate scans, alerts, SIEM exports, and re-quarantine)
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
- **Reload** — Upload, edit, and delete operations reload rules immediately

The bundled set contains 27 `.yar` files. Anteumbra compiles each file in its
own namespace and skips only the invalid file if a custom rule has a compiler
or runtime failure; the last valid ruleset remains active on a failed reload.
For filesystem edits made outside the UI, use the YARA reload action or restart
the service. This avoids a background file watcher silently changing active
detection policy.

### 5.8 Manual Scanner

`/admin/scanner` — Active directory scanning.

- Select a target directory
- Limit the scan to comma-separated extensions; a leading dot is optional
- Real-time progress via SSE
- Explicit completed, stopped, and failed states with a reusable scan form
- Automatically refreshed scan history with results, duration, and findings count
- Printable reports

### 5.9 Live Log Stream

`/admin` → Log Stream panel — Real-time monitor log via SSE.

- Level filtering (configurable in `web_admin.sse_log_levels`)
- Auto-scroll with pause-on-hover
- Merged history from every enabled site's monitor log before live events
- Quiet reconnects and 15-second keepalive heartbeats

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

### 11.1 Production Runtime (Waitress)

```bash
anteumbra run --host 127.0.0.1 --port 8080
```

`anteumbra run` starts the complete runtime, including Waitress, file monitors,
baseline scanning, plugins, SIEM export, and background workers. Do not launch
only `create_app()` through a separate WSGI command; that omits the monitoring
and response subsystems.

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
    ports: ["127.0.0.1:18080:8080"]
    volumes:
      - ./anteumbra-data:/app/data
      - ./anteumbra-logs:/app/logs
      # Optional: mount an edited runtime config after first start.
      # - ./config.toml:/app/config.toml
      - ./rules:/app/rules
    environment:
      # Optional: set either ANTEUMBRA_ADMIN_PASSWORD or ANTEUMBRA_PASSWORD_HASH.
      - ANTEUMBRA_ADMIN_PASSWORD=${ANTEUMBRA_ADMIN_PASSWORD:-}
      - ANTEUMBRA_SECRET_KEY=${ANTEUMBRA_SECRET_KEY:-}
    restart: unless-stopped
```

### 11.4 Security Hardening

1. **Bind to localhost** unless behind a reverse proxy with auth
2. **Use strong passwords** (scrypt hash via werkzeug)
3. **IP whitelist** (`web_admin.allowed_ips`)
4. **CSRF protection** (enabled by default)
5. **HTTPS via reverse proxy** (Nginx/Caddy in front)
6. **Trust forwarded headers only from the proxy peer** (`trusted_proxy_ips`)
7. **Regular backups** of `data/` and `config.toml`

### 11.5 Reverse Proxy (Nginx)

```nginx
server {
    listen 443 ssl;
    server_name security.example.com;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_buffering off;  # Required for SSE log stream
    }
}
```

Pair this with `web_admin.trusted_proxy_ips = ["127.0.0.1"]` when Nginx is
local. Do not add broad networks unless every member is a controlled proxy;
untrusted forwarded headers must not influence client-IP authorization or HTTPS
cookie behavior.

---

## 12. Troubleshooting

### 12.1 Common Issues

**"No config.toml was found"**
→ Run `anteumbra config init`, or pass `--config` with the deployment path.

**"Port already in use"**
→ Another Anteumbra instance is running. Use `anteumbra stop` or change the port in `config.toml`.

**YARA rules not loading**
→ Check `rules/webshell/` exists and contains `.yar` files. Check `paths.yara_rules_path` in config.

**SSE log stream not working**
→ Check `web_admin.sse_log_levels` — DEBUG level is excluded by default. Ensure Nginx has `proxy_buffering off`.

**High memory usage**
→ Lower `scanner.event_queue_size` or `plugins.event_queue_size` only after
measuring backpressure. Check `web_admin.sse_max_total_clients` and avoid
unbounded log-client retention.

**Windows: file changes not detected**
→ Ensure `monitor.windows_verify_delay_ms` is at least 50ms. Check that `paths.monitor_extensions` includes your file types.

### 12.2 Log Files

| Log | Path | Content |
|-----|------|---------|
| Monitor | `logs/{site_id}/monitor.log` | File change events, scan results, alerts |
| Access | `logs/Anteumbra/access.log` | Flask HTTP access log |
| System | `logs/Anteumbra/system.log` | Startup, config reloads, errors |

Monitor log directories use immutable `website.id`, not the display name.
Anteumbra migrates legacy display-name logs when that site's monitor starts.
Aggregated history and new monitor lines include `[site=<id>]` attribution.

### 12.3 Health Check

```
GET /api/v1/health          # Public metrics + checks + capability modes
GET /admin/api/v1/health    # Minimal public load-balancer status
GET /admin/health           # Authenticated full diagnostics
```

Optional engine or notification degradation returns HTTP `200` with warning
details. Invalid configuration and critical Registry/WAL failures return HTTP
`503`. Use `/api/v1/health` when automation needs metrics/capabilities and the
minimal `/admin/api/v1/health` when only a status is required.

### 12.4 Getting Help

- **GitHub Issues**: https://github.com/SxyLao1/Anteumbra/issues
- **[README](../README.md)**: Project overview and quick start
- **[ARCHITECTURE.md](ARCHITECTURE.md)**: Technical deep-dive for developers
- **[ROADMAP.md](../ROADMAP.md)**: Current readiness and planned work
- **[RELEASE.md](RELEASE.md)**: Release, tag, and PyPI checklist

---

<div align="center">
  <sub>Anteumbra v1.0.29 — MIT License</sub>
</div>
