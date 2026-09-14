# Anteumbra User Manual v1.0.38

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
13. [MCP Server & Agent Skill](#13-mcp-server--agent-skill)

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

Treat package code and runtime data as separate locations:

- `python -m pip install anteumbra` installs code into the active Python environment.
- `anteumbra install INSTANCE_DIR` creates the one default mutable runtime at a chosen path.
- The runtime owns `config.toml`, `.env`, `data/`, `logs/`, `rules/`, and quarantine state.

Install into the Python environment you already manage. Anteumbra does not
create a virtual environment or modify the user or system `PATH`. When the
Python Scripts directory is not already discoverable, the module form avoids
any `PATH` change. A Windows example is:

```powershell
py -3.12 -m pip install --upgrade anteumbra
py -3.12 -m anteumbra install "$HOME\Anteumbra"
py -3.12 -m anteumbra --home "$HOME\Anteumbra" config wizard
py -3.12 -m anteumbra --home "$HOME\Anteumbra" start
```

`INSTANCE_DIR` may be absolute or relative and defaults to the current
directory. `--home INSTANCE_DIR` lets `run/start/stop/status/config` address a
specific runtime from any working directory. After registering a default
instance, entering that directory or omitting `--home` also works.

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

`anteumbra install --force` only permits replacing the default-instance
registration or using a non-empty target; it does not replace an existing
`config.toml` or `.env`. An intentional reset requires the explicit
`anteumbra config init --force` command.
The install summary displays the configured administrator username. It reports
an existing password only as unchanged because `.env` stores a one-way hash;
use `anteumbra config wizard` to set a new password when it is unknown.

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
anteumbra config          # Show config subcommand help; never write files
anteumbra config init     # Explicitly create config, env, rules, default site
anteumbra config wizard   # Interactive first-run setup
anteumbra config validate # Validate paths, ports, .env, enabled integrations
anteumbra mcp             # Serve Anteumbra to a local AI agent (MCP)
anteumbra mcp serve       # stdio MCP server; read-only unless --allow-write
anteumbra mcp tools       # List the tools a client would see for this instance
anteumbra skill export    # Copy the bundled agent skill out of the package
```

### Global Options
```
  --home DIRECTORY   Select a runtime instance explicitly
  -h, --help         Show help
  --version          Show version
```

For example: `anteumbra --home E:\Software\Anteumbra config validate`.
Global options must appear before the subcommand.

### `anteumbra install [INSTANCE_DIR]`
Creates a runtime instance; it does not install the Python package. The path
is explicit and defaults to the current directory. `--force` allows replacing
the default registration or using a non-empty target while preserving config
and secrets.

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
for both the process identity file and two consecutive health checks. The
identity records the PID, a platform-stable process start token, and runtime
root so a reused PID cannot claim the instance. Legacy integer PID files remain
readable. Startup uses unbuffered output so progress and failures appear in the
log immediately, and exits non-zero when the process exits or never becomes
ready.

### `anteumbra stop`
Stops the running process. On Windows it uses `taskkill /F`; on Linux it sends
`SIGTERM` and falls back to `SIGKILL`. The command verifies actual process exit
before deleting the PID file or reporting success. A termination failure returns
non-zero and preserves the PID for diagnosis or retry.

If `status` reports `UNKNOWN`, ownership could not be verified. `start` and
`stop` then fail closed and preserve `data/anteumbra.pid`; retry with permission
to inspect the process. Remove that file manually only after independently
confirming that no Anteumbra process is running.

### `anteumbra config`
```
Subcommands:
  init [-o PATH]         Create config.toml, .env, default site dir, rules
  wizard                Interactive setup for website path, admin port, logs, WAF
  access-log TYPE       Configure access-log analysis presets
  set KEY VALUE         Set a dotted config key, e.g. web_admin.port 8080
  env set KEY VALUE     Set one .env variable
  validate              Validate runnable paths and integration settings
  reload                Parse and validate the resolved deployment config
```

Bare `anteumbra config` only prints this help. `config init` confirms before
replacing existing files; `config init --force` replaces config and secrets
without prompting and is intended only for an explicit reset.

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
    "threat_graph_handler",
    "siem_handler",
    "memory_shell_probe"
]
```

| Plugin | Function |
|--------|----------|
| `stdout_logger` | Prints all events to console (debug/development) |
| `quarantine_handler` | Performs quarantine + post-quarantine bookkeeping |
| `notifier_handler` | Sends alerts via email/WeChat/webhook |
| `threat_graph_handler` | Updates attacker profiles from detection events |
| `siem_handler` | Exports events in a SIEM-consumable form |
| `memory_shell_probe` | Detects webshells that exist only in memory, with no file on disk (see 10.4) |

### 10.2 WAF Adapters

WAF adapters are **event-source plugins**: they pull or receive events from an external
WAF and hand them to Anteumbra. Enabling one takes **two switches** — list it in
`builtin` *and* set `enabled = true` in its own section:

```toml
[plugins]
builtin = [
    "waf_adapters.modsecurity",   # note the module-style plugin name
]

[plugins.modsecurity]
enabled = true
audit_log_path = "data/modsec_audit.log"
poll_interval = 5
min_score = 5.0

[plugins.cloudflare]
enabled = false
zone_id = "${CLOUDFLARE_ZONE_ID:-}"
api_token = "${CLOUDFLARE_API_TOKEN:-}"
poll_interval = 60
```

| Plugin name | Adapter | Purpose |
|-------------|---------|---------|
| `waf_adapters.modsecurity` | `ModSecurityAdapter` | Polls ModSecurity v2/v3 JSON audit logs |
| `waf_adapters.cloudflare` | `CloudflareAdapter` | Polls the Cloudflare firewall events API |
| `waf_adapters.aws_waf` | `AWSWAFAdapter` | Polls AWS WAF; degrades to inactive without `boto3` |
| `waf_adapters.syslog_waf` | `SyslogWAFReceiver` | Listens on syslog for WAF events |

Behaviour:

- A source plugin is started (`start()`) at registration and stopped (`stop()`) on
  unload; a failing adapter degrades to "loaded but inert" instead of affecting other
  plugins or the runtime.
- Adapter events are published as `waf.event` **and** appended to
  `data/waf_events.jsonl`, the same file the runtime's own WAF poller writes and the
  threat graph's `JsonlEventTailer` reads, so collected events reach profiles and SIEM
  exports.
- Every adapter ships with `enabled = false` and none is in the default `builtin` list,
  so an unconfigured install makes no network calls and opens no ports.
- The settings-page plugin panel distinguishes "loaded", "installed but disabled in
  config" and "not listed in `builtin`", with a copy-ready config snippet for each.

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

### 10.4 Memory-Shell Probe (`memory_shell_probe`)

A file-based webshell disappears when the file is deleted; a memory shell does not,
because it never existed as a file and the file monitor cannot see it. This plugin
asks the servlet container itself what is registered in memory:

```
random directory + random file name: the probe JSP lands in the site root
        │  (the probe file and its URL are registered as internal artifacts first)
        ├─ HTTP GET http://<site>:<port>/<random path>/<random name>.jsp?t=<run token>
        │     the probe enumerates the StandardContext: Filter / Servlet / Listener,
        │     and any Class parked in an HttpSession
        ▼
parse JSON → suspicious components become probe findings and alerts
        │
        └─ finally: delete the probe file and its random directory (only that one)
```

Enable it with:

```toml
[plugins]
enabled = true
builtin = ["memory_shell_probe"]

[plugins.memory_shell_probe]
enabled = true
auto_probe_on_detection = true
trigger_extensions = [".jsp", ".jspx", ".jspf", ".jsw", ".jsv"]
site_ids = []
probe_base_dirs = {}
url_prefixes = {}
cooldown_seconds = 300
http_timeout_seconds = 8
artifact_ttl_seconds = 120
directory_prefix = "mb-"
history_size = 50
alert_on_suspects = true
host = "127.0.0.1"
scheme = "http"
forensics_enabled = true
heap_dump_enabled = true
forensics_history = 200
forensics_max_dump_mb = 2048
```

| Option | Meaning |
|--------|---------|
| `enabled` | Master switch; when off, neither automatic nor manual probing runs |
| `auto_probe_on_detection` | Probe the site automatically after a webshell alert |
| `trigger_extensions` | File suffixes that trigger an automatic probe; JSP family by default |
| `site_ids` | Restrict probing to these sites; empty means every enabled site with an existing path |
| `probe_base_dirs` | `{ site id = "subdir" }`: which deployed context the probe is written into (required for a Tomcat `webapps` root) |
| `url_prefixes` | `{ site id = "/prefix" }`: URL prefix when the site path is a subdirectory of the document root |
| `cooldown_seconds` | Minimum interval between two automatic probes of the same site |
| `http_timeout_seconds` | Timeout for reading the probe |
| `artifact_ttl_seconds` | Lifetime of the internal-artifact registration (released as soon as the probe is deleted) |
| `directory_prefix` | Prefix of the random directory, for humans looking at the filesystem |
| `history_size` | How many recent probe runs the admin page keeps |
| `alert_on_suspects` | Raise an alert as soon as a suspicious component is found |
| `host` / `scheme` | Address and protocol used to reach the probe |
| `forensics_enabled` | Allow forensics (取证) runs; when off, the tab says so and refuses to dump |
| `heap_dump_enabled` | Ask for a heap dump during a forensics run (the manifest is stored either way) |
| `forensics_history` | How many forensics runs the on-disk index keeps (1-10000, default 200) |
| `forensics_max_dump_mb` | Free-space pre-check for a heap dump (0 disables the pre-check) |

A component is marked suspicious when any of these hold:

- the class has no file on disk (defined at runtime with `defineClass`, the hallmark of a memory shell);
- the class or registration name carries tool signatures (`behinder`, `godzilla`, `memshell`, `shell`, `inject`, `payload`, ...);
- the class name is a short random string (tools randomise it per deployment);
- the class loader is anonymous or JSP-generated (names like `..._jsp$U`);
- the class has no `CodeSource`;
- method/field fingerprints: `getMagic`, `fillContext`, `getBasicsInfo`, `equals(Object)` returning `boolean`, or `whatever`/`shellCode`/`classBody` fields;
- an HttpSession holds a non-JDK class that has no file on disk (Godzilla-style clients cache their payload class in the session).
  JDK classes (for example `String.class` stored in a session) are skipped, so ordinary session state stays quiet.

Self-noise handling: the probe file and its URL are registered as *internal artifacts*,
and the file monitor, the baseline sweep, manual scans and the access-log monitor all
skip them, so Anteumbra never alerts on its own probe. Registration matches the exact
path and URL of the current run, with a time limit, and never uses a name wildcard such
as `probe-*` — otherwise naming a backdoor `probe-x.jsp` would earn it an exemption.

Limits and boundaries:

- Only applicable to Java containers that serve a watched filesystem path directly
  (Tomcat / Jetty / Resin). The probe is a JSP; PHP and IIS sites are never triggered.
- The probe must land inside a **deployed context**; a JSP that belongs to no context
  answers 404. Three cases: (1) the site `path` is itself a document root (contains
  `WEB-INF/web.xml`) — the probe goes there with an empty URL prefix; (2) exactly one
  context exists below the site root — it is selected automatically and its name becomes
  the URL prefix; (3) several contexts exist (Tomcat's `webapps`) — set
  `probe_base_dirs = { tomcat = "dshlab" }` explicitly, otherwise the run fails with an
  honest "probe HTTP 404" and the reason is written to the log and the page rather than
  being retried silently. When the site `path` is a subdirectory of the document root,
  add `url_prefixes = { tomcat = "/blog" }`.
- The probe only sees what the container **registered**. Bytecode-enhancement memory
  shells (`retransform` / `instrument`) register no Filter or Servlet and are invisible
  to it: Behinder 4.1's native memory shell, for example, uses javassist to insert code
  before `org.apache.catalina.core.ApplicationFilterChain.internalDoFilter`, adds no
  FilterDef/FilterMap and does not change `web.xml`, so `findFilterDefs()`,
  `findFilterMaps()` and `filterConfigs` all miss it (verified in the lab against the
  real tool). Finding those requires diffing the bytecode of `catalina.jar` or watching
  for agent attachment (`-javaagent`, `jdk.attach.allowAttachSelf`, a
  `ClassFileTransformer` appearing); the probe reports `javaagent`, `attach_self` and the
  JVM input arguments as manual-judgement hints.
- A probe result is a point-in-time snapshot kept in memory (the last `history_size`
  runs) and is cleared on restart; findings still go through the normal alert channels.
- Every failure mode (container down, site unreachable, probe replaced, cleanup failed)
  is surfaced on the page and in the log. **A failed cleanup is shown in red**, because it
  means a file that should not exist was left behind in the site.

#### Forensics (取证) - what a memory shell actually was

Detection answers "is something registered in memory that should not be". Forensics answers
"what exactly is it", *before* anyone removes it. The same probe file answers an
`action=dump` request for one component (`kind` = `filter` | `servlet` | `listener`, plus the
registered `name`), and Anteumbra stores the result as an artifact.

What is dumped:

- the **manifest**: kind, name, url patterns, class name, class-loader identity, code
  source, an `on_disk` flag, the declared methods and fields (names and signatures, bounded
  to 200 each), the protection domain, the container/server info, the site and context path,
  the probe URL (without the per-run token), the JVM input arguments and
  `jdk.attach.allowAttachSelf`;
- the **class bytes**, base64-encoded, **only when the class really resolves to a
  classloader resource** (a deployed class, a JSP class, anything loaded from a jar or a
  directory);
- an optional **heap dump**, written by the target JVM itself through
  `com.sun.management:type=HotSpotDiagnostic` `dumpHeap(<absolute path>, <live>)`.

What cannot be dumped, and why it says so instead of guessing:

- a class defined at runtime with `defineClass` (the hallmark of a memory shell, and what
  Behinder/Godzilla payloads use) **has no bytecode resource**. A JSP cannot recover the
  bytes of a loaded `Class` from a running JVM: there is no supported API for it. The dump
  then returns `class_bytes_unavailable_reason`
  (`class_defined_at_runtime_without_bytecode_resource`) instead of empty bytes, and no
  `class-<name>.class` file is written. That absence is itself evidence: a filter whose class
  exists nowhere on disk is exactly what you are looking for.
- a heap dump can fail - no HotSpot diagnostic MXBean (a non-HotSpot JVM), a permission or
  attach restriction, no free disk space, or an unsupported `live` mode. The response then
  carries `heap_error` with the real cause, **and the manifest is still returned and still
  stored**. A failed dump is never allowed to cost you the forensics you already have. The
  probe refuses a dump up front when the free space is clearly below what this JVM could
  need, and never runs one without an absolute target path.
- the manifest records the bytes the *classloader* serves, which is what was compiled, not
  what a `retransform`-based agent may have rewritten in memory. The manifest names its
  source (`class_bytes_source`) so the distinction is visible.

Where the artifacts live:

```
<data_dir>/forensics/<site_id>/<UTC timestamp>-<kind>-<slug>/
    manifest.json          what the probe reported about the component
    class-<name>.class     the class bytes, when they could be resolved
    heap.hprof             the heap dump, when one was produced
<data_dir>/forensics/index.json
    every run, newest first, bounded to forensics_history entries:
    artifact id, site, time, trigger, component, class, files (size + sha256),
    heap state, and the remediation history of that component
```

The index is written atomically (a temporary file plus `os.replace`) and keeps the last
`forensics_history` runs; sizes and hashes are computed from the files that are actually on
disk. An index that cannot be read is reported on the page rather than silently reset, so
"no evidence" is never confused with "the evidence was lost". There is deliberately no
database table: artifacts are files plus one index.

The heap dump appears under three different shapes, because three layers describe it: the
probe's own `action=dump` response reports `heap_path` / `heap_bytes` / `heap_sha256` /
`heap_live` (plus `heap_error`), the stored `manifest.json` and the index entry carry a `heap`
object with `path` / `bytes` / `sha256` / `live`, and the indexed file list always contains a
final entry named `heap.hprof` with the size and hash the store computed itself
(`sha256_source` is `computed`, or `probe` for a dump large enough that re-hashing it would
cost more than it is worth). So inside `<data_dir>/forensics/index.json` the byte count of a
heap dump is `runs[i].heap.bytes` — **not** `heap_bytes`, which only exists in the raw probe
response.

The 取证 tab (`/admin/memory-shell/forensics`) lists the artifacts per site with their size,
files, class-bytes/heap state and remediation result, opens the stored manifest, downloads
any indexed file, and starts a dump for the component you arrived with. Starting from a
finding on the 检测 tab pre-fills that component. Use "Dump live objects only" when the heap
is large: it is a smaller file, but it pauses the JVM longer.

#### Remediation (处置) - removing the component from memory

处置 unregisters exactly one component from the running container. It is the only action in
Anteumbra that changes a protected system, so it is built around the three questions that
decide whether it is *the same thing* Anteumbra saw:

1. **Is there forensics for this component?** Without an artifact, the request is refused
   unless it acknowledges that explicitly (`acknowledge_no_forensics=1`). The UI asks before
   it posts: with an artifact you get a plain confirmation; without one you get
   `没有对应的取证文件。确认要在不取证的情况下处置内存马吗？` and three buttons - 立即处置
   (posts `acknowledge_no_forensics=1`), 前往取证 (the forensics tab for that component) and
   取消.
2. **Is it still the same class?** The request must carry the class name Anteumbra recorded
   for that component, and the probe compares it with the class the container reports *inside
   the JVM* immediately before removing anything. A mismatch is a refusal
   (`class_name_mismatch`), because something changed under us and the decision no longer
   describes reality. Without a recorded class name, nothing is removed at all
   (`no_recorded_class`).
3. **Is it a real file on disk?** A component whose class resolves to a jar or a directory is
   a legitimately deployed component, not a memory shell. It is refused (`class_on_disk`)
   unless `force=1` is passed explicitly.

On success it removes the component in full, and it verifies that before claiming anything:

- **Filter**: every `FilterMap` of that name first (the filter stops being applied on the very
  next request), then the `FilterDef` through `removeFilterDef(FilterDef)`, then the
  `ApplicationFilterConfig`, which is removed from `StandardContext`'s private `filterConfigs`
  map explicitly and released. That third step is not optional: Tomcat's `removeFilterDef()`
  only drops the entry from `filterDefs` and leaves `filterConfigs` untouched (verified against
  Tomcat 7.0.108 and 9.0.96 bytecode; the reference scanner in
  `tools/memory-shell/java/tomcat-memshell-scanner.jsp` documents the same leftover as a known,
  unfixed problem). Without it the shell stops answering but stays registered forever, and every
  later probe keeps reporting it. If the name is somehow still registered afterwards, the probe
  calls `filterStop()` + `filterStart()` so the container rebuilds its filter state from the
  definitions that are left, and checks once more.
- **Servlet**: `removeServletMapping(String)` for every pattern, then `removeChild(Container)`.
- **Listener**: the instance is removed from wherever that container keeps application event
  listeners - a `List` on Tomcat 8/9, an `Object[]` on Tomcat 6/7, both behind
  `getApplicationEventListeners()` / `setApplicationEventListeners()`.

Success is reported only when a fresh enumeration no longer finds the component. A removal that
cannot be verified is reported as `removed=false` with a concrete reason
(`filter_configs_unavailable`, `filter_still_registered_after_cleanup`,
`servlet_still_registered_after_cleanup`, `listener_still_registered_after_cleanup`,
`remove_filter_map_failed: ...`), so a half-finished removal is never mistaken for a finished
one; the response always carries the post-action component list so the caller can check. It
never deletes a file, never edits `web.xml`, and never touches anything outside the identified
component.

Because `filterStop()` / `filterStart()` re-create the other filters too (it is the container's
own reload path), that repair is attempted only when the name survived the explicit cleanup -
that is, only when the alternative would be leaving a memory shell in place.

**Removing an in-memory component is irreversible for that component.** There is no undo and
no copy: the class, its registrations and anything it held are gone. That is why the
forensics step exists and why the confirmation is explicit - taking the dump first is the
only way to keep something to analyse afterwards. The heap dump is not a copy of the
component either; it is a snapshot of the JVM that may contain it.

Every attempt - removed, refused or failed - publishes a `memory_shell_remediated` event with
the before/after component state and writes one WARNING line to the log, and a successful
removal is recorded in that artifact's remediation history (`remediated_at`, result,
operator). The detection alert path is unchanged.

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

## 13. MCP Server & Agent Skill

Anteumbra ships a **Model Context Protocol (MCP) server** and an **agent skill**.
It does **not** embed an AI agent. The agent is yours: point your own local agent
(Claude Desktop, Cursor, VS Code, or any other MCP client) at this server, and it
can discover web services on the machine, decide with you what to monitor,
configure it, validate, restart, verify that detection really works, and report
back. Every write goes through the same code path the CLI uses.

### 13.1 Install the optional extra

The official `mcp` Python SDK is an optional dependency, so a base install
carries no agent-protocol code. Install it only where you run the server:

```bash
pip install "anteumbra[mcp]"
```

Without it, `anteumbra mcp serve` fails with a single actionable line on stderr
and exit code 1 - never an `ImportError` traceback:

```
Error: The MCP server needs the optional "mcp" Python SDK. Install it with:
pip install "anteumbra[mcp]" - then run "anteumbra mcp serve" again.
```

`anteumbra mcp tools`, `anteumbra skill export` and every other command keep
working on a base install; the server imports the SDK lazily.

### 13.2 Serve one instance over stdio

```bash
anteumbra --home /opt/anteumbra mcp tools                  # what a client would see
anteumbra --home /opt/anteumbra mcp serve                  # read-only
anteumbra --home /opt/anteumbra mcp serve --allow-write    # adds the write tools
```

The transport is **stdio**: the client starts this process and speaks the
protocol on its stdin/stdout. `--home` selects the runtime instance exactly like
it does for `status` or `config`, and it must appear before `mcp`.

### 13.3 Register the server in your client

```json
{
  "mcpServers": {
    "anteumbra": {
      "command": "anteumbra",
      "args": ["--home", "/opt/anteumbra", "mcp", "serve", "--allow-write"]
    }
  }
}
```

On Windows use a Windows path (`"E:\\Software\\Anteumbra"`); the client may need
the full path to `anteumbra.exe` when it is not on `PATH`. Omit `--allow-write`
for a read-only agent.

### 13.4 What the agent can do

Read-only, always available:

| Tool | Returns |
|------|---------|
| `get_status` | Running state, version, admin URL, uptime, health endpoint, monitored sites |
| `list_sites` | Per site: stable id, name, path, port, enabled, reachable, whether it serves JSP |
| `get_config` | Effective configuration with every credential redacted |
| `validate_config` | Exactly what `anteumbra config validate` prints, plus structured errors and warnings |
| `list_detections` | Registry rows, newest first, filtered by site and status |
| `list_quarantine` | Quarantine rows (metadata only, never file contents) |
| `list_sites_summary` | Per-site detection and quarantine counts for a report |
| `list_listening_ports` | Local TCP listeners with the owning process |
| `discover_web_services` | Listeners that look like web services, with the document root when the OS states it |

Write-gated - these do **not exist** in the tool list unless the server was
started with `--allow-write`:

| Tool | Effect |
|------|--------|
| `add_site` / `update_site` / `disable_site` | Add, change or stop monitoring a site in `config.toml` |
| `set_config_value` | Set one dotted key, identical to `anteumbra config set` |
| `set_env_value` | Write one secret to `.env` (never `config.toml`); needs a restart |
| `run_memory_shell_probe` | Run Anteumbra's own JSP probe - offered only while the instance is stopped |

Every mutating call revalidates the configuration and returns the validation
result, so a change that breaks the config tells the agent immediately.

### 13.5 Safety defaults

* **Read-only by default.** Without `--allow-write`, mutating tools are absent
  from the tool list rather than present and failing.
* **Secrets stay out of responses.** `get_config` replaces any credential-shaped
  value with `***REDACTED***`, and every tool response is swept for the values
  stored in the instance `.env`, so a resolved `${VAR}` placeholder or a
  credential inside a URL cannot leak either. `set_env_value` never echoes the
  value it wrote.
* **Discovery is bounded and local.** It reads the operating system's connection
  table and the owning process; it does not walk the filesystem, sweep ports, or
  contact anything. HTTP probing of candidates is off unless the agent asks for
  it, because those requests would appear in the access log Anteumbra watches.
* **Nothing about the machine is guessed.** A document root that cannot be
  derived is returned as `null` with the reason.
* **Process lifecycle is not exposed.** Start, stop and restart stay in the CLI,
  where a human or the agent runs them deliberately.

### 13.6 The agent skill

The operator manual for an AI lives inside the package and is exported on
demand:

```bash
anteumbra skill export ~/.agents/skills     # writes ~/.agents/skills/anteumbra/SKILL.md
anteumbra skill export ./skills --flat      # writes ./skills/SKILL.md
anteumbra skill show                        # print it without copying
```

Most agents discover skills as `<skills-root>/<name>/SKILL.md`, so the default
layout creates the `anteumbra` directory for you. Use `--force` to replace an
existing copy.

The skill tells the agent which tool to call at each step, what to ask you for
and why (admin password, notification channel, SMTP settings and the mail
provider's **authorization code** - not the account password, WeChat/WeCom send
key or webhook, optional WAF token, whether to enable auto-quarantine and IP
blocking), which safety rules are non-negotiable, and the verification checklist
it must complete before reporting success.

---

<div align="center">
  <sub>Anteumbra v1.0.38 — MIT License</sub>
</div>
