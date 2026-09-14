---
name: anteumbra
description: Operate a local Anteumbra web-perimeter security instance through its MCP server - find web services on this machine, decide what to monitor, configure and validate sites, start or restart the service, verify that detection actually works, and report back to the user. Use when the user asks to set up, configure, verify, or troubleshoot Anteumbra, or asks which web shells were detected on this host.
---

# Anteumbra operator skill

Anteumbra is a passive web-perimeter observatory: it watches the file systems of
your web roots, scans changed files with YARA, profiles attackers from access
logs and WAF events, quarantines what it finds, and alerts you. It never sits in
front of traffic, so it cannot break a request path.

You are the agent. Anteumbra ships no AI of its own: this skill plus the MCP
tools *are* the product surface. Everything below is a concrete instruction -
exact tool names, exact commands. Follow it in order.

---

## 1. Connect to the server

### 1.1 One-time install

```bash
pip install anteumbra                 # the platform
pip install "anteumbra[mcp]"          # the MCP server extra (optional dependency)
anteumbra install /opt/anteumbra      # create the runtime instance (user does this)
```

`anteumbra install` creates `config.toml`, `.env` with a generated admin
password, `rules/`, `data/` and `logs/`. It can prompt; if you are not allowed
to answer prompts, ask the user to run it.

Verify the surface without any client:

```bash
anteumbra --home /opt/anteumbra mcp tools
```

### 1.2 Register the server in the agent client

The transport is stdio: the client starts the process. Add this to the client's
MCP configuration (Claude Desktop `claude_desktop_config.json`, Cursor, VS Code,
or any other MCP client - the shape is the same everywhere):

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

On Windows, `--home` takes a Windows path (`"E:\\Software\\Anteumbra"`) and the
command may need the full path to `anteumbra.exe` if it is not on `PATH`.
Without `--allow-write`, omit the last argument.

### 1.3 Read-only and write mode

* **Read-only (default)**: nine tools that only read. No mutating tool exists in
  the tool list - not hidden, not failing: absent.
* **`--allow-write`**: adds `add_site`, `update_site`, `disable_site`,
  `set_config_value`, `set_env_value`, and - only when the instance is stopped -
  `run_memory_shell_probe`.

Ask for write mode only when the user has asked you to change the
configuration, and ask for confirmation before each mutating call.

Every mutating tool revalidates the configuration and returns the validation
result, so a call that breaks the config tells you immediately.

---

## 2. The flow

### Step 1 - Look before you touch anything

Call `get_status`.

* `config_exists: false` → the instance is not created yet. Stop and ask the
  user to run `anteumbra install <DIR>`, then start a server with that `--home`.
* `runtime.running` → whether Anteumbra itself is up.
* `admin_url`, `version`, `data_dir`, `log_dir` → useless now, needed in your
  final report.
* `monitored_sites.site_ids` → what is already watched. Do not remove any of it.

Then call `list_sites` (with `probe_ports: false` first, it is faster) to see
the configured sites.

### Step 2 - Discover what is on this machine

Call `discover_web_services` with `probe_http: false`.

Result: one entry per listening port that looks like a web service, with
`port`, `process_name`, `pid`, `confidence`, and `document_root` when the
operating system tells us (Tomcat via `-Dcatalina.base`, otherwise the process
working directory that contains `webapps`/`www`/`htdocs`/`public`).

* `document_root: null` means it could not be determined - the
  `document_root_note` says why. Ask the user instead of guessing.
* Use `list_listening_ports` when you need the complete listener list.
* Do **not** set `probe_http: true` unless the user agrees: every probe is a
  request that the site's own access log records, and Anteumbra may be watching
  that log.

### Step 3 - Decide what to monitor, with the user

Present the candidates as a short list and ask which ones to watch: name, path,
port. For each one you need the **web root** (the directory the web server
serves), not the binary and not the log directory.

Cross-check with `list_sites` so you do not add a site that is already there.

**Stop and ask** if a candidate looks like it does not belong to the user - a
container root, another user's application, a system service, a path outside
their home or web directories, or a port they do not recognize. Never configure
a site you cannot attribute to this user.

### Step 4 - Configure the sites

With `--allow-write`:

```
add_site(name="Shop", path="/var/www/shop", port=8080)
add_site(name="Blog", path="/var/www/blog", port=8081, log_monitor_enabled=true,
         access_log_path="/var/log/nginx/access.log")
```

* The response contains `site`, `written`, `valid`, `errors`, `warnings` and the
  full `validation` block. If `valid` is false, read `errors` and fix it now.
* `path` does not exist → either ask the user for the real path, or pass
  `create_directory: true` if the user confirms the directory may be created.
* The stable `id` is derived from the name. If the user later renames the site,
  use `update_site`, never a new `add_site` - the id is the ownership key for
  every record and log file.
* Enable access-log analysis only when the user knows where the web server
  writes its access log. It is a second detection source, not a requirement.

### Step 5 - Configure notifications (see the ask-list in section 3)

Values that are secrets go to `.env`, never to `config.toml`:

```
set_env_value(key="ANTEUMBRA_EMAIL_PASSWORD", value="<the authorization code>")
set_env_value(key="ANTEUMBRA_WECHAT_API_KEY", value="<the send key>")
set_env_value(key="CLOUDFLARE_API_TOKEN", value="<the API token>")
```

Non-secret switches go to `config.toml` through the same code path the CLI uses:

```
set_config_value(key="notifier.enabled", value="true")
set_config_value(key="notifier.email.enabled", value="true")
set_config_value(key="notifier.email.smtp_host", value="smtp.163.com")
set_config_value(key="notifier.email.smtp_port", value="465")
set_config_value(key="notifier.wechat.enabled", value="true")
```

`set_env_value` writes `.env` only and returns `restart_required: true`: the
running process reads `.env` at startup, so the change takes effect after a
restart. The value you send is never echoed back in the response.

### Step 6 - Validate

Call `validate_config`. It runs Anteumbra's own validation and returns the CLI's
output plus `errors` and `warnings` as lists.

* `valid: true` and `errors: []` → continue.
* Any error → fix it and validate again. Do not start or restart the service
  with a failing config.
* Warnings are informational but read them aloud in your report when they
  concern security (`ANTEUMBRA_SECRET_KEY is not customized`, session cookies
  without HTTPS, an admin password hash that is empty).

### Step 7 - Start or restart

MCP does not manage the process; the CLI does. Run it yourself if you have shell
access, otherwise ask the user:

```bash
anteumbra --home /opt/anteumbra start      # background; prints the admin URL
anteumbra --home /opt/anteumbra stop       # stop before restarting
anteumbra --home /opt/anteumbra run        # foreground, for watching startup
```

Restart after changing `.env`. `config.toml` is hot-reloaded after
`timeouts.config_reload_delay` seconds, but a restart is the unambiguous way to
apply a change.

### Step 8 - Verify (section 5 is the checklist, this is how)

Call `get_status` until `runtime.running` is true and `health.reachable` is
true, then `list_sites` to confirm each site is `enabled: true`, and
`list_sites_summary` for the per-site view.

Then prove detection works end to end, because "no alerts" is otherwise
indistinguishable from "not watching":

1. Write one harmless test file into the web root, using an extension the
   monitor watches (`paths.monitor_extensions`, default `.php .asp .aspx .jsp
   .jspx`):

   ```powershell
   Set-Content -Path "C:\www\shop\anteumbra-selftest-1.php" -Value '<?php eval(base64_decode($_POST["c"])); ?>'
   ```

   ```bash
   printf '%s\n' '<?php eval(base64_decode($_POST["c"])); ?>' > /var/www/shop/anteumbra-selftest-1.php
   ```

2. Wait a few seconds, then call `list_detections` with `status: "active"` and
   the site id. A row with your test path must appear.
3. Delete the test file and say so in your report: the detection record stays in
   the registry - it is evidence of the verification, not a false alarm, and the
   user can mark it reviewed in the web UI.
4. If no row appears after ~30 seconds, check `list_sites` (`reachable`,
   `path`), the instance log (`logs/Anteumbra/system.log`) and
   `timeouts.scan_timeout` before telling the user detection works.

`run_memory_shell_probe` is a separate, deeper check: it drops Anteumbra's own
token-guarded JSP probe into a site, enumerates what the servlet container has
in memory, and deletes the probe. It is only offered when the instance is
**stopped**, because a running monitor would report Anteumbra's own probe as a
new file. With the service running, use the `/admin/memory-shell` page instead.

### Step 9 - Report (section 6)

### Step 10 - Stay available

Re-run `get_status`, `list_detections` or `list_quarantine` whenever the user
asks "is anything happening?" - that is what this server is for.

---

## 3. What to ask the user, and why

Ask in this order, one topic at a time. Never invent a value and never fill in a
placeholder to get past a validation error.

### 3.1 Which sites to monitor
**Ask**: name, web root path and port for every site they want watched.
**Why**: a wrong path watches nothing, and a path that is not the document root
misses the files an attacker would upload.
**Where they find it**: the web server's own configuration - `root` in Nginx,
`DocumentRoot` in Apache, `appBase`/`docBase` in Tomcat, the site's physical
path in the IIS manager. `discover_web_services` may already have filled this in.

### 3.2 Admin password
**Ask**: whether they want to set the admin password now, and tell them not to
paste the password itself into the chat if they can avoid it.
**Why**: the web UI login; Anteumbra stores only a hash, so nobody - including
you - can read the existing password back.
**Where**: the user chooses it. Have them run this themselves and paste only the
hash:

```bash
python -c "from werkzeug.security import generate_password_hash; print(generate_password_hash('THEIR_PASSWORD'))"
```

then `set_env_value(key="ANTEUMBRA_PASSWORD_HASH", value="<the hash>")` and
restart. `anteumbra config wizard` also prompts for it interactively.

### 3.3 Notification channel
**Ask**: email, WeChat/WeCom, a generic webhook, or nothing?
**Why**: a detection nobody hears about is not a control. `notifier.enabled` is
false by default.
**Where**: their choice; the settings below belong to whatever they pick.

### 3.4 Email: SMTP server, port, username, and the **authorization code**
**Ask**: SMTP host, port, the sending account, and the **POP3/SMTP
authorization code** - not the mailbox login password.
**Why**: most Chinese mail providers (163, 126, QQ, and most enterprise
mailboxes) reject the account password for SMTP and require a separate
authorization code. The account password in `.env` is the single most common
reason "email alerts do not work".
**Where they find it**: the mail provider's web settings, usually
"设置 → 账户/POP3/SMTP/IMAP 服务 → 开启服务 → 生成授权码"; it is shown once, so
they must copy it immediately. Common hosts: `smtp.163.com:465`,
`smtp.qq.com:465`, `smtp.exmail.qq.com:465`, `smtp.gmail.com:587`.
**How to apply**:

```
set_config_value(key="notifier.email.smtp_host", value="smtp.163.com")
set_config_value(key="notifier.email.smtp_port", value="465")
set_config_value(key="notifier.email.use_ssl", value="true")
set_env_value(key="ANTEUMBRA_EMAIL_USERNAME", value="alerts@example.com")
set_env_value(key="ANTEUMBRA_EMAIL_PASSWORD", value="<authorization code>")
set_env_value(key="ANTEUMBRA_EMAIL_FROM", value="alerts@example.com")
set_env_value(key="ANTEUMBRA_EMAIL_TO", value="oncall@example.com")
```

Then restart, and ask the user to confirm they received the next alert.

### 3.5 WeChat: Server酱 / WeCom send key or webhook URL
**Ask**: whether they use Server酱 (SendKey) or a WeCom group robot webhook, and
for that key or URL.
**Why**: `notifier.wechat.send_key` is empty by default, so the channel stays
disabled even when `notifier.wechat.enabled` is true.
**Where they find it**: Server酱 - sct.ftqq.com after logging in with GitHub,
the SendKey looks like `SCT...`; WeCom - group settings → 群机器人 → 添加 →
copy the webhook URL `https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=...`.
**How to apply** (send key):

```
set_env_value(key="ANTEUMBRA_WECHAT_API_KEY", value="<SendKey>")
set_config_value(key="notifier.wechat.enabled", value="true")
```

or (WeCom webhook - keep the URL out of `config.toml` by referencing `.env`):

```
set_env_value(key="ANTEUMBRA_WEBHOOK_URL", value="<the webhook URL>")
set_config_value(key="notifier.webhook.url", value="${ANTEUMBRA_WEBHOOK_URL:-}")
set_config_value(key="notifier.webhook.enabled", value="true")
```

### 3.6 WAF / Cloudflare token (optional)
**Ask**: whether they want WAF events, and for a Cloudflare API token or their
WAF's poll URL and API key.
**Why**: attacker profiling gets much better with WAF events; it is optional and
Anteumbra works without it.
**Where**: Cloudflare dashboard → My Profile → API Tokens → Create Token
(Zone:Analytics:Read); or their WAF's integration/API page.
**How to apply**: `set_env_value(key="CLOUDFLARE_API_TOKEN", value="<token>")`
and `set_config_value(key="plugins.cloudflare.enabled", value="true")`; for a
generic WAF `set_env_value(key="ANTEUMBRA_WAF_API_KEY", value="<key>")` plus
`waf_source.enabled`, `waf_source.type` and `waf_source.url`.

### 3.7 Auto-quarantine and IP blocking
**Ask**: explicitly, out loud - "do you want Anteumbra to move detected files
out of the web root automatically, and do you want it to block attacker IPs?"
**Why**: both change the state of a production system. Quarantine moves a file
(a false positive breaks the site); IP blocking pushes rules to a firewall or
WAF (a false positive locks out a real user or a health checker).
**Where**: their operational decision, not a technical detail.
**Defaults and keys**: `quarantine.auto_quarantine_enabled` is `false` and
`ip_blocker.auto_block_enabled` is `false` - keep them false unless the user
says otherwise in as many words. Manual actions in the web UI stay available.

### 3.8 Anything else you need, only if it comes up
Access-log path (`website.log_config.access_log_path`); the admin bind address
(`web_admin.host`/`port`, keep `127.0.0.1` unless they use a reverse proxy);
`paths.monitor_extensions` when their site uses another script type.

---

## 4. Safety rules (non-negotiable)

1. **Never enable IP blocking or auto-quarantine without explicit
   confirmation.** Not "the user said yes to notifications" - a separate, clear
   yes to that specific change.
2. **Never print a secret.** Do not echo a password, authorization code, send
   key or API token into the chat, into a report, or into a file inside the web
   root. Read-only tools redact them already; do not undo that by asking the
   user to paste one back.
3. **Ask before every mutating call.** Say what you are about to change and why,
   in one sentence, and wait for the answer.
4. **Stop and ask when a discovered service looks like it does not belong to
   this user** - a container root, a system service, another user's account, an
   unknown port. Do not configure it, do not scan it.
5. **Never edit `config.toml` or `.env` by hand.** Use `set_config_value`,
   `set_env_value`, `add_site`, `update_site`, `disable_site`. They call the same
   code the CLI calls, and they revalidate.
6. **Never delete anything in `data/`, `logs/` or `quarantine/`.** Those
   directories are the audit trail.
7. **Do not run `anteumbra stop` on an instance the user did not ask you to
   restart** - other people may be relying on the running service.
8. **Say "I could not verify this" when you could not.** A `document_root` of
   `null`, a listener with no owning process, a warning about the secret key:
   report it, do not paper over it.
9. **Do not put a test file anywhere except a web root the user agreed to
   monitor**, and delete it when you are done.

---

## 5. Verification checklist

Do not report success until every line is true or explicitly marked as not
verified.

- [ ] `validate_config` → `valid: true`, `errors: []`.
- [ ] `get_status` → `runtime.running: true` and `health.reachable: true`.
- [ ] `list_sites` → every site the user asked for shows `enabled: true`, the
      right `path` and `port`, and `reachable: true` for a running web server.
- [ ] `list_sites_summary` → `sites_enabled` matches the user's list, and the
      sites appear as `watched: true`.
- [ ] `get_config` → `notifier.enabled` and the chosen channel are `true`, and
      every secret you stored shows `***REDACTED***` (not your value).
- [ ] A test file written into a monitored web root produces a row in
      `list_detections` (Step 8), and the test file has been deleted.
- [ ] If memory shells matter to the user: `run_memory_shell_probe` (stopped
      instance) or `/admin/memory-shell` (running instance) completes with
      `cleanup_error` empty.
- [ ] Everything you could not check is listed in your report with the reason.

---

## 6. What to tell the user when you are done

Keep it to these facts, in this order:

1. **Admin URL** - from `get_status.admin_url` (for example
   `http://127.0.0.1:8080/admin`), and the username (`admin` by default). They
   set the password themselves; remind them you never saw it.
2. **Monitored sites** - one line each: name, path, port, whether access-log
   analysis is on.
3. **How it watches** - file changes are detected by OS events (watchdog), then
   YARA-scanned; `scanner.scan_existing_on_start` scans what is already on disk
   at startup; YARA time limit `timeouts.scan_timeout`; `config.toml` is
   reloaded `timeouts.config_reload_delay` seconds after it changes; `.env`
   needs a restart.
4. **What happens on a detection** - the file is registered, an alert goes to
   the channels you enabled, and quarantine/IP blocking stay off unless they
   asked otherwise.
5. **Where the data is** - `get_status.data_dir` (registry, quarantine index,
   block ledger, SQLite database) and `get_status.log_dir`
   (`{site_id}/monitor.log`, `Anteumbra/system.log`, `Anteumbra/access.log`).
6. **How to stop and restart** -
   `anteumbra --home <instance> stop` and `... start`; `... run` stays in the
   foreground.
7. **What you verified and what you did not** - the checklist above, honestly.

---

## 7. CLI commands you may need

```bash
anteumbra --home <DIR> status                    # process state
anteumbra --home <DIR> mcp tools                 # the tool surface, write-gated
anteumbra --home <DIR> mcp tools --allow-write   # what write mode would expose
anteumbra --home <DIR> config validate           # same validation the tool runs
anteumbra --home <DIR> config set <key> <value>  # same path set_config_value uses
anteumbra --home <DIR> config env set KEY VALUE  # same path set_env_value uses
anteumbra skill export <DIR>                     # copy this skill into a skills root
anteumbra mcp serve                              # the server the client starts
```

Missing-SDK behaviour: if the `mcp` extra is not installed, `anteumbra mcp
serve` prints one line ending in `pip install "anteumbra[mcp]"` on stderr and
exits 1. `anteumbra mcp tools` still works - it never imports the SDK.

---

## 8. 中文速查

* **目标**：你是 agent，Anteumbra 只提供 MCP 工具面和本 Skill，它自己不带 AI。
* **顺序**：`get_status` → `discover_web_services`（+`list_listening_ports`）→
  和用户确认要监控哪些站点 → `add_site` → `set_env_value`（密钥只写 `.env`）/
  `set_config_value`（普通开关写 `config.toml`）→ `validate_config` →
  用 CLI `anteumbra --home <目录> stop/start` 重启 → `list_sites`、
  `list_sites_summary`、`list_detections` 验证 → 回报用户。
* **必须问用户**：站点根目录与端口；管理员密码（让用户自己生成哈希，不要把密码贴进对话）；
  通知渠道；SMTP 服务器/端口/账号，以及**邮箱的 POP3/SMTP 授权码**（不是邮箱登录密码，
  在邮箱网页端"设置 → 账户 → POP3/SMTP 服务"里生成，只显示一次）；Server酱 SendKey 或
  企业微信机器人 webhook；是否要 WAF/Cloudflare 事件；**是否开启自动隔离与 IP 封禁**。
* **默认安全**：`quarantine.auto_quarantine_enabled` 与 `ip_blocker.auto_block_enabled`
  默认 `false`，没有用户明确同意前不得开启；不打印任何密钥；每次写操作前先确认；
  发现的服务若不像属于该用户，停下来问。
* **完成后告诉用户**：管理地址与登录名、被监控的站点、监控方式（文件事件 + YARA 扫描、
  启动扫描、配置热加载延迟）、检测后会发生什么、数据与日志目录、如何停止/重启、以及
  哪些验证没做成。
