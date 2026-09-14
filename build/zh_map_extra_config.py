# -*- coding: utf-8 -*-
"""Chinese strings for the advanced config editor (``/admin/config``).

Owned by the config-editor work: the page gained one document model behind three
views (form / tree / raw), a write-only secrets tab, and a version history with
diff, restore and download.  ``build/build_zh_catalog.py`` merges this dict after
``zh_map_extra.py``, so an entry here wins for the source strings this feature
owns.

Msgids that already had an authored translation elsewhere - ``Error``, ``Refresh``,
``Time``, ``Source``, ``Actions``, ``Restore``, ``Clear``, ``set``, ``not set``,
``Set a new password``, ``The two passwords do not match.`` - are deliberately
absent: the catalog is global, so re-translating a shared msgid here would change
every other page that uses it.

Only source strings that ``pybabel extract`` can see (``_('...')`` in the editor
templates, ``gettext('...')`` in ``config_editor_bp.py``) take effect.
"""

ZH_MAP_EXTRA_CONFIG = {
    # ── page shell: tabs, counters, validate ────────────────────────────────
    "Editor": "编辑器",
    "Secrets": "密钥",
    "History": "历史版本",
    "Configuration editor": "配置编辑器",
    "%(keys)s keys": "%(keys)s 个配置项",
    "%(count)s tables": "%(count)s 个表",
    "Validate now": "立即校验",
    "Reload history": "重载记录",
    # ── view switch, search and readability filters ─────────────────────────
    "Form": "表单",
    "Tree": "树形",
    "Raw": "原文",
    "Search keys, values and comments...": "搜索配置项、值与注释…",
    "Only values set here": "仅显示已设置的值",
    "Hide everything still identical to the shipped config.toml":
        "隐藏与随附 config.toml 完全相同的项",
    "Only keys changed from the shipped defaults": "仅显示相对随附默认值有改动的项",
    "%(shown)s of %(total)s keys shown": "已显示 %(shown)s / %(total)s 个配置项",
    "%(count)s changed from defaults": "%(count)s 项与默认值不同",
    # ── form view ───────────────────────────────────────────────────────────
    "Form view": "表单视图",
    "Review changed fields": "检查已修改字段",
    "Every control shows the effective value and where it comes from. A single-value "
    "edit rewrites only that key's line, so comments and formatting survive.":
        "每个控件显示生效值及其来源。单值编辑只重写该配置项所在的行，注释与格式保持不变。",
    "No key matches the current filters.": "没有配置项符合当前筛选条件。",
    "%(count)s key(s)": "%(count)s 项",
    # ── tree view ───────────────────────────────────────────────────────────
    "Tree view": "树形视图",
    "new_key": "配置项名",
    "new.table": "表名",
    "value": "值",
    "Adds one line at the end of this table; nothing else moves.":
        "在该表末尾追加一行，其他内容不变。",
    "Add key": "添加配置项",
    "Add another block like this": "再添加一个同类块",
    "Remove this block": "删除此块",
    "Remove this table": "删除此表",
    "Structural changes re-serialize the file: comments may be reformatted.":
        "结构性修改会重新序列化文件：注释格式可能被重排。",
    "A new table, or one more [[array.of.tables]] block. Re-serializes the file.":
        "新建一个表，或再添加一个 [[array.of.tables]] 块。会重新序列化文件。",
    "Add table or block": "添加表或块",
    "Arrays": "数组",
    "%(count)s item(s)": "%(count)s 项",
    "Add item": "添加项",
    "Remove item": "删除项",
    # ── raw view ────────────────────────────────────────────────────────────
    "Raw view": "原文视图",
    "secret values are redacted": "密钥值已脱敏",
    "Highlighted view of the file on disk": "磁盘文件的语法高亮视图",
    "Review raw changes": "检查原文修改",
    "The text is validated with the same validator the CLI uses before anything is "
    "written; the current file is backed up first.":
        "写入前会使用与 CLI 相同的校验器校验文本；当前文件会先备份。",
    # ── one key row ─────────────────────────────────────────────────────────
    "changed": "已改动",
    "secret": "密钥",
    "dangerous": "危险",
    "Review change": "检查修改",
    "Read-only": "只读",
    # ── the gated-save result ───────────────────────────────────────────────
    "Structural change: config.toml is re-serialized with the project writer, so "
    "comments and blank lines may be reformatted.":
        "结构性修改：config.toml 由项目写入器重新序列化，注释与空行可能被重排。",
    "Key": "配置项",
    "Change": "变更",
    "Old value": "原值",
    "New value": "新值",
    "No key value changed.": "没有任何配置项的值发生变化。",
    "blocking errors": "阻断性错误",
    "warnings (they do not block)": "警告（不会阻断保存）",
    "written": "已写入",
    "backup: %(name)s": "备份：%(name)s",
    "revision: %(id)s": "版本：%(id)s",
    "restart required": "需要重启",
    "Read once at startup: %(keys)s": "启动时读取一次：%(keys)s",
    "runtime reload failed": "运行时重载失败",
    "The runtime reloaded this change live.": "运行时已即时重载本次修改。",
    "Confirm save": "确认保存",
    "A timestamped backup of the current file is written first.":
        "会先为当前文件生成带时间戳的备份。",
    # ── version history ─────────────────────────────────────────────────────
    "Version history": "版本历史",
    "%(count)s revision(s)": "%(count)s 个版本",
    "Every save keeps a timestamped copy of config.toml next to it. Restoring one "
    "copies the current file aside first, revalidates the result with the same "
    "validator the CLI uses, and reports which keys need a restart.":
        "每次保存都会在 config.toml 旁保留一份带时间戳的副本。恢复某个版本时会先把当前文件"
        "另存为备份，再用与 CLI 相同的校验器重新校验，并说明哪些配置项需要重启。",
    "No revision yet: nothing has written config.toml from this page.":
        "暂无版本：尚未通过本页写入 config.toml。",
    "Changed keys": "变更的配置项",
    "%(size)s bytes": "%(size)s 字节",
    "backup of the file": "文件副本",
    "recorded change": "变更记录",
    "same keys as the file on disk": "与磁盘文件配置项相同",
    "comments or layout only": "仅注释或排版不同",
    "View diff": "查看差异",
    "Restore this backup? The current config.toml is copied aside first.":
        "恢复此备份？当前 config.toml 会先另存为备份。",
    "Download": "下载",
    "read-only record": "只读记录",
    # ── secrets tab ─────────────────────────────────────────────────────────
    "Secrets and credentials": "密钥与凭据",
    "write-only: values are never shown": "只写：不会显示已有值",
    "Credentials live in .env next to config.toml. Saving writes the variable and "
    "reloads the runtime; an empty field leaves the current value untouched, and no "
    "value is ever sent back to this page.":
        "凭据保存在 config.toml 同目录的 .env 中。保存会写入该变量并重载运行时；留空则保持"
        "原值，已有值不会回传到本页。",
    "resolves web_admin.password_hash": "对应 web_admin.password_hash",
    "New admin password": "新的管理员密码",
    "Repeat it": "再输入一次",
    "Hashed here; the hash is never displayed.": "在此处哈希；哈希值不会显示。",
    "Save to .env": "保存到 .env",
    "Clear this variable? Notifications or integrations using it stop working.":
        "清空此变量？使用它的通知或集成将失效。",
    "ANTEUMBRA_SECRET_KEY is deliberately not editable here: rotating it signs every "
    "session out.":
        "此处刻意不允许修改 ANTEUMBRA_SECRET_KEY：轮换它会让所有会话退出登录。",
    # ── why a key deserves a warning ────────────────────────────────────────
    "Turning automatic quarantine on moves every matching file out of the website "
    "directory.":
        "开启自动隔离会把所有命中文件移出网站目录。",
    "This list is the admin IP allow-list: an entry that does not cover your current "
    "address locks you out of this UI.":
        "此列表是管理端 IP 白名单：若其中的条目不包含你当前地址，你将无法登录本界面。",
    "Only a proxy you control belongs here; a wrong entry lets a client forge its own "
    "address in logs, profiles and blocking.":
        "此处只应填写你控制的代理地址；填错会让客户端在日志、画像与封禁中伪造来源地址。",
    "Forcing secure cookies over plain HTTP makes the login cookie unusable and locks "
    "everyone out.":
        "在纯 HTTP 下强制安全 Cookie 会导致登录 Cookie 失效，所有人都会被锁在外面。",
    "The IP blocker acts on live attacker addresses; a wrong threshold blocks real "
    "users at the WAF or firewall.":
        "IP 封禁会直接作用于真实攻击者地址；阈值填错会在 WAF 或防火墙上误封正常用户。",
    "The storage backend decides where detections are written; changing it splits the "
    "ledger this dashboard reads.":
        "存储后端决定检测记录的写入位置；更改它会让本仪表盘读取的台账出现分叉。",
    # ── mutation labels and confirmations ───────────────────────────────────
    "Edit %(key)s": "修改 %(key)s",
    "Edit %(count)s value(s)": "修改 %(count)s 个值",
    "Add key %(key)s": "添加配置项 %(key)s",
    "Remove key %(key)s": "删除配置项 %(key)s",
    "Add table %(table)s": "添加表 %(table)s",
    "Remove table %(table)s": "删除表 %(table)s",
    "Add an item to %(key)s": "向 %(key)s 添加一项",
    "Remove item %(index)s of %(key)s": "删除 %(key)s 的第 %(index)s 项",
    "Save the raw config.toml": "保存 config.toml 原文",
    "Set %(key)s in .env": "在 .env 中设置 %(key)s",
    "Set a new admin password": "设置新的管理员密码",
    "Validate %(name)s": "校验 %(name)s",
    "Validated %(name)s.": "已校验 %(name)s。",
    "Revision %(id)s": "版本 %(id)s",
    "Restore revision %(id)s": "恢复版本 %(id)s",
    "Unknown revision.": "未知版本。",
    # ── hints next to a secret control ──────────────────────────────────────
    "Set a new password instead of editing this hash.":
        "请改用“设置新密码”，不要直接编辑该哈希。",
    "Secret: set it in .env, never here.": "密钥：请在 .env 中设置，不要在此处填写。",
    "Credentials are read when the config loads, so the reload above is what applies "
    "this to the running runtime.":
        "凭据在配置加载时读取，因此上面的重载才会让它对运行中的实例生效。",
    "%(key)s written to .env; the value is never shown again.":
        "%(key)s 已写入 .env；该值不会再显示。",
    "The hash is never displayed, not even to you.": "该哈希不会显示，对你也不例外。",
    "web_admin.password_hash resolves this value, and it is read on every sign-in, so "
    "the reload above is what activates the new password.":
        "web_admin.password_hash 会解析该值，且每次登录都会读取，因此上面的重载才会让新密码"
        "生效。",
    "The new password is active for the next sign-in.": "新密码将在下次登录时生效。",
    # ── refusals and errors ─────────────────────────────────────────────────
    "No changes: nothing to save.": "没有变化：无需保存。",
    "Saving an empty table: no key value changed, and the file is re-serialized with "
    "the project writer.":
        "保存空表：没有任何配置项的值发生变化，文件将用项目写入器重新序列化。",
    "Only comments or formatting changed: no configuration key moved, and the file is "
    "still rewritten verbatim.":
        "仅注释或排版发生变化：没有任何配置项改变，文件仍会原样重写。",
    "Not saved: the change introduces configuration errors.":
        "未保存：该修改会引入配置错误。",
    "Review the changes below, then confirm to write config.toml.":
        "请确认下方变更，然后确认写入 config.toml。",
    "config.toml changed on disk since this preview (another editor, the CLI, or the "
    "runtime). Re-open the editor before saving.":
        "自本次预览以来 config.toml 已在磁盘上被改动（其他编辑器、CLI 或运行时）。请重新"
        "打开编辑器后再保存。",
    "Not saved: the file moved under us.": "未保存：文件在预览之后发生了变化。",
    "Written, but the resulting config.toml does not validate - restore a revision "
    "below.":
        "已写入，但生成的 config.toml 未通过校验——请在下方恢复某个版本。",
    "Saved and backed up, but the runtime could not reload: it is still running the "
    "previous configuration.":
        "已保存并备份，但运行时重载失败：它仍在运行旧的配置。",
    "Saved: config.toml written and reloaded.": "已保存：config.toml 已写入并重新加载。",
    "Secret values are not editable here: leave %(key)s as it is, or set a new "
    "password / .env value on the Secrets tab.":
        "此处不可编辑密钥值：请保持 %(key)s 原样，或在“密钥”页设置新密码 / .env 值。",
    "A redacted value was moved or duplicated; reload the raw view.":
        "脱敏值被移动或复制；请重新加载原文视图。",
    "Restoring this backup applies the changes below; the current file is backed up "
    "first.":
        "恢复该备份将应用下方变更；当前文件会先备份。",
    "That backup is no longer on disk.": "该备份已不在磁盘上。",
    "Recorded keys only: this entry stores no content to restore.":
        "仅记录配置项名：该条目没有可用于恢复的内容。",
    "This entry records which keys changed, not their content: it can be read but not "
    "restored or downloaded.":
        "该条目只记录哪些配置项发生了变更，不保存其内容：可以查看，但无法恢复或下载。",
    "That revision has no stored content to restore.": "该版本没有可恢复的内容。",
    "That revision has no stored content to download.": "该版本没有可下载的内容。",
    "That revision could not be redacted, so it will not be downloaded.":
        "该版本无法脱敏，因此不会提供下载。",
    "config.toml changed on disk since the preview; re-open the editor before "
    "restoring.":
        "自预览以来 config.toml 已在磁盘上被改动；请重新打开编辑器后再恢复。",
    "config.toml could not be read: %(detail)s": "无法读取 config.toml：%(detail)s",
    "No key was submitted.": "没有提交配置项。",
    "No table was submitted.": "没有提交表。",
    "No values were submitted.": "没有提交任何值。",
    "One value at a time: use Save changed fields instead.":
        "一次只能修改一个值：请改用“保存已修改字段”。",
    "A key name must be a bare TOML key.": "配置项名必须是裸 TOML 键名。",
    "A key and an array index are required.": "需要配置项名与数组下标。",
    "The submitted text is too large to save.": "提交的文本过大，无法保存。",
    "That variable cannot be edited here.": "该变量不能在此处编辑。",
    "Enter a value first; nothing was written.": "请先输入值；未写入任何内容。",
    "Use at least 8 characters for the admin password.": "管理员密码至少需要 8 个字符。",
    "The change could not be prepared: %(detail)s": "无法准备该修改：%(detail)s",
    "The .env value could not be written: %(detail)s": "无法写入 .env 值：%(detail)s",
    "The new password could not be written: %(detail)s": "无法写入新密码：%(detail)s",
}
