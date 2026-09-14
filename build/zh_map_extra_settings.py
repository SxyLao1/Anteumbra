# -*- coding: utf-8 -*-
"""Chinese strings for the settings page restructure and plugin control.

Owned by the settings/plugin-control work: the settings page gained ordered
collapsible sections with live state summaries, and the plugin panel gained an
effective status matrix plus enable/disable and builtin controls.  ``build/
build_zh_catalog.py`` merges this dict after ``zh_map_extra.py``, so an entry
here wins for the source strings this feature owns.

Only source strings that ``pybabel extract`` can see (``_('...')`` in templates,
``gettext('...')`` in settings_bp.py) take effect: the catalog build writes a
translation for every msgid present in ``messages.pot`` and skips the rest.
"""

ZH_MAP_EXTRA_SETTINGS = {
    # ── settings page: section headers and summaries ────────────────────────
    "ENVIRONMENT & SECRETS": "环境与密钥",
    "SITE CONFIGURATION": "站点配置",
    "MONITORING & DETECTION": "监控与检测",
    "STORAGE & PATHS": "存储与路径",
    "PLUGINS": "插件",
    "ADVANCED": "高级",
    "Mail credentials, tokens and keys are stored in .env next to config.toml. "
    "Empty fields are left untouched; values are never committed to git.":
        "邮件凭据、令牌与密钥保存在 config.toml 同目录的 .env 中。留空的字段不会被改写；"
        "这些值不会进入 git。",
    "Admin password hash": "管理员密码哈希",
    "The hash itself is never displayed; set a new password in the advanced section below.":
        "哈希本身不会显示；请在下方高级分区中设置新密码。",
    "Save environment": "保存环境变量",
    "Written to .env and reloaded.": "已写入 .env 并重新加载。",
    "%(count)s value(s) written to .env": "已写入 .env：%(count)s 项",
    "Nothing to save: every field was left empty.": "没有可保存的内容：所有字段都留空了。",
    "Environment save failed: %(detail)s": "环境变量保存失败：%(detail)s",
    "Access log:": "访问日志：",
    "Access log analysis": "访问日志分析",
    "No website is configured.": "尚未配置任何站点。",
    "Watched paths": "监控路径",
    "Monitored extensions": "监控扩展名",
    "Auto quarantine": "自动隔离",
    "Auto IP block": "自动封禁 IP",
    "WAF source": "WAF 事件源",
    "none configured": "未配置",
    "not enabled": "未启用",
    "not configured": "未配置",
    # section header summaries
    "%(count)s credentials set": "已设置 %(count)s 项凭据",
    "mail configured": "邮件已配置",
    "mail not configured": "邮件未配置",
    "signed in as %(user)s": "当前登录：%(user)s",
    "%(count)s site(s) enabled": "%(count)s 个站点已启用",
    "%(count)s watched path(s)": "监控 %(count)s 个路径",
    "access log on": "访问日志已开启",
    "access log off": "访问日志未开启",
    "%(count)s channel(s) enabled": "已启用 %(count)s 个通知通道",
    "notifications off": "通知未开启",
    "backend %(backend)s": "存储后端 %(backend)s",
    "plugin system not attached": "插件系统未接入",
    "%(loaded)s loaded / %(total)s available": "已加载 %(loaded)s / 共 %(total)s 个",
    "config file %(name)s": "配置文件 %(name)s",
    # ── plugin panel: effective status ──────────────────────────────────────
    "Active:": "活跃：",
    "Loaded": "已加载",
    "Not running": "未运行",
    "Run state unknown": "运行状态未知",
    "Config section:": "配置段：",
    "not set explicitly": "未显式配置",
    "enabled is not reported for a plugin that is not loaded":
        "插件未加载时不显示 enabled 状态",
    # ── plugin panel: controls ──────────────────────────────────────────────
    "Enable": "开启",
    "Disable": "关闭",
    "Add to builtin": "加入 builtin",
    "Remove from builtin": "移出 builtin",
    "Protected:": "受保护：",
    # ── plugin control results ──────────────────────────────────────────────
    "Switched off %(name)s: config.toml written and the plugin was unloaded from "
    "the running runtime.":
        "已关闭 %(name)s：配置已写入 config.toml，并已从运行中的运行时卸载。",
    "Switched on %(name)s: config.toml written and the plugin was registered in "
    "the running runtime.":
        "已开启 %(name)s：配置已写入 config.toml，并已在运行中的运行时注册。",
    "Added %(name)s to [plugins] builtin and loaded it in the running runtime.":
        "已将 %(name)s 加入 [plugins] builtin，并在运行中的运行时加载。",
    "Removed %(name)s from [plugins] builtin and unloaded it from the running runtime.":
        "已将 %(name)s 移出 [plugins] builtin，并从运行中的运行时卸载。",
    "the plugin system is switched off in this process": "本进程的插件系统处于关闭状态",
    "no plugin manager is attached to this runtime": "该运行时没有挂载插件管理器",
    "Config written, but %(name)s could not be applied to the running runtime "
    "(%(reason)s). A restart is required.":
        "配置已写入，但 %(name)s 无法在运行中的运行时生效（%(reason)s）。需要重启生效。",
    "Config written, but applying %(name)s to the running runtime failed: "
    "%(detail)s A restart is required to pick the configuration up.":
        "配置已写入，但在运行中的运行时应用 %(name)s 失败：%(detail)s 需要重启才能生效。",
    "the plugin did not activate": "插件未成功激活",
    "Config written and the runtime reload failed (%(detail)s); the running plugin "
    "state was left untouched. A restart is required.":
        "配置已写入，但运行时重新加载失败（%(detail)s）；运行中的插件状态未改动。需要重启生效。",
    "Note: %(name)s is still listed in [plugins] builtin, so a restart loads it "
    "again from there.":
        "注意：%(name)s 仍在 [plugins] builtin 中，重启后会再次从那里加载。",
    "Note: %(name)s is not listed in [plugins] builtin, so a restart will not load it.":
        "注意：%(name)s 不在 [plugins] builtin 中，重启后不会加载它。",
    "Note: %(name)s is no longer listed in [plugins] builtin, so a restart will not "
    "load it.":
        "注意：%(name)s 已不在 [plugins] builtin 中，重启后不会再加载它。",
    "Not set": "未设置",
    "Backup kept: %(file)s": "已保留备份：%(file)s",
    "Unknown plugin: %(name)s": "未知插件：%(name)s",
    "Unsupported plugin action: %(action)s": "不支持的插件操作：%(action)s",
    "%(name)s is listed in config.toml, but this build has no implementation for it.":
        "config.toml 中列出了 %(name)s，但本构建没有它的实现。",
    "%(name)s is already listed in [plugins] builtin.":
        "%(name)s 已经列在 [plugins] builtin 中。",
    "%(name)s is not listed in [plugins] builtin.":
        "%(name)s 不在 [plugins] builtin 中。",
    "Runtime alerting is delivered by this plugin; switching it off would silently "
    "drop every alert.":
        "运行时的告警投递依赖该插件；关闭它会静默丢弃所有告警。",
    "Refused: %(name)s must stay switched on and listed in builtin. %(reason)s":
        "已拒绝：%(name)s 必须保持开启并列在 builtin 中。%(reason)s",
    "Configuration path is unavailable; nothing was written.":
        "配置文件路径不可用；未写入任何内容。",
    "Config write failed for %(name)s: %(detail)s":
        "写入 %(name)s 的配置失败：%(detail)s",
    "Config write refused for %(name)s: %(detail)s":
        "拒绝写入 %(name)s 的配置：%(detail)s",
    "validation failed": "校验未通过",
    "Plugin control failed: %(detail)s": "插件控制失败：%(detail)s",
    # ── readability pass: filters, jump control, section counters ───────────
    # The filter labels live in SETTINGS_FILTER_LABELS and are passed through
    # ``_(label)`` by the template, so the msgid is the label itself.
    "Show:": "显示：",
    "All values": "全部取值",
    "Only non-default values": "仅显示非默认值",
    "Only changed from shipped defaults": "仅显示与出厂默认不同的值",
    "Jump to:": "跳转到：",
    "choose a section...": "选择一个分区...",
    "Advanced config editor": "高级配置编辑器",
    "Raw config.toml editing (advanced)": "直接编辑 config.toml（高级）",
    "Every key in the file, full validation, and a backup on every save.":
        "文件中的每一个键、完整校验，且每次保存都会留备份。",
    "%(count)s changed": "已修改 %(count) 项",
    "all defaults": "全部为默认值",
    "filtered": "已过滤",
    "The readability filter is active; plugin rows and settings are shown accordingly.":
        "可读性过滤已生效；插件行与设置项按该条件显示。",
    "This section is the only place on this page that writes .env. The config editor "
    "below is a legacy copy of the same fields; it is kept for compatibility and is not "
    "needed for a normal change.":
        "本分区是本页唯一写入 .env 的地方。下方配置编辑器是同一批字段的遗留副本，仅为兼容保留，"
        "正常修改不需要使用它。",
    # ── readability pass: guarded keys ──────────────────────────────────────
    "Keys that remove a protection": "会移除防护的配置项",
    "caution": "注意",
    "current:": "当前值：",
    "from": "来源",
    "These keys are edited in the advanced config editor, which validates them before writing.":
        "这些配置项在高级配置编辑器中修改，写入前会经过校验。",
    # ── readability pass: the password flow ─────────────────────────────────
    "Admin password": "管理员密码",
    "config.toml stores only a hash (web_admin.password_hash). Set a new password here; "
    "it is hashed before it is written, so no plaintext ever reaches disk.":
        "config.toml 只保存哈希（web_admin.password_hash）。在此设置新密码，写入前会先做哈希，"
        "明文不会落盘。",
    "New password (min 6 characters)": "新密码（至少 6 个字符）",
    "Repeat the new password": "再次输入新密码",
    "Set a new password": "设置新密码",
    "Hash: scrypt via werkzeug": "哈希算法：werkzeug scrypt",
    "Password too short: at least %(count)s characters are required.":
        "密码过短：至少需要 %(count)s 个字符。",
    "The two passwords do not match.": "两次输入的密码不一致。",
    "New password hash written to .env. Existing sessions stay signed in until they "
    "expire; the next sign-in uses the new password.":
        "新密码哈希已写入 .env。已登录的会话会保持到过期，下次登录请使用新密码。",
    "Changing the password failed: %(detail)s": "修改密码失败：%(detail)s",
    # ── plugin panel: configuration entry points ────────────────────────────
    "Configure": "配置",
    "Settings:": "设置项：",
    "%(count)s differ from defaults": "%(count)s 项与默认值不同",
    "%(count)s differ from the shipped file": "%(count)s 项与出厂文件不同",
    "all at defaults": "全部为默认值",
    "%(count)s with changed values": "%(count)s 个存在已修改的值",
    "Showing %(shown)s of %(total)s": "显示 %(shown)s / %(total)s",
    "%(changed)s of %(total)s plugins have values that differ from their defaults; "
    "showing those %(shown)s.":
        "%(total)s 个插件中有 %(changed)s 个存在与默认值不同的配置；当前显示其中 %(shown)s 个。",
    "%(changed)s of %(total)s plugins have values that differ from the shipped config.toml "
    "defaults; showing those %(shown)s.":
        "%(total)s 个插件中有 %(changed)s 个与出厂 config.toml 默认值不同；当前显示其中 %(shown)s 个。",
    # ── plugin configuration form ───────────────────────────────────────────
    "Configuration:": "配置：",
    "%(count)s setting(s), %(changed)s differ from the default":
        "共 %(count)s 项设置，其中 %(changed)s 项与默认值不同",
    "changed from default": "已偏离默认值",
    "default": "默认值",
    "default:": "默认：",
    "effective from:": "当前生效来源：",
    "differs from the shipped config.toml": "与出厂 config.toml 不同",
    "not present in config.toml yet": "config.toml 中尚无此项",
    "comma separated, or a JSON list": "逗号分隔，或使用 JSON 列表",
    "set": "已设置",
    "not set": "未设置",
    "A value is stored; it is never displayed.": "已存有值；该值不会显示。",
    "No value is stored yet.": "尚未存有值。",
    "Set a new value (leave blank to keep the stored one)": "输入新值（留空则保留已存的值）",
    "No .env variable is declared for this secret, so it cannot be changed from here.":
        "该密钥未声明对应的 .env 变量，无法在此修改。",
    "This is a literal value in config.toml, so a value saved to .env will not take effect "
    "until config.toml references the variable.":
        "该值以字面量形式写在 config.toml 中，因此保存到 .env 的值不会生效，"
        "除非 config.toml 改为引用该变量。",
    "No value is in effect: config.toml refers to ${%(var)s}, which .env does not define "
    "and which has no fallback.":
        "当前没有生效的值：config.toml 引用了 ${%(var)s}，而 .env 未定义该变量且没有回退值。",
    "This plugin declares no schema in this build, so these controls were derived from the "
    "keys present in config.toml. Types inferred from a value can be wrong — check the "
    "effective value after saving.":
        "该插件在本构建中未声明配置结构，以下控件依据 config.toml 中实际存在的键推导而来。"
        "由取值推断的类型可能有误——保存后请核对当前生效值。",
    "No setting is shown: every field is at its default and the readability filter is active.":
        "未显示任何设置项：所有字段均为默认值，且当前启用了可读性过滤。",
    "%(count)s field(s) differ from the default.": "%(count)s 个字段与默认值不同。",
    "Save plugin settings": "保存插件设置",
    "Written to config.toml with a timestamped backup; secrets go to .env.":
        "写入 config.toml 并保留带时间戳的备份；密钥写入 .env。",
    # ── plugin configuration validation (server-side, operator-facing) ──────
    "This value is required.": "此项为必填。",
    "Expected a boolean (true or false).": "应为布尔值（true 或 false）。",
    "Expected a number.": "应为数字。",
    "Must be at least %(min)s.": "不得小于 %(min)s。",
    "Must be at most %(max)s.": "不得大于 %(max)s。",
    "Must be one of: %(choices)s.": "必须是以下之一：%(choices)s。",
    "Expected a list, for example a, b, c.": "应为列表，例如 a, b, c。",
    "At least one value is required.": "至少需要一项。",
    "Every entry must be %(hint)s: %(item)s": "每一项都必须是%(hint)s：%(item)s",
    "Expected %(hint)s.": "应为%(hint)s。",
    "a different format": "其他格式",
    "valid": "合法取值",
    "No .env variable is declared for this secret, so it cannot be written safely from here.":
        "该密钥未声明对应的 .env 变量，无法从此处安全写入。",
    "Nothing was written: %(count)s value(s) were rejected. Fix the fields marked below and "
    "save again.":
        "未写入任何内容：%(count)s 项被拒绝。请修正下方标记的字段后重新保存。",
    "No plugin was named.": "未指定插件。",
    "%(name)s declares no settings this build can write.":
        "%(name)s 在本构建中未声明可写入的设置项。",
    "Nothing to save: every value is unchanged.": "没有可保存的内容：所有取值均未变化。",
    "The plugin reads this section once, at activation: a saved value takes effect after the "
    "plugin is reloaded or Anteumbra is restarted.":
        "该插件在激活时只读取本配置段一次：保存的值需在插件重新加载或 Anteumbra 重启后生效。",
    # ── plugin configuration save results ───────────────────────────────────
    "Saved %(count)s value(s) for %(name)s and reloaded the plugin, so the running runtime "
    "uses them now.":
        "已为 %(name)s 保存 %(count)s 项，并重新加载该插件，运行中的运行时立即生效。",
    "Saved %(count)s value(s) for %(name)s. The plugin is not loaded right now, so they apply "
    "the next time it activates.":
        "已为 %(name)s 保存 %(count)s 项。该插件当前未加载，将在下次激活时生效。",
    "Saved %(count)s value(s) for %(name)s, but reloading the plugin failed (%(detail)s). "
    "A restart is required; the previous instance may have been unloaded.":
        "已为 %(name)s 保存 %(count)s 项，但重新加载插件失败（%(detail)s）。需要重启；"
        "原实例可能已被卸载。",
    "Saved %(count)s value(s) for %(name)s to disk, but they could not be applied to the "
    "running runtime (%(detail)s). A restart is required.":
        "已为 %(name)s 将 %(count)s 项写入磁盘，但无法应用到运行中的运行时（%(detail)s）。"
        "需要重启生效。",
    "%(count)s secret(s) written to .env. Their values are never shown or logged; the field "
    "only reports whether one is set.":
        "已向 .env 写入 %(count)s 个密钥。其取值不会被显示或记录日志；字段只报告是否已设置。",
    "%(fields)s is still a literal value in config.toml, which the loader does not replace: "
    "the .env value that was just written is not in effect. Change config.toml to reference "
    "the variable, then restart.":
        "%(fields)s 仍是 config.toml 中的字面量，加载器不会替换它：刚写入 .env 的值并未生效。"
        "请将 config.toml 改为引用该变量，然后重启。",
    ".env write failed after %(written)s of %(total)s secret(s) were stored (%(detail)s). "
    "Nothing else was changed.":
        "已存入 %(written)s / %(total)s 个密钥后 .env 写入失败（%(detail)s）。其余内容未改动。",
    "%(fields)s has no .env variable name in this build, so it stays read-only here. Set it "
    "in .env and reference it from config.toml.":
        "%(fields)s 在本构建中没有对应的 .env 变量名，因此在此保持只读。请在 .env 中设置它，"
        "并在 config.toml 中引用。",
    "%(fields)s is a literal value in config.toml, and the loader only substitutes ${VAR} "
    "placeholders: a value saved to .env will not take effect until config.toml references "
    "the variable instead.":
        "%(fields)s 是 config.toml 中的字面量，而加载器只会替换 ${VAR} 占位符："
        "在 config.toml 改为引用该变量之前，保存到 .env 的值不会生效。",
    "No value is in effect for %(fields)s yet: config.toml refers to %(vars)s, which .env "
    "does not define and which has no fallback.":
        "%(fields)s 目前没有生效的值：config.toml 引用了 %(vars)s，而 .env 未定义该变量，"
        "且没有回退值。",
    # ── shell navigation: the advanced editor this page links to ────────────
    "Config Editor": "配置编辑器",
    # Source labels.  ``config.toml`` and ``.env`` stay verbatim on purpose: they
    # are file names an operator types, not prose.
    "shipped default": "出厂默认值",
    "built-in default": "内置默认值",
    "Configured:": "已配置：",
}
