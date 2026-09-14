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
}
