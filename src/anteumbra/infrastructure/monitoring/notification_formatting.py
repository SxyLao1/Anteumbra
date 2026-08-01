"""Pure notification message formatting."""

from __future__ import annotations


def enhance_alert_message(message: str, analysis: dict | None = None) -> str:
    """Append access-log analysis details before transport dispatch."""
    if not analysis:
        return message
    suspicious_ips = analysis.get("suspicious_ips", {})
    if not suspicious_ips:
        return message

    lines = [
        message,
        "",
        "攻击溯源分析:",
        f"时间窗口: {analysis.get('create_time', '未知')}",
        "可疑IP访问统计:",
    ]
    lines.extend(f"   {ip}: {count}次" for ip, count in suspicious_ips.items())
    lines.append(f"日志文件: {analysis.get('log_path', '未知')}")
    return "\n".join(lines)


def _ip_label(ip: str) -> str:
    if not ip:
        return "未知"
    if ip in ("127.0.0.1", "::1", "0:0:0:0:0:0:0:1"):
        return f"{ip} (本机/内网)"
    return ip


def _disposition_block(status: dict) -> str:
    auto = status.get("auto_block_enabled", False)
    device_count = status.get("block_device_count", 0)
    ip = status.get("first_seen_ip") or status.get("attacker_ip", "")

    if auto and device_count > 0:
        return f"IP封禁: 已自动封禁 ({device_count} 台设备)\n  被封禁IP: {ip}"
    if auto and device_count == 0:
        return "IP封禁: 自动封禁已开启但无可用设备"
    return f"IP封禁: 已关闭自动封禁\n  可疑IP: {ip}\n  建议: 人工研判后在管理面板手动封禁"


def _disposition_quarantine(status: dict) -> str:
    auto = status.get("auto_quarantine_enabled", True)
    quarantine_id = status.get("quarantine_id")
    quarantine_path = status.get("quarantine_path")

    if quarantine_id and quarantine_path:
        return f"文件隔离: 已自动隔离\n  隔离ID: {quarantine_id}\n  隔离路径: {quarantine_path}"
    if not auto:
        return "文件隔离: 已关闭自动隔离（可手动在隔离管理页面操作）"
    return f"文件隔离: 隔离失败（{status.get('reason', '未知原因')}）"


def format_alert_message(context: dict) -> str:
    """Build the stable plain-text message for one alert context."""
    alert_type = context.get("alert_type", "unknown")
    timestamp = context.get("timestamp", "")
    level = context.get("level", "WARNING")

    header = f"[Anteumbra {level}] {timestamp}"
    site_id = str(context.get("site_id", "")).strip()
    site_name = str(context.get("site_name", "")).strip()
    if site_name and site_id:
        header += f"\n[Site] {site_name} ({site_id})"
    elif site_name or site_id:
        header += f"\n[Site] {site_name or site_id}"

    if alert_type == "local_detection":
        body = (
            "[!!] 内网边界突破告警\n\n"
            "可疑文件在本地被检测到（无外网访问记录）\n\n"
            f"文件路径: {context.get('file_path', '?')}\n"
            f"检测引擎: {context.get('engine', '?')}\n"
            f"匹配规则: {', '.join(context.get('features', [])[:5])}\n"
            f"首次发现IP: {_ip_label(context.get('first_seen_ip', ''))}\n"
            f"检测时间: {timestamp}"
        )
    elif alert_type == "webshell_access":
        body = (
            "[WEB] WebShell 被外部访问\n\n"
            f"文件路径: {context.get('file_path', '?')}\n"
            f"攻击IP: {context.get('attacker_ip', '?')}\n"
            f"告警级别: {context.get('alert_level', level)}\n"
            f"访问时间: {timestamp}"
        )
    elif alert_type == "quarantine_batch":
        body = (
            "[BATCH] 批量隔离完成\n\n"
            f"本次共隔离 {context.get('batch_count', 0)} 个可疑文件\n"
            f"完成时间: {timestamp}\n\n"
            "详情请登录管理面板查看 [威胁 -> 隔离管理]"
        )
    elif alert_type == "quarantine_single":
        body = (
            "[OK] 文件已隔离\n\n"
            f"文件路径: {context.get('file_path', '?')}\n"
            f"检测引擎: {context.get('engine', '?')}\n"
            f"匹配规则: {', '.join(context.get('features', [])[:5])}\n"
            f"首次发现IP: {_ip_label(context.get('first_seen_ip', ''))}"
        )
    elif alert_type == "quarantine_failed":
        body = (
            "[FAIL] 隔离失败\n\n"
            f"文件路径: {context.get('file_path', '?')}\n"
            f"检测引擎: {context.get('engine', '?')}\n"
            f"匹配规则: {', '.join(context.get('features', [])[:5])}\n"
            f"首次发现IP: {_ip_label(context.get('first_seen_ip', ''))}\n"
            f"失败原因: {context.get('reason', '未知')}\n"
            f"时间: {timestamp}"
        )
    elif alert_type == "quarantine_skipped":
        reason = context.get("reason", "")
        if reason == "auto_quarantine_disabled":
            reason_text = "自动隔离总开关已关闭"
        elif reason == "recently_restored":
            reason_text = "文件刚被恢复，跳过隔离（30秒白名单）"
        else:
            reason_text = reason
        body = (
            "[SKIP] 隔离已跳过\n\n"
            f"文件路径: {context.get('file_path', '?')}\n"
            f"检测引擎: {context.get('engine', '?')}\n"
            f"匹配规则: {', '.join(context.get('features', [])[:5])}\n"
            f"首次发现IP: {_ip_label(context.get('first_seen_ip', ''))}\n"
            f"跳过原因: {reason_text}\n"
            f"时间: {timestamp}"
        )
    else:
        body = context.get("raw_message", f"未知告警类型: {alert_type}")

    types_with_disposition = {
        "local_detection",
        "webshell_access",
        "quarantine_single",
        "quarantine_failed",
        "quarantine_skipped",
    }
    separator = "=============================="
    if alert_type in types_with_disposition:
        disposition = (
            f"\n{separator}\n"
            "[处置状态]\n\n"
            f"{_disposition_quarantine(context)}\n"
            f"{_disposition_block(context)}\n"
            f"{separator}"
        )
    else:
        disposition = ""

    divider = separator if alert_type in types_with_disposition else "-" * 48
    return f"{header}\n{divider}\n{body}{disposition}"
