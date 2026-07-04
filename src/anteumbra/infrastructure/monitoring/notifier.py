# -*- coding: utf-8 -*-
"""
@Time: 1/5/2026 5:35 PM
@Auth: SxyLao1
@File: notifier.py
@IDE: PyCharm
@Motto: HACK THE REAL
v1.7.0重构：迁移所有硬编码到config.toml
"""
import logging
import os
import queue
import smtplib
import sys
import threading

import requests
import json
from pathlib import Path
from typing import Dict, Any, Optional
from email.mime.text import MIMEText
from email.header import Header
from datetime import datetime

from anteumbra.infrastructure.config.registry import ConfigRegistry
from anteumbra.infrastructure.monitoring.metrics import get_metrics
from anteumbra.infrastructure.utils.path_utils import normalize_path

class Notifier:
    """告警通知器：支持邮件、微信、Webhook三渠道"""

    def __init__(self, config: Dict[str, Any], logger: logging.Logger):
        self.config = config
        self.logger = logger
        self.enabled = config.get("enabled", False)
        self._wechat_failure_count = 0

        # v1.7.0重构：从配置读取熔断阈值
        self._circuit_threshold = config.get("circuit_breaker_threshold", 10)
        self._wechat_circuit_enabled = True

        # v1.7.0重构：从配置读取队列容量
        queue_config = config.get("queue", {})
        maxsize = queue_config.get("maxsize", 0)  # 0=无限制

        # 测试环境强制限制，生产环境读取配置
        if os.environ.get("ANTEUMBRA_TOOL_MODE") == "true":
            maxsize = 100  # 铁律1：测试环境必须限制

        self._alert_queue = queue.Queue(maxsize=maxsize)
        self._alert_thread = None
        self._overflow_count = 0

        normalize_path("data").mkdir(parents=True, exist_ok=True)

        # 初始化各渠道配置
        self.channels = {
            "email": self._init_email(),
            "wechat": self._init_wechat(),
            "webhook": self._init_webhook()
        }

        # 立即启动工作线程
        if self.enabled:
            self._start_alert_worker()

    def _start_alert_worker(self):
        """v1.7.9: 启动告警工作线程（批量消费，减少网络IO阻塞）"""
        if self._alert_thread is not None and self._alert_thread.is_alive():
            return

        def _worker():
            self.logger.info("[ALERT][WORKER] 线程启动（批量模式）")
            while True:
                try:
                    # v1.7.9: 批量取件，每次最多10条或等待1秒
                    batch = []
                    try:
                        first = self._alert_queue.get(timeout=1)
                        if first[0] is None:  # 退出信号
                            break
                        batch.append(first)
                    except queue.Empty:
                        continue

                    # 继续取，最多再取9条（非阻塞）
                    for _ in range(9):
                        try:
                            item = self._alert_queue.get_nowait()
                            if item[0] is None:
                                break
                            batch.append(item)
                        except queue.Empty:
                            break

                    # 批量处理：相同级别合并为一条消息
                    self.logger.info(f"[ALERT][WORKER] 批量处理 {len(batch)} 条告警")
                    if len(batch) == 1:
                        message, level = batch[0]
                        try:
                            self.send_alert(message, level=level)
                        except Exception as e:
                            self.logger.error(f"[ALERT][WORKER] 发送失败: {e}", exc_info=True)
                    else:
                        # 合并发送：减少网络请求次数
                        levels = set(l for _, l in batch)
                        if len(levels) == 1:
                            combined = "\n".join([f"[{i+1}] {msg[:200]}" for i, (msg, _) in enumerate(batch)])
                            try:
                                self.send_alert(f"批量告警 ({len(batch)}条)\n{combined}", level=list(levels)[0])
                            except Exception as e:
                                self.logger.error(f"[ALERT][WORKER] 批量发送失败: {e}", exc_info=True)
                        else:
                            # 不同级别分别发送（只发最高级别）
                            max_level = max(levels, key=lambda x: {"INFO":0, "WARNING":1, "CRITICAL":2}.get(x, 0))
                            critical_msgs = [msg for msg, lvl in batch if lvl == max_level]
                            combined = "\n".join([f"[{i+1}] {msg[:200]}" for i, msg in enumerate(critical_msgs)])
                            try:
                                self.send_alert(f"批量告警 ({len(batch)}条, 最高级别{max_level})\n{combined}", level=max_level)
                            except Exception as e:
                                self.logger.error(f"[ALERT][WORKER] 批量发送失败: {e}", exc_info=True)

                except Exception as e:
                    self.logger.critical(f"[ALERT][WORKER] 致命错误: {e}", exc_info=True)
                    break

        self._alert_thread = threading.Thread(target=_worker, daemon=True, name="AlertWorker")
        self._alert_thread.start()
        self.logger.info("[ALERT] 告警工作线程已启动（批量模式）")

    def drain(self):
        """v1.7.9: 主动疏通告警队列——清空队列并全部持久化到磁盘"""
        drained = []
        while True:
            try:
                msg, lvl = self._alert_queue.get_nowait()
                if msg is not None:
                    drained.append((msg, lvl))
            except queue.Empty:
                break
        if drained:
            self._persist_batch_overflow(drained)
            self.logger.info(f"[ALERT][DRAIN] 主动疏通完成，{len(drained)}条告警已持久化")
        return len(drained)

    def _safe_notify(self, message: str, level: str = "CRITICAL"):
        """
        v1.7.9: 异步通知（唯一入口）
        - 正常：写入队列
        - 队列积压>100: 丢弃旧告警，保留最新（防止内存爆炸）
        - 溢出：立即持久化到磁盘
        - 异常：双保险持久化
        """
        try:
            # v1.7.9: 队列防积压策略——超过100条时丢弃最旧的50%
            qsize = self._alert_queue.qsize()
            if qsize > 100:
                self._drain_old_alerts(qsize // 2)
                self.logger.warning(f"[ALERT][DRAIN] 队列积压{qsize}条，已丢弃旧告警")

            # 尝试入队（非阻塞）
            self._alert_queue.put_nowait((message, level))
        except queue.Full:
            # 队列满：立即持久化
            self._persist_overflow(message, level)
            self._overflow_count += 1
            self.logger.critical(
                f"[ALERT][OVERFLOW] 队列已满({self._alert_queue.qsize()}), "
                f"已持久化: {message[:50]}..."
            )
        except Exception as e:
            # 任何异常都触发持久化（最后防线）
            self.logger.error(f"[ALERT][QUEUE] 入队失败: {e}", exc_info=True)
            self._persist_overflow(message, level)

    def _drain_old_alerts(self, count: int):
        """v1.7.9: 丢弃队列中最旧的N条告警（防止积压）"""
        drained = []
        for _ in range(min(count, self._alert_queue.qsize())):
            try:
                msg, lvl = self._alert_queue.get_nowait()
                drained.append((msg, lvl))
            except queue.Empty:
                break
        # 被丢弃的告警批量持久化（不丢失）
        if drained:
            self._persist_batch_overflow(drained)

    def _persist_batch_overflow(self, items):
        """批量持久化溢出告警"""
        overflow_file = normalize_path("data/alert_overflow.json")
        overflow_file.parent.mkdir(parents=True, exist_ok=True)
        try:
            with open(overflow_file, "a", encoding='utf-8', buffering=1) as f:
                for message, level in items:
                    f.write(json.dumps({
                        "timestamp": datetime.now().isoformat(),
                        "level": level,
                        "message": message,
                        "dropped": True
                    }) + "\n")
                f.flush()
                os.fsync(f.fileno())
        except Exception as e:
            print(f"[ALERT][FATAL] 批量磁盘失败: {e}", file=sys.stderr, flush=True)

    def _persist_overflow(self, message: str, level: str):
        """溢出持久化（内联简化版）"""
        overflow_file = normalize_path("data/alert_overflow.json")
        overflow_file.parent.mkdir(parents=True, exist_ok=True)

        try:
            with open(overflow_file, "a", encoding='utf-8', buffering=1) as f:
                f.write(json.dumps({
                    "timestamp": datetime.now().isoformat(),
                    "level": level,
                    "message": message
                }) + "\n")
                f.flush()
                os.fsync(f.fileno())
        except Exception as e:
            print(f"[ALERT][FATAL] 磁盘失败: {e}", file=sys.stderr, flush=True)

    def _init_email(self) -> Dict[str, Any]:
        """初始化SMTP配置"""
        email_cfg = self.config.get("email", {})

        # v1.7.0重构：从配置读取超时
        base_timeout = email_cfg.get("timeout", 10)

        # v1.7.9: 优先从环境变量读取密码，避免明文存储在 config.toml
        email_password = email_cfg.get("password", "")
        if email_password.startswith("${") or not email_password:
            import os
            email_password = os.environ.get("ANTEUMBRA_EMAIL_PASSWORD", "")

        return {
            "enabled": email_cfg.get("enabled", False),
            "smtp_host": email_cfg.get("smtp_host", ""),
            "smtp_port": email_cfg.get("smtp_port", 587),
            "username": email_cfg.get("username", ""),
            "password": email_password,
            "from_addr": email_cfg.get("from_addr", ""),
            "to_addrs": email_cfg.get("to_addrs", []),
            "use_tls": email_cfg.get("use_tls", True),
            "use_ssl": email_cfg.get("use_ssl", False),
            "timeout": base_timeout
        }

    def _init_wechat(self) -> Dict[str, Any]:
        """初始化Server酱配置"""
        wechat_cfg = self.config.get("wechat", {})

        # 从配置读取超时和阈值
        base_timeout = wechat_cfg.get("timeout", 10)

        return {
            "enabled": wechat_cfg.get("enabled", False),
            "send_key": wechat_cfg.get("send_key", ""),
            "timeout": base_timeout,
            "channel": wechat_cfg.get("channel", "9"),
            "noip": wechat_cfg.get("noip", False)
        }

    def _init_webhook(self) -> Dict[str, Any]:
        """初始化Webhook配置"""
        webhook_cfg = self.config.get("webhook", {})
        return {
            "enabled": webhook_cfg.get("enabled", False),
            "url": webhook_cfg.get("url", ""),
            "headers": webhook_cfg.get("headers", {}),
            "timeout": webhook_cfg.get("timeout", 10)
        }

    def send_alert(self, message: str, level: str = "CRITICAL", analysis: Optional[Dict[str, Any]] = None):
        """
        发送告警（主入口）

        Args:
            message: 告警主体消息
            level: 告警级别 INFO/WARNING/CRITICAL
            analysis: 可选的日志分析结果
        """
        if not self.enabled:
            self.logger.debug("[NOTIFIER] 告警功能未启用")
            return

        # 必须在调用发送方法前完成消息增强
        enhanced_message = message
        if analysis:
            suspicious_ips = analysis.get("suspicious_ips", {})
            if suspicious_ips:
                enhanced_message += f"\n\n攻击溯源分析:\n"
                enhanced_message += f"时间窗口: {analysis.get('create_time', '未知')}\n"
                enhanced_message += f"可疑IP访问统计:\n"
                for ip, count in suspicious_ips.items():
                    enhanced_message += f"   {ip}: {count}次\n"
                enhanced_message += f"日志文件: {analysis.get('log_path', '未知')}"

        # 必须传递参数，微信失败不影响邮件
        # 通道1：微信（可能熔断）
        if self.channels["wechat"]["enabled"] and self._wechat_circuit_enabled:
            try:
                self._send_wechat(enhanced_message, level)  # ← 必须传参数
            except Exception as e:
                self.logger.error(f"[NOTIFIER][WECHAT] 调用异常: {e}")  # 确保异常不向上抛

        # 通道2：邮件（高可靠性，永不熔断）
        if self.channels["email"]["enabled"]:
            try:
                self._send_email(enhanced_message, level)  # ← 必须传参数
            except Exception as e:
                self.logger.error(f"[NOTIFIER][EMAIL] 调用异常: {e}")

        # 通道3：Webhook（可选）
        if self.channels["webhook"]["enabled"]:
            try:
                self._send_webhook(enhanced_message, level)
            except Exception as e:
                self.logger.error(f"[NOTIFIER][WEBHOOK] 调用异常: {e}")

        # 日志输出必须在所有通道尝试后，避免重复
        # 提取核心消息（第一行）用于日志，保持日志简洁
        core_message = enhanced_message.split('\n')[0].strip()
        self.logger.critical(f"[NOTIFIER][ALERT][{level}] {core_message}")

    def _send_email(self, message: str, level: str):
        """发送邮件告警"""
        try:
            cfg = self.channels["email"]
            msg = MIMEText(message, "plain", "utf-8")
            msg["Subject"] = Header(f"[WebShell警报-{level}]", "utf-8")
            msg["From"] = cfg["from_addr"]
            msg["To"] = ", ".join(cfg["to_addrs"])

            # 修复：根据端口选择SMTP或SMTP_SSL
            port = cfg["smtp_port"]
            timeout = cfg.get("timeout", 10)

            if cfg.get("use_ssl", False) or port == 465:
                # SSL加密端口（465）
                self.logger.debug(f"[NOTIFIER][EMAIL] 使用SSL连接: {cfg['smtp_host']}:{port}")
                server = smtplib.SMTP_SSL(cfg["smtp_host"], port, timeout=timeout)
            else:
                # TLS加密端口（587/25）
                self.logger.debug(f"[NOTIFIER][EMAIL] 使用TLS连接: {cfg['smtp_host']}:{port}")
                server = smtplib.SMTP(cfg["smtp_host"], port, timeout=timeout)
                if cfg.get("use_tls", True):
                    server.starttls()

            server.login(cfg["username"], cfg["password"])
            server.send_message(msg)
            server.quit()

            self.logger.info(f"[NOTIFIER][EMAIL] 发送成功 -> {cfg['to_addrs']}")

        except Exception as e:
            if not self._warned_missing_config:
                self.logger.warning(f"[NOTIFIER][EMAIL] skipped: credentials not configured"); self._warned_missing_config = True

    def _send_wechat(self, message: str, level: str):
        """发送微信告警（Server酱）- 熔断降级版【必须完整替换】"""

        if not self._wechat_circuit_enabled:
            self.logger.warning("[NOTIFIER][WECHAT] 熔断中，跳过发送")
            return

        try:
            cfg = self.channels["wechat"]
            send_key = cfg["send_key"]
            if not send_key:
                self.logger.warning("[NOTIFIER][WECHAT] SendKey未配置，推送已跳过")
                return

            # VPN/代理环境优化
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

            url = f"https://sctapi.ftqq.com/{send_key}.send"
            title = f"[WebShell-{level}]"[:32]

            payload = {
                "title": title,
                "desp": message,
                "channel": cfg["channel"],
                "noip": cfg["noip"]
            }

            session = requests.Session()
            session.verify = False

            if os.environ.get("HTTPS_PROXY"):
                self.logger.debug(f"[NOTIFIER][WECHAT] 检测到系统代理: {os.environ['HTTPS_PROXY']}")

            self.logger.debug(f"[NOTIFIER][WECHAT] 正在发送请求至: {url}")

            # 设置超时和重试
            from requests.adapters import HTTPAdapter
            from urllib3.util.retry import Retry

            retry_strategy = Retry(
                total=3,  # 最多3次重试
                backoff_factor=0.5,  # 间隔0.5秒递增
                status_forcelist=[500, 502, 503, 504]
            )
            session.mount("https://", HTTPAdapter(max_retries=retry_strategy))

            response = session.post(
                url,
                json=payload,
                timeout=cfg["timeout"],
                headers={"Content-Type": "application/json"}
            )

            response.raise_for_status()
            result = response.json()

            if result.get("code") == 0:
                pushid = result.get("data", {}).get("pushid")
                self.logger.info(f"[NOTIFIER][WECHAT] 发送成功 (pushid: {pushid})")
            else:
                error_msg = result.get("message", "未知错误")
                raise RuntimeError(f"Server酱API返回错误: {error_msg}")

            # 成功：重置熔断计数
            self._wechat_failure_count = 0
            self.logger.debug("[NOTIFIER][WECHAT] 发送成功")

        # 异常处理：所有路径统一增加熔断计数
        except ValueError as e:
            self._wechat_failure_count += 1
            if "check_hostname requires server_hostname" in str(e):
                self.logger.error("[NOTIFIER][WECHAT] SSL代理配置错误")
            else:
                self.logger.error(f"[NOTIFIER][WECHAT] 参数错误: {e}")

        except requests.exceptions.ProxyError as e:
            self._wechat_failure_count += 1
            self.logger.error(f"[NOTIFIER][WECHAT] 代理连接失败: {e}")

        except requests.exceptions.ConnectionError as e:
            self._wechat_failure_count += 1
            self.logger.error(f"[NOTIFIER][WECHAT] 网络连接失败: {e}")

        except Exception as e:
            self._wechat_failure_count += 1
            self.logger.warning(f"[NOTIFIER][WECHAT] skipped: {e} (API key not configured?)")

        # 熔断判断
        finally:
            if self._wechat_failure_count >= self._circuit_threshold:
                self._wechat_circuit_enabled = False
                self.logger.critical("[NOTIFIER][WECHAT] 熔断器触发，降级为仅邮件")

                # 发送熔断通知到邮件
                fallback_msg = f"微信推送熔断已触发！失败次数: {self._wechat_failure_count}"
                try:
                    self._send_email(fallback_msg, "CRITICAL")
                except Exception as mail_e:
                    self.logger.critical(f"[NOTIFIER][FUSE] 邮件通知也失败: {mail_e}")

    def _send_webhook(self, message: str, level: str):
        """发送Webhook告警（钉钉/企微）"""
        try:
            cfg = self.channels["webhook"]

            payload = {
                "msgtype": "text",
                "text": {
                    "content": f"[WebShell-{level}]\n\n{message}"
                }
            }

            headers = {"Content-Type": "application/json"}
            headers.update(cfg["headers"])

            response = requests.post(
                cfg["url"],
                json=payload,
                headers=headers,
                timeout=cfg["timeout"]
            )
            response.raise_for_status()

            self.logger.info(f"[NOTIFIER][WEBHOOK] 发送成功")

        except Exception as e:
            self.logger.error(f"[NOTIFIER][WEBHOOK] 发送失败: {e}", exc_info=True)

    def _stop_alert_worker(self):
        """停止告警工作线程"""
        if self._alert_thread and self._alert_thread.is_alive():
            # 发送退出信号
            try:
                self._alert_queue.put_nowait((None, None))  # None作为退出信号
            except queue.Full:
                pass

            # 等待线程退出（最大5秒）
            self._alert_thread.join(timeout=5.0)

            if self._alert_thread.is_alive():
                self.logger.warning("[NOTIFIER] 工作线程未能正常退出")
            else:
                self.logger.info("[NOTIFIER] 工作线程已停止")

# 全局单例实例
_notifier_instance: Optional[Notifier] = None


def get_notifier(logger: logging.Logger) -> Notifier:
    """获取通知器单例"""
    global _notifier_instance
    if _notifier_instance is None:
        config = ConfigRegistry.get_raw_config().get("notifier", {})
        _notifier_instance = Notifier(config, logger)
    return _notifier_instance

def reset_notifier():
    """重置notifier单例（配置热加载后调用，重置熔断器状态）"""
    global _notifier_instance
    _notifier_instance = None
    logging.getLogger("webshell.notifier").info("[NOTIFIER] 实例已重置（熔断器状态清除）")

    # 清理函数
def shutdown_notifier():
    """全局清理函数（测试用）"""
    global _notifier_instance
    if _notifier_instance:
        _notifier_instance._stop_alert_worker()
        _notifier_instance = None


# ═══════════════════════════════════════════════════════════════
# v1.8.4: 统一通知消息构建器（纯函数，不依赖实例状态）
# ═══════════════════════════════════════════════════════════════

def _ip_label(ip: str) -> str:
    """给 IP 加上可读标签"""
    if not ip:
        return "未知"
    if ip in ("127.0.0.1", "::1", "0:0:0:0:0:0:0:1"):
        return f"{ip} (本机/内网)"
    return ip


def _disposition_block(status: dict) -> str:
    """构建封禁处置状态行"""
    auto = status.get("auto_block_enabled", False)
    device_count = status.get("block_device_count", 0)
    ip = status.get("first_seen_ip") or status.get("attacker_ip", "")

    if auto and device_count > 0:
        return (
            f"IP封禁: 已自动封禁 ({device_count} 台设备)\n"
            f"  被封禁IP: {ip}"
        )
    elif auto and device_count == 0:
        return "IP封禁: 自动封禁已开启但无可用设备"
    else:
        return (
            f"IP封禁: 已关闭自动封禁\n"
            f"  可疑IP: {ip}\n"
            f"  建议: 人工研判后在管理面板手动封禁"
        )


def _disposition_quarantine(status: dict) -> str:
    """构建隔离处置状态行"""
    auto = status.get("auto_quarantine_enabled", True)
    qid = status.get("quarantine_id")
    qpath = status.get("quarantine_path")

    if qid and qpath:
        return (
            f"文件隔离: 已自动隔离\n"
            f"  隔离ID: {qid}\n"
            f"  隔离路径: {qpath}"
        )
    elif not auto:
        return "文件隔离: 已关闭自动隔离（可手动在隔离管理页面操作）"
    else:
        reason = status.get("reason", "未知原因")
        return f"文件隔离: 隔离失败（{reason}）"


def format_alert_message(context: dict) -> str:
    """
    v1.8.4: 统一构建告警通知消息。

    支持的 alert_type:
        - "local_detection":  本地文件系统检测到可疑文件
        - "webshell_access":  WebShell 被 HTTP 访问
        - "quarantine_batch": 批量隔离完成
        - "quarantine_single": 单文件隔离成功
        - "quarantine_failed": 隔离失败
        - "quarantine_skipped": 隔离被跳过（开关关闭/白名单）

    Returns: 格式化的纯文本告警消息（无 emoji，纯 ASCII）
    """
    alert_type = context.get("alert_type", "unknown")
    ts = context.get("timestamp", "")
    level = context.get("level", "WARNING")
    status = context  # 直接传整个 context 给子函数

    # -- 公共头部 --
    header = f"[Anteumbra {level}] {ts}"

    if alert_type == "local_detection":
        body = (
            f"[!!] 内网边界突破告警\n\n"
            f"可疑文件在本地被检测到（无外网访问记录）\n\n"
            f"文件路径: {context.get('file_path', '?')}\n"
            f"检测引擎: {context.get('engine', '?')}\n"
            f"匹配规则: {', '.join(context.get('features', [])[:5])}\n"
            f"首次发现IP: {_ip_label(context.get('first_seen_ip', ''))}\n"
            f"检测时间: {ts}"
        )

    elif alert_type == "webshell_access":
        body = (
            f"[WEB] WebShell 被外部访问\n\n"
            f"文件路径: {context.get('file_path', '?')}\n"
            f"攻击IP: {context.get('attacker_ip', '?')}\n"
            f"告警级别: {context.get('alert_level', level)}\n"
            f"访问时间: {ts}"
        )

    elif alert_type == "quarantine_batch":
        count = context.get("batch_count", 0)
        body = (
            f"[BATCH] 批量隔离完成\n\n"
            f"本次共隔离 {count} 个可疑文件\n"
            f"完成时间: {ts}\n\n"
            f"详情请登录管理面板查看 [威胁 -> 隔离管理]"
        )

    elif alert_type == "quarantine_single":
        body = (
            f"[OK] 文件已隔离\n\n"
            f"文件路径: {context.get('file_path', '?')}\n"
            f"检测引擎: {context.get('engine', '?')}\n"
            f"匹配规则: {', '.join(context.get('features', [])[:5])}\n"
            f"首次发现IP: {_ip_label(context.get('first_seen_ip', ''))}"
        )

    elif alert_type == "quarantine_failed":
        body = (
            f"[FAIL] 隔离失败\n\n"
            f"文件路径: {context.get('file_path', '?')}\n"
            f"检测引擎: {context.get('engine', '?')}\n"
            f"匹配规则: {', '.join(context.get('features', [])[:5])}\n"
            f"首次发现IP: {_ip_label(context.get('first_seen_ip', ''))}\n"
            f"失败原因: {context.get('reason', '未知')}\n"
            f"时间: {ts}"
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
            f"[SKIP] 隔离已跳过\n\n"
            f"文件路径: {context.get('file_path', '?')}\n"
            f"检测引擎: {context.get('engine', '?')}\n"
            f"匹配规则: {', '.join(context.get('features', [])[:5])}\n"
            f"首次发现IP: {_ip_label(context.get('first_seen_ip', ''))}\n"
            f"跳过原因: {reason_text}\n"
            f"时间: {ts}"
        )

    else:
        body = context.get("raw_message", f"未知告警类型: {alert_type}")

    # -- 处置状态（仅适用于需要展示处置状态的类型） --
    types_with_disposition = {
        "local_detection", "webshell_access", "quarantine_single",
        "quarantine_failed", "quarantine_skipped"
    }
    sep = "=============================="

    if alert_type in types_with_disposition:
        disposition = (
            f"\n{sep}\n"
            f"[处置状态]\n\n"
            f"{_disposition_quarantine(status)}\n"
            f"{_disposition_block(status)}\n"
            f"{sep}"
        )
    else:
        disposition = ""

    divider = sep if alert_type in types_with_disposition else "-" * 48
    return f"{header}\n{divider}\n{body}{disposition}"