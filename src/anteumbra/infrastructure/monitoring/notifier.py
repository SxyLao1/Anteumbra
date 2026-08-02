# -*- coding: utf-8 -*-
"""
@Time: 1/5/2026 5:35 PM
@Auth: SxyLao1
@File: notifier.py
@IDE: PyCharm
@Motto: HACK THE REAL
v1.7.0重构：迁移所有硬编码到config.toml
"""

import json
import logging
import os
import queue
import smtplib
import threading
from datetime import datetime
from typing import Any, Dict, Optional

import requests

from anteumbra.domain.runtime import MetricsPort
from anteumbra.infrastructure.monitoring import notification_transports
from anteumbra.infrastructure.monitoring.notification_formatting import (
    enhance_alert_message,
)
from anteumbra.infrastructure.monitoring.notification_formatting import (
    format_alert_message as _format_alert_message,
)
from anteumbra.infrastructure.monitoring.notification_redaction import (
    mask_email as _redact_email,
)
from anteumbra.infrastructure.monitoring.notification_redaction import (
    mask_secret as _redact_secret,
)
from anteumbra.infrastructure.monitoring.notification_redaction import (
    mask_url_secret as _redact_url_secret,
)
from anteumbra.infrastructure.monitoring.notification_redaction import (
    sanitize_log_text as _redact_log_text,
)
from anteumbra.infrastructure.utils.path_utils import normalize_path

_notifier_logger = logging.getLogger(__name__)

# Preserve the long-standing helper import surface while implementations live
# in focused pure modules.
format_alert_message = _format_alert_message
_mask_email = _redact_email
_mask_secret = _redact_secret
_mask_url_secret = _redact_url_secret
_sanitize_log_text = _redact_log_text


class Notifier:
    """告警通知器：支持邮件、微信、Webhook三渠道"""

    def __init__(
        self,
        config: Dict[str, Any],
        logger: logging.Logger,
        metrics: MetricsPort,
    ):
        self.config = config
        self.logger = logger
        self.metrics = metrics
        self.requested_enabled = bool(config.get("enabled", False))
        self.enabled = False
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
            "webhook": self._init_webhook(),
        }
        self.enabled = self.requested_enabled and any(
            channel["enabled"] for channel in self.channels.values()
        )
        if self.requested_enabled and not self.enabled:
            self.logger.warning(
                "[NOTIFIER] No configured external channel is ready; using local logs only"
            )

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
                    stop_after_batch = False
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
                                stop_after_batch = True
                                break
                            batch.append(item)
                        except queue.Empty:
                            break

                    self._dispatch_batch(batch)
                    if stop_after_batch:
                        break

                except Exception as e:
                    self.logger.critical(f"[ALERT][WORKER] 致命错误: {e}", exc_info=True)
                    break

        self._alert_thread = threading.Thread(target=_worker, daemon=True, name="AlertWorker")
        self._alert_thread.start()
        self.logger.info("[ALERT] 告警工作线程已启动（批量模式）")

    def _dispatch_batch(self, batch: list[tuple[str, str, str | None]]) -> None:
        """Dispatch queued notifications without mixing site ownership."""
        by_site: Dict[str | None, list[tuple[str, str, str | None]]] = {}
        for item in batch:
            by_site.setdefault(item[2], []).append(item)

        for site_id, site_batch in by_site.items():
            self.logger.info(
                "[ALERT][WORKER] processing %d alerts for site=%s",
                len(site_batch),
                site_id or "legacy",
            )
            try:
                if len(site_batch) == 1:
                    message, level, _ = site_batch[0]
                    self.send_alert(
                        message,
                        level=level,
                        site_id=site_id,
                        _already_counted=True,
                    )
                    continue

                levels = {level for _, level, _ in site_batch}
                if len(levels) == 1:
                    level = next(iter(levels))
                    combined = "\n".join(
                        f"[{index + 1}] {message[:200]}"
                        for index, (message, _, _) in enumerate(site_batch)
                    )
                    self.send_alert(
                        f"Batch alerts ({len(site_batch)})\n{combined}",
                        level=level,
                        site_id=site_id,
                        _already_counted=True,
                    )
                    continue

                max_level = max(
                    levels,
                    key=lambda value: {"INFO": 0, "WARNING": 1, "CRITICAL": 2}.get(value, 0),
                )
                messages = [message for message, level, _ in site_batch if level == max_level]
                combined = "\n".join(
                    f"[{index + 1}] {message[:200]}" for index, message in enumerate(messages)
                )
                self.send_alert(
                    f"Batch alerts ({len(site_batch)}, highest={max_level})\n{combined}",
                    level=max_level,
                    site_id=site_id,
                    _already_counted=True,
                )
            except Exception as exc:
                self.logger.error(
                    "[ALERT][WORKER] batch send failed for site=%s: %s",
                    site_id or "legacy",
                    exc,
                    exc_info=True,
                )

    def drain(self):
        """v1.7.9: 主动疏通告警队列——清空队列并全部持久化到磁盘"""
        drained = []
        while True:
            try:
                message, level, site_id = self._alert_queue.get_nowait()
                if message is not None:
                    drained.append((message, level, site_id))
            except queue.Empty:
                break
        if drained:
            self._persist_batch_overflow(drained)
            self.logger.info(f"[ALERT][DRAIN] 主动疏通完成，{len(drained)}条告警已持久化")
        return len(drained)

    def enqueue_alert(
        self,
        message: str,
        level: str = "CRITICAL",
        *,
        site_id: str | None = None,
    ) -> bool:
        """
        Queue an alert for asynchronous delivery.

        - 正常：写入队列
        - 队列积压>100: 丢弃旧告警，保留最新（防止内存爆炸）
        - 溢出：立即持久化到磁盘
        - 异常：双保险持久化
        """
        metrics = self.metrics
        metrics.increment("alert_total", site_id=site_id)
        if not self.enabled:
            metrics.record_notification(
                "skipped",
                "no external channel is configured",
                site_id=site_id,
            )
            self.logger.warning(
                "[NOTIFIER][LOCAL_ONLY][%s] %s",
                level,
                message.splitlines()[0][:500],
            )
            return False

        try:
            # v1.7.9: 队列防积压策略——超过100条时丢弃最旧的50%
            qsize = self._alert_queue.qsize()
            if qsize > 100:
                self._drain_old_alerts(qsize // 2)
                self.logger.warning(f"[ALERT][DRAIN] 队列积压{qsize}条，已丢弃旧告警")

            # 尝试入队（非阻塞）
            self._alert_queue.put_nowait((message, level, site_id))
            self.logger.info(
                "[NOTIFIER][QUEUE] queued alert level=%s size=%s",
                level,
                self._alert_queue.qsize(),
            )
            return True
        except queue.Full:
            # 队列满：立即持久化
            self._persist_overflow(message, level, site_id=site_id)
            self._overflow_count += 1
            self.logger.critical(
                f"[ALERT][OVERFLOW] 队列已满({self._alert_queue.qsize()}), "
                f"已持久化: {message[:50]}..."
            )
            return False
        except Exception as e:
            # 任何异常都触发持久化（最后防线）
            self.logger.error(f"[ALERT][QUEUE] 入队失败: {e}", exc_info=True)
            self._persist_overflow(message, level, site_id=site_id)
            return False

    def _drain_old_alerts(self, count: int):
        """v1.7.9: 丢弃队列中最旧的N条告警（防止积压）"""
        drained = []
        for _ in range(min(count, self._alert_queue.qsize())):
            try:
                message, level, site_id = self._alert_queue.get_nowait()
                if message is not None:
                    drained.append((message, level, site_id))
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
            with open(overflow_file, "a", encoding="utf-8", buffering=1) as f:
                for message, level, site_id in items:
                    f.write(
                        json.dumps(
                            {
                                "timestamp": datetime.now().isoformat(),
                                "level": level,
                                "message": message,
                                "site_id": site_id,
                                "dropped": True,
                            }
                        )
                        + "\n"
                    )
                f.flush()
                os.fsync(f.fileno())
        except Exception as e:
            _notifier_logger.critical(f"[ALERT][FATAL] Batch disk write failed: {e}")

    def _persist_overflow(
        self,
        message: str,
        level: str,
        *,
        site_id: str | None = None,
    ):
        """溢出持久化（内联简化版）"""
        overflow_file = normalize_path("data/alert_overflow.json")
        overflow_file.parent.mkdir(parents=True, exist_ok=True)

        try:
            with open(overflow_file, "a", encoding="utf-8", buffering=1) as f:
                f.write(
                    json.dumps(
                        {
                            "timestamp": datetime.now().isoformat(),
                            "level": level,
                            "message": message,
                            "site_id": site_id,
                        }
                    )
                    + "\n"
                )
                f.flush()
                os.fsync(f.fileno())
        except Exception as e:
            _notifier_logger.critical(f"[ALERT][FATAL] Disk write failed: {e}")

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

        recipients = email_cfg.get("to_addrs", [])
        if isinstance(recipients, str):
            recipients = [recipients]
        requested = bool(email_cfg.get("enabled", False))
        ready = all(
            (
                str(email_cfg.get("smtp_host", "")).strip(),
                str(email_cfg.get("username", "")).strip(),
                str(email_password).strip(),
                str(email_cfg.get("from_addr", "")).strip(),
                any(str(address).strip() for address in recipients),
            )
        )
        if requested and not ready:
            self.logger.warning(
                "[NOTIFIER][EMAIL] Channel disabled because required credentials are incomplete"
            )

        return {
            "enabled": requested and ready,
            "smtp_host": email_cfg.get("smtp_host", ""),
            "smtp_port": email_cfg.get("smtp_port", 587),
            "username": email_cfg.get("username", ""),
            "password": email_password,
            "from_addr": email_cfg.get("from_addr", ""),
            "to_addrs": recipients,
            "use_tls": email_cfg.get("use_tls", True),
            "use_ssl": email_cfg.get("use_ssl", False),
            "timeout": base_timeout,
        }

    def _init_wechat(self) -> Dict[str, Any]:
        """初始化Server酱配置"""
        wechat_cfg = self.config.get("wechat", {})

        # 从配置读取超时和阈值
        base_timeout = wechat_cfg.get("timeout", 10)

        send_key = str(wechat_cfg.get("send_key", "")).strip()
        requested = bool(wechat_cfg.get("enabled", False))
        if requested and not send_key:
            self.logger.warning("[NOTIFIER][WECHAT] Channel disabled because SendKey is missing")
        return {
            "enabled": requested and bool(send_key),
            "send_key": send_key,
            "timeout": base_timeout,
            "channel": wechat_cfg.get("channel", "9"),
            "noip": wechat_cfg.get("noip", False),
            "verify_ssl": wechat_cfg.get("verify_ssl", True),
        }

    def _init_webhook(self) -> Dict[str, Any]:
        """初始化Webhook配置"""
        webhook_cfg = self.config.get("webhook", {})
        url = str(webhook_cfg.get("url", "")).strip()
        requested = bool(webhook_cfg.get("enabled", False))
        if requested and not url:
            self.logger.warning("[NOTIFIER][WEBHOOK] Channel disabled because URL is missing")
        return {
            "enabled": requested and bool(url),
            "url": url,
            "headers": webhook_cfg.get("headers", {}),
            "timeout": webhook_cfg.get("timeout", 10),
        }

    def send_alert(
        self,
        message: str,
        level: str = "CRITICAL",
        analysis: Optional[Dict[str, Any]] = None,
        *,
        _already_counted: bool = False,
        site_id: str | None = None,
    ) -> bool:
        """
        发送告警（主入口）

        Args:
            message: 告警主体消息
            level: 告警级别 INFO/WARNING/CRITICAL
            analysis: 可选的日志分析结果
        """
        metrics = self.metrics
        if not _already_counted:
            metrics.increment("alert_total", site_id=site_id)
        if not self.enabled:
            metrics.record_notification(
                "skipped",
                "no external channel is configured",
                site_id=site_id,
            )
            self.logger.warning(
                "[NOTIFIER][LOCAL_ONLY][%s] %s",
                level,
                message.splitlines()[0][:500],
            )
            return False

        enhanced_message = enhance_alert_message(message, analysis)
        results = {}
        metrics.record_notification("attempted", site_id=site_id)

        if self.channels["wechat"]["enabled"] and self._wechat_circuit_enabled:
            try:
                results["wechat"] = self._send_wechat(enhanced_message, level)
            except Exception as e:
                results["wechat"] = False
                self.logger.error(f"[NOTIFIER][WECHAT] 调用异常: {e}")

        if self.channels["email"]["enabled"]:
            try:
                results["email"] = self._send_email(enhanced_message, level)
            except Exception as e:
                results["email"] = False
                self.logger.error(f"[NOTIFIER][EMAIL] 调用异常: {e}")

        if self.channels["webhook"]["enabled"]:
            try:
                results["webhook"] = self._send_webhook(enhanced_message, level)
            except Exception as e:
                results["webhook"] = False
                self.logger.error(f"[NOTIFIER][WEBHOOK] 调用异常: {e}")

        if not results:
            metrics.record_notification(
                "skipped",
                "all configured channels are unavailable",
                site_id=site_id,
            )
            return False

        successes = sum(bool(value) for value in results.values())
        if successes == len(results):
            metrics.record_notification("success", site_id=site_id)
        elif successes:
            metrics.record_notification(
                "partial",
                "one or more notification channels failed",
                site_id=site_id,
            )
        else:
            metrics.record_notification(
                "failed",
                "all notification channels failed",
                site_id=site_id,
            )

        # 日志输出必须在所有通道尝试后，避免重复
        # 提取核心消息（第一行）用于日志，保持日志简洁
        core_message = enhanced_message.split("\n")[0].strip()
        self.logger.critical(f"[NOTIFIER][ALERT][{level}] {core_message}")
        return successes > 0

    def _send_email(self, message: str, level: str) -> bool:
        return notification_transports.send_email(
            self.channels["email"],
            message,
            level,
            self.logger,
            smtp_module=smtplib,
        )

    def _send_wechat(self, message: str, level: str) -> bool:
        if not self._wechat_circuit_enabled:
            self.logger.warning("[NOTIFIER][WECHAT] 熔断中，跳过发送")
            return False

        config = self.channels["wechat"]
        if not config["send_key"]:
            return notification_transports.send_serverchan(
                config,
                message,
                level,
                self.logger,
                requests_module=requests,
                os_module=os,
            )

        success = notification_transports.send_serverchan(
            config,
            message,
            level,
            self.logger,
            requests_module=requests,
            os_module=os,
        )
        if success:
            self._wechat_failure_count = 0
            return True

        self._wechat_failure_count += 1
        if self._wechat_failure_count >= self._circuit_threshold:
            self._wechat_circuit_enabled = False
            self.logger.critical("[NOTIFIER][WECHAT] 熔断器触发，降级为仅邮件")
            fallback_message = f"微信推送熔断已触发！失败次数: {self._wechat_failure_count}"
            try:
                self._send_email(fallback_message, "CRITICAL")
            except Exception as exc:
                self.logger.critical(f"[NOTIFIER][FUSE] 邮件通知也失败: {exc}")
        return False

    def _send_webhook(self, message: str, level: str) -> bool:
        return notification_transports.send_webhook(
            self.channels["webhook"],
            message,
            level,
            self.logger,
            requests_module=requests,
        )

    def _stop_alert_worker(self):
        """停止告警工作线程"""
        if self._alert_thread and self._alert_thread.is_alive():
            # 发送退出信号
            try:
                self._alert_queue.put_nowait((None, None, None))  # None作为退出信号
            except queue.Full:
                pass

            # 等待线程退出（最大5秒）
            self._alert_thread.join(timeout=5.0)

            if self._alert_thread.is_alive():
                self.logger.warning("[NOTIFIER] 工作线程未能正常退出")
            else:
                self.logger.info("[NOTIFIER] 工作线程已停止")

    def shutdown(self) -> None:
        """Release the notifier worker owned by the application runtime."""
        self._stop_alert_worker()
