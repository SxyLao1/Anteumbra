"""Protocol-specific notification transports."""

from __future__ import annotations

from email.header import Header
from email.mime.text import MIMEText
from types import ModuleType

from anteumbra.infrastructure.monitoring.notification_redaction import (
    mask_email,
    mask_url_secret,
    sanitize_log_text,
)


def send_email(
    config: dict,
    message: str,
    level: str,
    logger,
    *,
    smtp_module: ModuleType,
) -> bool:
    """Deliver one alert through SMTP or SMTP-over-SSL."""
    try:
        email = MIMEText(message, "plain", "utf-8")
        email["Subject"] = Header(f"[WebShell警报-{level}]", "utf-8")
        email["From"] = config["from_addr"]
        email["To"] = ", ".join(config["to_addrs"])

        port = config["smtp_port"]
        timeout = config.get("timeout", 10)
        if config.get("use_ssl", False) or port == 465:
            logger.debug(
                "[NOTIFIER][EMAIL] 使用SSL连接: %s:%s",
                config["smtp_host"],
                port,
            )
            server = smtp_module.SMTP_SSL(
                config["smtp_host"], port, timeout=timeout
            )
        else:
            logger.debug(
                "[NOTIFIER][EMAIL] 使用TLS连接: %s:%s",
                config["smtp_host"],
                port,
            )
            server = smtp_module.SMTP(config["smtp_host"], port, timeout=timeout)
            if config.get("use_tls", True):
                server.starttls()

        server.login(config["username"], config["password"])
        server.send_message(email)
        server.quit()

        recipients = [mask_email(address) for address in config["to_addrs"]]
        logger.info("[NOTIFIER][EMAIL] 发送成功 -> %s", recipients)
        return True
    except Exception as exc:
        logger.error("[NOTIFIER][EMAIL] send failed: %s", exc, exc_info=True)
        return False


def send_serverchan(
    config: dict,
    message: str,
    level: str,
    logger,
    *,
    requests_module: ModuleType,
    os_module: ModuleType,
) -> bool:
    """Deliver one alert through the ServerChan HTTP API."""
    send_key = config["send_key"]
    if not send_key:
        logger.warning("[NOTIFIER][WECHAT] SendKey未配置，推送已跳过")
        return False

    try:
        import urllib3
        from requests.adapters import HTTPAdapter
        from urllib3.util.retry import Retry

        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        url = f"https://sctapi.ftqq.com/{send_key}.send"
        payload = {
            "title": f"[WebShell-{level}]"[:32],
            "desp": message,
            "channel": config["channel"],
            "noip": config["noip"],
        }

        session = requests_module.Session()
        session.verify = bool(config.get("verify_ssl", True))
        if os_module.environ.get("HTTPS_PROXY"):
            logger.debug(
                "[NOTIFIER][WECHAT] 检测到系统代理: %s",
                mask_url_secret(os_module.environ["HTTPS_PROXY"]),
            )
        logger.debug(
            "[NOTIFIER][WECHAT] 正在发送请求至: %s", mask_url_secret(url)
        )

        retry_strategy = Retry(
            total=3,
            backoff_factor=0.5,
            status_forcelist=[500, 502, 503, 504],
        )
        session.mount("https://", HTTPAdapter(max_retries=retry_strategy))
        response = session.post(
            url,
            json=payload,
            timeout=config["timeout"],
            headers={"Content-Type": "application/json"},
        )
        response.raise_for_status()
        result = response.json()
        if result.get("code") != 0:
            raise RuntimeError(
                f"Server酱API返回错误: {result.get('message', '未知错误')}"
            )

        push_id = result.get("data", {}).get("pushid")
        logger.info("[NOTIFIER][WECHAT] 发送成功 (pushid: %s)", push_id)
        logger.debug("[NOTIFIER][WECHAT] 发送成功")
        return True
    except ValueError as exc:
        if "check_hostname requires server_hostname" in str(exc):
            logger.error("[NOTIFIER][WECHAT] SSL代理配置错误")
        else:
            logger.error(
                "[NOTIFIER][WECHAT] 参数错误: %s", sanitize_log_text(exc)
            )
    except requests_module.exceptions.ProxyError as exc:
        logger.error(
            "[NOTIFIER][WECHAT] 代理连接失败: %s", sanitize_log_text(exc)
        )
    except requests_module.exceptions.ConnectionError as exc:
        logger.error(
            "[NOTIFIER][WECHAT] 网络连接失败: %s", sanitize_log_text(exc)
        )
    except Exception as exc:
        logger.error("[NOTIFIER][WECHAT] send failed: %s", sanitize_log_text(exc))
    return False


def send_webhook(
    config: dict,
    message: str,
    level: str,
    logger,
    *,
    requests_module: ModuleType,
) -> bool:
    """Deliver one alert through a generic text webhook."""
    try:
        payload = {
            "msgtype": "text",
            "text": {"content": f"[WebShell-{level}]\n\n{message}"},
        }
        headers = {"Content-Type": "application/json"}
        headers.update(config["headers"])
        response = requests_module.post(
            config["url"],
            json=payload,
            headers=headers,
            timeout=config["timeout"],
        )
        response.raise_for_status()
        logger.info("[NOTIFIER][WEBHOOK] 发送成功")
        return True
    except Exception as exc:
        logger.error("[NOTIFIER][WEBHOOK] 发送失败: %s", exc, exc_info=True)
        return False
