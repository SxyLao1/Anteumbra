"""Secret redaction helpers for notification transport logs."""

from __future__ import annotations

import re


def mask_secret(value: str, prefix: int = 6, suffix: int = 4) -> str:
    value = str(value or "")
    if len(value) <= prefix + suffix:
        return "***" if value else ""
    return f"{value[:prefix]}...{value[-suffix:]}"


def mask_email(address: str) -> str:
    address = str(address or "")
    if "@" not in address:
        return mask_secret(address, 2, 2)
    local, domain = address.split("@", 1)
    if len(local) <= 2:
        masked_local = local[:1] + "***"
    else:
        masked_local = f"{local[:2]}***{local[-1:]}"
    return f"{masked_local}@{domain}"


def mask_url_secret(url: str) -> str:
    url = str(url or "")
    return re.sub(
        r"/([^/?#]+)(\.send)",
        lambda match: f"/{mask_secret(match.group(1))}{match.group(2)}",
        url,
    )


def sanitize_log_text(value: object) -> str:
    text = str(value or "")
    return re.sub(
        r"https://sctapi\.ftqq\.com/([^/\s]+)\.send",
        lambda match: (
            f"https://sctapi.ftqq.com/{mask_secret(match.group(1))}.send"
        ),
        text,
    )
