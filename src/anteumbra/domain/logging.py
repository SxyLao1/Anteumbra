"""Configuration-free logging helpers shared across runtime layers."""

from __future__ import annotations

import logging
from collections.abc import Mapping
from types import MappingProxyType
from typing import Any

DEFAULT_SYMBOLS: Mapping[str, str] = MappingProxyType({
    "success": "[MONITOR][START][SUCCESS]",
    "critical_start": "[MONITOR][START][CRITICAL]",
    "create_dir": "[MONITOR][CREATE][DIR]",
    "create_file": "[MONITOR][CREATE][FILE]",
    "create_wait": "[MONITOR][CREATE][WAIT]",
    "create_skip": "[MONITOR][CREATE][SKIP]",
    "create_error": "[MONITOR][CREATE][ERROR]",
    "delete_dir": "[MONITOR][DELETE][DIR]",
    "delete_file": "[MONITOR][DELETE][FILE]",
    "modify": "[MONITOR][MODIFY][FILE]",
    "close": "[MONITOR][CLOSE][FILE]",
    "move_file": "[MONITOR][MOVE][FILE]",
    "move_dir": "[MONITOR][MOVE][DIR]",
    "skip_duplicate": "[MONITOR][SKIP][DUPLICATE]",
    "skip_exclude": "[MONITOR][SKIP][EXCLUDE]",
    "skip_size": "[MONITOR][SKIP][SIZE_LIMIT]",
    "warning_permission": "[MONITOR][PERMISSION][WARNING]",
    "critical_permission": "[MONITOR][PERMISSION][CRITICAL]",
    "error_dir_cache": "[MONITOR][ERROR][CACHE]",
    "scan_hit": "[SCAN][FILE][HIT]",
    "scan_safe": "[SCAN][FILE][SAFE]",
    "scan_queue_full": "[SCAN][QUEUE][WARNING]",
    "error_scan": "[SCAN][ERROR]",
    "error_scan_fail": "[SCAN][CHAIN][ERROR]",
    "quarantine_add": "[QUARANTINE][ADD][SUCCESS]",
    "registry_add": "[REGISTRY][ADD][SUCCESS]",
    "registry_remove": "[REGISTRY][REMOVE][SUCCESS]",
    "notice": "[REGISTRY][NOTICE][INFO]",
    "warning_wal_fail": "[REGISTRY][WAL][WARNING]",
    "error_registry_save": "[REGISTRY][SAVE][ERROR]",
    "log_monitor_start": "[LOG_MONITOR][START][SUCCESS]",
    "log_monitor_start_error": "[LOG_MONITOR][START][ERROR]",
    "log_monitor_info": "[LOG_MONITOR][INFO]",
    "log_monitor_stop": "[LOG_MONITOR][STOP][INFO]",
    "log_monitor_skip": "[LOG_MONITOR][SKIP][INFO]",
    "log_monitor_skip_duplicate": "[LOG_MONITOR][SKIP][DUPLICATE]",
    "log_monitor_error": "[LOG_MONITOR][ERROR]",
    "log_monitor_warning": "[LOG_MONITOR][WARNING]",
    "notifier_init": "[NOTIFIER][INIT][SUCCESS]",
    "error_notifier_email": "[NOTIFIER][EMAIL][ERROR]",
    "warning_config_reload": "[CONFIG][RELOAD][WARNING]",
    "yara_list": "[YARA][LIST][INFO]",
    "yara_upload": "[YARA][UPLOAD][SUCCESS]",
    "yara_update": "[YARA][UPDATE][SUCCESS]",
    "yara_delete": "[YARA][DELETE][SUCCESS]",
    "yara_validate": "[YARA][VALIDATE][INFO]",
    "yara_error": "[YARA][ERROR][FAIL]",
    "debug_exclude": "[DEBUG][EXCLUDE][INFO]",
    "debug_scan": "[DEBUG][SCAN][INFO]",
    "warning": "[GENERAL][WARNING]",
    "error": "[GENERAL][ERROR]",
    "info": "[GENERAL][INFO]",
})


def log_with_symbol(
    symbol_key: str,
    level: str,
    message: str,
    logger: logging.Logger,
) -> None:
    """Emit a prefixed message through an explicitly owned logger."""
    configured = getattr(logger, "anteumbra_symbols", None)
    symbols = configured if isinstance(configured, Mapping) else DEFAULT_SYMBOLS
    prefix = str(symbols.get(symbol_key, f"[{symbol_key.upper()}]"))
    method = getattr(logger, str(level).lower(), None)
    if not callable(method):
        logger.error("%s [INVALID_LEVEL:%s] %s", prefix, level, message)
        return
    method("%s %s", prefix, message)


def bind_symbols(logger: logging.Logger, config: Mapping[str, Any]) -> None:
    """Attach one immutable symbol snapshot to a runtime-owned logger."""
    configured = config.get("logging", {}).get("symbols", {})
    symbols = dict(DEFAULT_SYMBOLS)
    if isinstance(configured, Mapping):
        symbols.update({str(key): str(value) for key, value in configured.items()})
    logger.anteumbra_symbols = MappingProxyType(symbols)


__all__ = ["DEFAULT_SYMBOLS", "bind_symbols", "log_with_symbol"]
