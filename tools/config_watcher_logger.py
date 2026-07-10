"""Compatibility wrapper for config reload history logging."""

from anteumbra.application.config_history_service import (
    ConfigHistoryLogger,
    ConfigWatcherLogger,
    get_config_history_logger,
    get_config_watcher_logger,
)

__all__ = [
    "ConfigHistoryLogger",
    "ConfigWatcherLogger",
    "get_config_history_logger",
    "get_config_watcher_logger",
]
