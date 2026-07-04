# -*- coding: utf-8 -*-
"""
Application Service: Logging Utilities

Thin facade over infrastructure/utils/logger_factory.py.
Fixes DDD dependency direction: Interfaces → Application → Infrastructure.

Note: logging is a cross-cutting concern, but we wrap it for DDD consistency
with the rest of the application service layer.
"""
from anteumbra.infrastructure.utils.logger_factory import (
    log_with_symbol,
    silence_werkzeug,
    get_access_logger,
    get_flask_runtime_logger,
)

__all__ = [
    "log_with_symbol",
    "silence_werkzeug",
    "get_access_logger",
    "get_flask_runtime_logger",
]
