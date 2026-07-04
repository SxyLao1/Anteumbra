# -*- coding: utf-8 -*-
"""
Application Service: SSE Manager

Thin facade over infrastructure/utils/sse_manager.py.
Fixes DDD dependency direction: Interfaces → Application → Infrastructure.
"""
from anteumbra.infrastructure.utils.sse_manager import (
    start_sse_worker,
    register_sse_client,
    unregister_sse_client,
    get_connected_client_count,
    get_ip_client_count,
    get_ip_clients,
    remove_dead_clients,
    trigger_registry_update,
    persist_log_line,
    get_log_buffer,
    cleanup_sse_connections,
    get_sse_limits,
)

__all__ = [
    "start_sse_worker",
    "register_sse_client",
    "unregister_sse_client",
    "get_connected_client_count",
    "get_ip_client_count",
    "get_ip_clients",
    "remove_dead_clients",
    "trigger_registry_update",
    "persist_log_line",
    "get_log_buffer",
    "cleanup_sse_connections",
    "get_sse_limits",
]
