# -*- coding: utf-8 -*-
"""
Application Service: Password Utilities

Thin facade over infrastructure/utils/password_utils.py.
Fixes DDD dependency direction: Interfaces → Application → Infrastructure.
"""
from anteumbra.infrastructure.utils.password_utils import (
    check_password_strength,
    update_password_hash_in_config,
    validate_current_password,
    load_weak_passwords,
)

__all__ = [
    "check_password_strength",
    "update_password_hash_in_config",
    "validate_current_password",
    "load_weak_passwords",
]
