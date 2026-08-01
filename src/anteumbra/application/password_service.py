"""Runtime-owned administrator credential operations."""

from __future__ import annotations

import os
import re
import secrets
import string
import threading
from collections.abc import Mapping
from pathlib import Path

from dotenv import set_key
from werkzeug.security import generate_password_hash

from anteumbra.domain.runtime import ConfigProviderPort

WEAK_PASSWORDS = frozenset(
    {
        "12345678",
        "123456789",
        "1234567890",
        "admin123",
        "admin1234",
        "anteumbra",
        "changeme",
        "detector",
        "letmein",
        "monitor",
        "password",
        "password1",
        "qwertyui",
        "root123",
        "scanner",
        "trident",
        "webshell",
        "welcome",
    }
)


class PasswordService:
    """Manage credentials relative to one runtime's configuration file."""

    def __init__(self, config: ConfigProviderPort) -> None:
        self._config = config
        self._lock = threading.RLock()

    @property
    def env_path(self) -> Path:
        """Return the deployment environment file owned by this runtime."""
        return self._config.path.parent / ".env"

    def ensure_initial_secrets(self) -> str | None:
        """Persist missing first-run credentials and return a generated password."""
        config = self._config.get()
        web_admin = config.get("web_admin", {})
        security = config.get("security", {})
        password_hash = web_admin.get("password_hash", "") if isinstance(web_admin, Mapping) else ""
        secret_key = security.get("secret_key", "") if isinstance(security, Mapping) else ""

        generated_password: str | None = None
        updates: dict[str, str] = {}
        if not password_hash or str(password_hash).startswith("${"):
            generated_password = "".join(
                secrets.choice(string.ascii_letters + string.digits) for _ in range(16)
            )
            updates["ANTEUMBRA_PASSWORD_HASH"] = generate_password_hash(generated_password)

        invalid_secrets = {
            "",
            "change_this_to_a_random_32_char_string",
            "YOUR_SECRET_KEY_HERE",
        }
        if str(secret_key).strip() in invalid_secrets or str(secret_key).startswith("${"):
            updates["ANTEUMBRA_SECRET_KEY"] = secrets.token_urlsafe(48)

        if updates:
            self._write_env_values(updates)
        return generated_password

    def check_strength(self, password: str) -> tuple[bool, str]:
        """Validate a proposed administrator password."""
        if len(password) < 8:
            return False, "Password must be at least 8 characters."
        if len(password) > 64:
            return False, "Password must not exceed 64 characters."
        if password.lower() in WEAK_PASSWORDS:
            return False, "Choose a password that is not commonly used."

        categories = sum(
            (
                any(character.isupper() for character in password),
                any(character.islower() for character in password),
                any(character.isdigit() for character in password),
                any(character in "@#$%^&+=-_!~.,:;*?/\\|" for character in password),
            )
        )
        if categories < 3:
            return (
                False,
                "Use at least three of uppercase, lowercase, digits, and symbols.",
            )
        if re.search(r"(.)\1{2,}", password):
            return False, "Do not use three repeated characters in sequence."

        lowered = password.lower()
        keyboard_patterns = ("qwerty", "asdf", "zxcv", "1234", "abcd", "qaz", "wsx")
        if any(pattern in lowered for pattern in keyboard_patterns):
            return False, "Do not use keyboard or sequential patterns."
        return True, "Password strength requirements are satisfied."

    def set_password(self, password: str) -> tuple[bool, str]:
        """Validate and atomically publish a new administrator password hash."""
        accepted, message = self.check_strength(password)
        if not accepted:
            return False, message
        try:
            self._write_env_values({"ANTEUMBRA_PASSWORD_HASH": generate_password_hash(password)})
        except (OSError, RuntimeError, ValueError) as exc:
            return False, f"Password update failed: {exc}"
        return True, "Password updated and active for new logins."

    def _write_env_values(self, updates: Mapping[str, str]) -> None:
        with self._lock:
            env_path = self.env_path
            env_path.parent.mkdir(parents=True, exist_ok=True)
            env_path.touch(exist_ok=True)
            for key, value in updates.items():
                set_key(str(env_path), key, value, quote_mode="auto")
                os.environ[key] = value
            self._config.reload()


__all__ = ["PasswordService", "WEAK_PASSWORDS"]
