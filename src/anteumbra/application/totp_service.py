"""Runtime-owned TOTP enrollment and recovery operations.

The web console has one administrator.  This service deliberately models one
active authenticator secret and a small set of one-time recovery codes instead
of introducing users, roles, or account storage.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import tempfile
import threading
import time
from pathlib import Path
from urllib.parse import quote

from dotenv import set_key

from anteumbra.application.config_document import ConfigDocument, KeyNotFound
from anteumbra.domain.runtime import ConfigProviderPort


class TotpService:
    """Manage one administrator's RFC 6238 secret and recovery codes."""

    STEP_SECONDS = 30
    DIGITS = 6
    DEFAULT_WINDOW = 1
    PENDING_TTL_SECONDS = 10 * 60
    LOGIN_TTL_SECONDS = 5 * 60
    RECOVERY_CODE_COUNT = 8
    RECOVERY_CODE_LENGTH = 12

    def __init__(self, config: ConfigProviderPort) -> None:
        self._config = config
        self._lock = threading.RLock()

    @property
    def env_path(self) -> Path:
        return self._config.path.parent / ".env"

    @property
    def enabled(self) -> bool:
        value = self._config.get().get("web_admin", {}).get("totp_enabled", False)
        if isinstance(value, bool):
            return value
        return str(value).strip().lower() in {"1", "true", "yes", "on"}

    @property
    def secret(self) -> str:
        return str(os.environ.get("ANTEUMBRA_TOTP_SECRET", "") or "").strip().upper()

    @property
    def recovery_hashes(self) -> list[str]:
        raw = str(os.environ.get("ANTEUMBRA_TOTP_RECOVERY_HASHES", "") or "")
        if not raw:
            return []
        try:
            values = json.loads(raw)
        except (TypeError, ValueError):
            return []
        if not isinstance(values, list):
            return []
        return [str(value).strip().lower() for value in values if str(value).strip()]

    @classmethod
    def generate_secret(cls) -> str:
        return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")

    @classmethod
    def generate_recovery_codes(cls) -> list[str]:
        alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
        return [
            "-".join(
                "".join(secrets.choice(alphabet) for _ in range(4))
                for _ in range(cls.RECOVERY_CODE_LENGTH // 4)
            )
            for _ in range(cls.RECOVERY_CODE_COUNT)
        ]

    @classmethod
    def recovery_hash(cls, code: str) -> str:
        normalized = "".join(str(code or "").upper().split())
        return hashlib.sha256(normalized.encode("utf-8")).hexdigest()

    @classmethod
    def otpauth_uri(cls, secret: str, issuer: str, username: str) -> str:
        label = quote(f"{issuer}:{username}", safe="")
        issuer_value = quote(issuer, safe="")
        return f"otpauth://totp/{label}?secret={secret}&issuer={issuer_value}"

    @classmethod
    def _counter_code(cls, secret: str, counter: int) -> str:
        normalized = str(secret or "").strip().upper()
        if not normalized:
            return ""
        padding = "=" * ((8 - len(normalized) % 8) % 8)
        try:
            key = base64.b32decode(normalized + padding, casefold=True)
        except (ValueError, TypeError):
            return ""
        message = counter.to_bytes(8, "big")
        digest = hmac.new(key, message, hashlib.sha1).digest()
        offset = digest[-1] & 0x0F
        value = int.from_bytes(digest[offset : offset + 4], "big") & 0x7FFFFFFF
        return str(value % (10**cls.DIGITS)).zfill(cls.DIGITS)

    @classmethod
    def verify_code(
        cls,
        secret: str,
        code: str,
        *,
        now: float | None = None,
        window: int = DEFAULT_WINDOW,
    ) -> bool:
        normalized = "".join(str(code or "").split())
        if len(normalized) != cls.DIGITS or not normalized.isdigit():
            return False
        counter = int((time.time() if now is None else now) // cls.STEP_SECONDS)
        return any(
            hmac.compare_digest(cls._counter_code(secret, counter + offset), normalized)
            for offset in range(-window, window + 1)
        )

    def verify(self, code: str, *, now: float | None = None) -> bool:
        return self.enabled and self.verify_code(self.secret, code, now=now)

    def consume_recovery_code(self, code: str) -> bool:
        if not self.enabled:
            return False
        candidate = self.recovery_hash(code)
        hashes = self.recovery_hashes
        if not candidate or candidate not in hashes:
            return False
        hashes.remove(candidate)
        self._write_env_values({"ANTEUMBRA_TOTP_RECOVERY_HASHES": json.dumps(hashes)})
        return True

    def enable(self, secret: str, recovery_codes: list[str]) -> None:
        normalized = str(secret or "").strip().upper()
        if not self._counter_code(normalized, 0):
            raise ValueError("TOTP secret is invalid")
        if not recovery_codes:
            raise ValueError("At least one recovery code is required")
        hashes = [self.recovery_hash(code) for code in recovery_codes]
        with self._lock:
            self._write_env_values(
                {
                    "ANTEUMBRA_TOTP_SECRET": normalized,
                    "ANTEUMBRA_TOTP_RECOVERY_HASHES": json.dumps(hashes),
                }
            )
            self._set_enabled(True)

    def disable(self) -> None:
        with self._lock:
            self._write_env_values(
                {
                    "ANTEUMBRA_TOTP_SECRET": "",
                    "ANTEUMBRA_TOTP_RECOVERY_HASHES": "[]",
                }
            )
            self._set_enabled(False)

    def _write_env_values(self, updates: dict[str, str]) -> None:
        env_path = self.env_path
        env_path.parent.mkdir(parents=True, exist_ok=True)
        env_path.touch(exist_ok=True)
        for key, value in updates.items():
            set_key(str(env_path), key, value, quote_mode="auto")
            os.environ[key] = value
        self._config.reload()

    def _set_enabled(self, enabled: bool) -> None:
        path = self._config.path
        if not path.exists():
            raise RuntimeError("Configuration file is missing")
        document = ConfigDocument.load(path)
        try:
            candidate = document.set_leaf("web_admin.totp_enabled", bool(enabled))
        except KeyNotFound:
            candidate = document.add_leaf("web_admin.totp_enabled", bool(enabled))
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="",
            dir=path.parent,
            prefix=".totp-",
            suffix=".tmp",
            delete=False,
        ) as stream:
            temporary = Path(stream.name)
            stream.write(candidate.text)
        try:
            if path.read_bytes().decode("utf-8") != document.text:
                raise RuntimeError("Configuration changed; retry the TOTP update.")
            temporary.replace(path)
        finally:
            temporary.unlink(missing_ok=True)
        self._config.reload()


__all__ = ["TotpService"]
