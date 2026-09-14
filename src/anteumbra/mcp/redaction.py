"""Keep secrets out of every MCP response.

Two independent mechanisms, because one of them alone is not enough:

* **Structural** - a redaction pass over the effective configuration replaces
  any value whose key names a credential. This catches a secret even when the
  ``.env`` file cannot be read.
* **Value-based** - every secret value read from the instance ``.env`` is
  collected and stripped from any string in any tool response. This catches a
  secret that lands somewhere the structural pass does not look at, such as a
  resolved ``${VAR}`` placeholder, a URL, or a detection record.

Neither mechanism ever returns a ``.env`` value itself, so a redacted response
cannot be used to recover what was hidden.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

REDACTED = "***REDACTED***"

# Whole-key names that always carry a credential.
_SECRET_KEY_NAMES = frozenset(
    {
        "apikey",
        "auth",
        "authorization",
        "bearer",
        "credential",
        "credentials",
        "hash",
        "key",
        "passwd",
        "password",
        "password_hash",
        "private_key",
        "secret",
        "secret_key",
        "sendkey",
        "session_secret",
        "token",
    }
)

# Key suffixes that make a compound name a credential, e.g. api_token.
_SECRET_KEY_SUFFIXES = (
    "_apikey",
    "_credential",
    "_credentials",
    "_hash",
    "_key",
    "_password",
    "_passwd",
    "_secret",
    "_token",
)

# A URL string inside one of these tables is itself the credential.
_CREDENTIAL_URL_TABLES = frozenset({"device", "devices", "webhook", "webhooks"})
_CREDENTIAL_URL_KEYS = frozenset({"endpoint", "target", "url", "webhook", "webhook_url"})

# Below this length a secret is matched exactly instead of as a substring, so a
# short secret cannot blank out unrelated text.
_MIN_SUBSTRING_SECRET = 8


def normalize_key(name: object) -> str:
    """Return a comparable form of a configuration key."""
    return str(name).strip().lower().replace("-", "_")


def is_secret_key(name: object) -> bool:
    """Return whether a key name denotes a credential."""
    key = normalize_key(name)
    return key in _SECRET_KEY_NAMES or key.endswith(_SECRET_KEY_SUFFIXES)


def _is_credential_url(table: str, key: object) -> bool:
    return normalize_key(table) in _CREDENTIAL_URL_TABLES and normalize_key(key) in (
        _CREDENTIAL_URL_KEYS
    )


def _has_embedded_credentials(value: str) -> bool:
    """Detect ``scheme://user:password@host`` without a URL parser."""
    if "://" not in value or "@" not in value:
        return False
    authority = value.split("://", 1)[1].split("/", 1)[0]
    return ":" in authority.split("@", 1)[0]


def redact_config(config: Any, *, parent_key: str = "") -> Any:
    """Return ``config`` with every credential-shaped value replaced.

    A table whose *name* looks like a credential is kept and recursed into
    rather than dropped, so the agent still sees that a channel exists while
    never seeing its secret.
    """
    if isinstance(config, Mapping):
        redacted: dict[Any, Any] = {}
        for key, value in config.items():
            if is_secret_key(key) or (
                isinstance(value, str) and _is_credential_url(parent_key, key)
            ):
                redacted[key] = REDACTED
                continue
            redacted[key] = redact_config(value, parent_key=str(key))
        return redacted
    if isinstance(config, (list, tuple)):
        return [redact_config(item, parent_key=parent_key) for item in config]
    if isinstance(config, str) and _has_embedded_credentials(config):
        return REDACTED
    return config


def parse_env_secrets(text: str) -> tuple[str, ...]:
    """Extract credential values from ``.env`` text.

    Only keys that name a credential are collected, so an account name or a
    public hostname stays visible to the agent while a password never does.
    """
    secrets: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, _, raw_value = stripped.partition("=")
        if not is_secret_key(key):
            continue
        value = raw_value.strip().strip("'\"")
        if value and value not in secrets:
            secrets.append(value)
    return tuple(secrets)


def load_env_secrets(env_path: Path) -> tuple[str, ...]:
    """Read credential values from an instance ``.env`` file, tolerating absence."""
    try:
        text = env_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return ()
    return parse_env_secrets(text)


def redact_secret_values(value: Any, secrets: Sequence[str]) -> Any:
    """Strip every known secret value out of an arbitrary response object."""
    if not secrets:
        return value
    if isinstance(value, Mapping):
        return {
            key: redact_secret_values(item, secrets) for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [redact_secret_values(item, secrets) for item in value]
    if not isinstance(value, str):
        return value
    for secret in secrets:
        if secret not in value:
            continue
        if len(secret) >= _MIN_SUBSTRING_SECRET:
            value = value.replace(secret, REDACTED)
        elif value == secret:
            value = REDACTED
    return value


__all__ = [
    "REDACTED",
    "is_secret_key",
    "load_env_secrets",
    "normalize_key",
    "parse_env_secrets",
    "redact_config",
    "redact_secret_values",
]
