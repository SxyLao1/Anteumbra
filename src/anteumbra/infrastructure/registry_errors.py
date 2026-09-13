"""Registry failure types shared by the Registry and its storage adapters."""

from __future__ import annotations


class RegistryError(RuntimeError):
    """Base class for Registry failures."""


class RegistryDataError(RegistryError):
    """Raised when no valid authoritative or recovery data can be loaded."""


class RegistryPersistenceError(RegistryError):
    """Raised when a Registry mutation cannot be durably persisted."""


__all__ = ["RegistryDataError", "RegistryError", "RegistryPersistenceError"]
