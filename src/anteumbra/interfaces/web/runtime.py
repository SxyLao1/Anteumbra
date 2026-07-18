"""Access the explicit runtime attached to the current Flask application."""

from __future__ import annotations

from flask import current_app

from anteumbra.application.runtime_container import RuntimeContainer


_RUNTIME_EXTENSION = "anteumbra.runtime"


def get_runtime() -> RuntimeContainer:
    """Return the current app-owned runtime or fail with a clear wiring error."""
    runtime = current_app.extensions.get(_RUNTIME_EXTENSION)
    if not isinstance(runtime, RuntimeContainer):
        raise RuntimeError("Anteumbra RuntimeContainer is not attached to this Flask app")
    return runtime
