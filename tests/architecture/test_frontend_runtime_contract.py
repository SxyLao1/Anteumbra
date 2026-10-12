"""Guard the lifecycle contract of the delegated admin frontend shell."""

from pathlib import Path


def test_frontend_shell_starts_when_loaded_after_dom_content_loaded():
    """HTMX-inserted script tags must not leave all data-actions inert."""

    source = (
        Path(__file__).parents[2]
        / "src"
        / "anteumbra"
        / "interfaces"
        / "web"
        / "static"
        / "js"
        / "app.js"
    ).read_text(encoding="utf-8")

    assert "if (document.readyState === 'loading')" in source
    assert "document.addEventListener('DOMContentLoaded', function () { app.start(); });" in source
    assert "window.setTimeout(function () { app.start(); }, 0);" in source
    assert "if (started && module.mount) module.mount(document);" in source
