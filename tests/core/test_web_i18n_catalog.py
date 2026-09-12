# -*- coding: utf-8 -*-
"""Keep the frontend i18n surface honest.

The admin shell ships JS modules a source->translation map built from
``JS_SOURCES``.  A literal that a module passes to ``app.t()`` but that never
reaches ``JS_SOURCES`` silently falls back to English, which is exactly the
mixed-language residue users noticed.  These tests fail loudly instead.
"""

from __future__ import annotations

import re
from pathlib import Path

from anteumbra.interfaces.web import js_strings as module

JS_ROOT = Path(module.__file__).resolve().parents[1] / "static" / "js"
T_CALL = re.compile(r"\bapp\.t\(\s*'((?:[^'\\]|\\.)*)'")
# t('a' + b) style concatenation cannot be translated; catch the accidental form.
T_CONCAT = re.compile(r"\bapp\.t\(\s*[^')\s]")


def _js_files() -> list[Path]:
    return sorted(JS_ROOT.rglob("*.js"))


def test_js_source_calls_are_registered() -> None:
    """Every literal handed to app.t() must be in JS_SOURCES."""
    registered = set(module.JS_SOURCES)
    missing: dict[str, list[str]] = {}
    for path in _js_files():
        text = path.read_text(encoding="utf-8")
        for literal in T_CALL.findall(text):
            value = literal.replace("\\'", "'").replace("\\\\", "\\")
            if value not in registered:
                missing.setdefault(path.name, []).append(value)
    assert not missing, f"app.t() literals missing from JS_SOURCES: {missing}"


def test_js_modules_do_not_concatenate_translations() -> None:
    """Translations must be built from placeholders, not string concatenation."""
    offenders: dict[str, list[str]] = {}
    for path in _js_files():
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if T_CONCAT.search(line):
                offenders.setdefault(path.name, []).append(f"{number}: {line.strip()}")
    assert not offenders, f"app.t() called with a non-literal argument: {offenders}"


def test_extraction_markers_match_the_runtime_sources() -> None:
    """The ``_()`` markers pybabel reads must cover JS_SOURCES exactly."""
    extracted = module._extraction_only()
    assert len(extracted) == len(set(extracted)), "duplicate extraction markers"
    assert set(extracted) == set(module.JS_SOURCES), (
        "JS_SOURCES and _extraction_only drifted: "
        f"only runtime={sorted(set(module.JS_SOURCES) - set(extracted))} "
        f"only markers={sorted(set(extracted) - set(module.JS_SOURCES))}"
    )


def test_js_strings_resolves_in_the_active_locale() -> None:
    """js_strings() must translate at call time, not freeze at import time."""
    from anteumbra.interfaces.web.factory import create_app

    app = create_app()
    with app.test_request_context("/admin/?lang=zh"):
        translated = module.js_strings()
    assert translated["Delete"] == "删除"
    assert translated["%(count)s selected"] == "已选 %(count) 项"
