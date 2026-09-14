# -*- coding: utf-8 -*-
"""Translation placeholders must match the message they translate.

A translation that writes '%(count)' where the message says '%(count)s' looks
harmless and passes every "is the key present" test, but Python's %-formatting
then treats the character after ')' as a conversion type and the page dies with
"unsupported format character" at render time - which is exactly how the
settings page broke once. This guard checks every authored translation and the
compiled catalog.
"""

from __future__ import annotations

import re
import runpy
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
BUILD = REPO / "build"
PO = REPO / "src" / "anteumbra" / "translations" / "zh" / "LC_MESSAGES" / "messages.po"

MAPS = (
    ("zh_map.py", "TRANSLATIONS"),
    ("zh_map_extra.py", "TRANSLATIONS"),
    ("zh_map_extra_sites.py", "ZH_MAP_EXTRA_SITES"),
    ("zh_map_extra_memshell.py", "ZH_MAP_EXTRA_MEMSSHELL"),
    ("zh_map_extra_settings.py", "ZH_MAP_EXTRA_SETTINGS"),
    ("zh_map_extra_config.py", "ZH_MAP_EXTRA_CONFIG"),
)

PLACEHOLDER = re.compile(r"%\((\w+)\)([a-zA-Z])")
def broken_percent_sequences(text: str) -> list[str]:
    """Return the '%' sequences that would break %-formatting.

    Scans left to right so that '%%' is consumed as one escaped literal; a
    '%' that is not '%%', '%s'-style or '%(name)s'-style is a defect.
    """
    problems: list[str] = []
    index = 0
    while index < len(text):
        if text[index] != "%":
            index += 1
            continue
        tail = text[index + 1 :]
        if tail.startswith("%") or re.match(r"[a-zA-Z]", tail):
            index += 2
            continue
        if re.match(r"\([^)]*\)[a-zA-Z]", tail):
            index += 1
            continue
        problems.append(text[index : index + 6])
        index += 1
    return problems


def load_maps() -> list[tuple[str, dict[str, str]]]:
    loaded: list[tuple[str, dict[str, str]]] = []
    for name, variable in MAPS:
        path = BUILD / name
        if not path.exists():
            continue
        entries = runpy.run_path(str(path)).get(variable)
        if isinstance(entries, dict):
            loaded.append((name, {str(k): str(v) for k, v in entries.items()}))
    return loaded


def test_every_authored_translation_is_available():
    maps = load_maps()
    assert maps, "no translation map could be loaded"
    assert sum(len(entries) for _, entries in maps) > 500


def test_placeholders_in_a_translation_match_its_message():
    problems: list[str] = []
    for name, entries in load_maps():
        for msgid, msgstr in entries.items():
            expected = set(PLACEHOLDER.findall(msgid))
            found = set(PLACEHOLDER.findall(msgstr))
            if expected != found:
                problems.append(
                    f"{name}: {msgid[:70]!r} expects {sorted(expected)} "
                    f"but the translation has {sorted(found)}"
                )
    assert not problems, "\n".join(problems[:20])


def test_no_translation_contains_a_broken_percent_sequence():
    problems: list[str] = []
    for name, entries in load_maps():
        for msgid, msgstr in entries.items():
            if broken_percent_sequences(msgstr):
                problems.append(f"{name}: {msgid[:60]!r} -> {msgstr[:80]!r}")
    assert not problems, "\n".join(problems[:20])


@pytest.mark.skipif(not PO.exists(), reason="compiled catalog is not present")
def test_compiled_catalog_has_no_broken_percent_sequence():
    text = PO.read_text(encoding="utf-8")
    problems: list[str] = []
    for block in re.split(r"\n\n+", text):
        msgid_match = re.search(r'msgid ((?:"(?:[^"\\]|\\.)*"\s*)+)', block)
        msgstr_match = re.search(r'msgstr ((?:"(?:[^"\\]|\\.)*"\s*)+)', block)
        if not msgid_match or not msgstr_match:
            continue
        msgid = "".join(re.findall(r'"((?:[^"\\]|\\.)*)"', msgid_match.group(1)))
        msgstr = "".join(re.findall(r'"((?:[^"\\]|\\.)*)"', msgstr_match.group(1)))
        if broken_percent_sequences(msgstr) or set(PLACEHOLDER.findall(msgid)) != set(
            PLACEHOLDER.findall(msgstr)
        ):
            problems.append(f"{msgid[:60]!r} -> {msgstr[:80]!r}")
    assert not problems, "\n".join(problems[:20])
