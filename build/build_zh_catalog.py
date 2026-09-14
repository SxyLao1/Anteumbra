# -*- coding: utf-8 -*-
"""Merge the authored translation map into the zh catalog and compile it.

Run from the repository root::

    pybabel extract -F build/babel.cfg -o build/messages.pot \
        --project=Anteumbra --copyright-holder=Anteumbra \
        --msgid-bugs-address=noreply@example.com src/anteumbra
    python build/build_zh_catalog.py

``messages.pot`` is the extraction baseline, ``zh_map.py`` and
``zh_map_extra.py`` hold the authored translations, and this script emits
``messages.po`` plus the compiled ``messages.mo``.  Every msgid the extraction
finds needs an entry in one of the two maps, or it falls back to English at
runtime.
"""

from __future__ import annotations

import runpy
import shutil
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
POT = REPO / "build" / "messages.pot"
PO = REPO / "src" / "anteumbra" / "translations" / "zh" / "LC_MESSAGES" / "messages.po"
PYBABEL = shutil.which("pybabel") or str(Path(sys.executable).parent / "pybabel")


def load_map() -> dict[str, str]:
    merged = dict(runpy.run_path(str(REPO / "build" / "zh_map.py"))["TRANSLATIONS"])
    # Feature-scoped maps keep parallel work off one shared file; each holds a
    # single dict and is optional so a checkout without it still builds.
    for name, variable in (
        ("zh_map_extra.py", "TRANSLATIONS"),
        ("zh_map_extra_sites.py", "ZH_MAP_EXTRA_SITES"),
        ("zh_map_extra_memshell.py", "ZH_MAP_EXTRA_MEMSSHELL"),
        ("zh_map_extra_settings.py", "ZH_MAP_EXTRA_SETTINGS"),
        ("zh_map_extra_config.py", "ZH_MAP_EXTRA_CONFIG"),
        ("zh_map_extra_mcp.py", "ZH_MAP_EXTRA_MCP"),
    ):
        path = REPO / "build" / name
        if not path.exists():
            continue
        namespace = runpy.run_path(str(path))
        entries = namespace.get(variable)
        if isinstance(entries, dict):
            merged.update(entries)
    return merged


def po_entry(msgid: str, msgstr: str) -> str:
    def quote(value: str) -> str:
        escaped = value.replace("\\", "\\\\").replace('"', '\\"')
        return f'"{escaped}"'

    lines = [f"msgid {quote(msgid)}"]
    if "\n" in msgstr:
        lines.append('msgstr ""')
        lines.extend(quote(part) for part in msgstr.split("\n"))
    else:
        lines.append(f"msgstr {quote(msgstr)}")
    return "\n".join(lines)


def read_pot_ids(pot: Path) -> list[str]:
    """Return every msgid in POT order, joining the multi-line continuations.

    pybabel wraps long msgids as ``msgid ""`` followed by adjacent quoted
    strings, so a line-by-line scan silently drops every long string — which is
    exactly how the false-positive hint stayed English.
    """
    ids: list[str] = []
    pending: list[str] | None = None

    def flush() -> None:
        nonlocal pending
        if pending is not None:
            value = "".join(pending)
            if value:
                ids.append(value)
            pending = None

    for line in pot.read_text(encoding="utf-8").splitlines():
        if line.startswith("msgid "):
            flush()
            first = line[len("msgid ") :].strip()
            if first == '""':
                pending = []
            else:
                ids.append(_unquote(first))
        elif pending is not None and line.startswith('"'):
            pending.append(_unquote(line.strip()))
        else:
            flush()
    flush()
    return ids


def _unquote(value: str) -> str:
    if value.startswith('"') and value.endswith('"') and len(value) >= 2:
        value = value[1:-1]
    return value.replace('\\"', '"').replace("\\\\", "\\").replace("\\n", "\n")


def _block_msgid(block: str) -> str:
    """Read the msgid out of one PO block, joining multi-line continuations."""
    parts: list[str] = []
    collecting = False
    for line in block.splitlines():
        if line.startswith("msgid "):
            first = line[len("msgid ") :].strip()
            if first == '""':
                collecting = True
                continue
            return _unquote(first)
        if collecting and line.startswith('"'):
            parts.append(_unquote(line.strip()))
        elif collecting:
            break
    return "".join(parts)


def pot_creation_date(pot: Path) -> str:
    """Reuse the template's creation date so the compiled catalog is stable.

    ``pybabel compile`` stamps ``POT-Creation-Date`` into the binary catalog; if
    the header carries no date it falls back to "now", which makes every rebuild
    produce different bytes for identical translations.  Copying the template's
    own date keeps the .mo reproducible as long as the .pot is unchanged.
    """
    for line in pot.read_text(encoding="utf-8").splitlines():
        if line.startswith('"POT-Creation-Date:'):
            value = line[len('"POT-Creation-Date:') :].rstrip('"').strip()
            return value.replace("\\n", "")
    return ""


def main() -> int:
    translations = load_map()
    print(f"map entries: {len(translations)}")

    # Every msgid the templates actually use, in POT order.
    ids: list[str] = read_pot_ids(POT)
    print(f"pot msgids: {len(ids)}")

    creation_date = pot_creation_date(POT)
    header_lines = [
        "# Anteumbra Simplified Chinese translation.",
        'msgid ""',
        'msgstr ""',
        '"Project-Id-Version: Anteumbra\\n"',
    ]
    if creation_date:
        header_lines.append(f'"POT-Creation-Date: {creation_date}\\n"')
    header_lines.extend(
        [
            '"Language: zh\\n"',
            '"MIME-Version: 1.0\\n"',
            '"Content-Type: text/plain; charset=UTF-8\\n"',
            '"Content-Transfer-Encoding: 8bit\\n"',
            '"Plural-Forms: nplurals=1; plural=0;\\n"',
        ]
    )
    header = "\n".join(header_lines)

    body = []
    translated = 0
    emitted: set[str] = set()
    for msgid in ids:
        value = translations.get(msgid)
        if value is None:
            continue
        translated += 1
        emitted.add(msgid)
        body.append(po_entry(msgid, value))

    # Keep entries that only exist in the previous catalog (older strings).
    existing_extra = []
    if PO.exists():
        for block in PO.read_text(encoding="utf-8").split("\n\n"):
            msgid = _block_msgid(block)
            if not msgid or msgid in emitted or msgid in translations:
                continue
            existing_extra.append(block.strip())
            emitted.add(msgid)

    PO.parent.mkdir(parents=True, exist_ok=True)
    PO.write_text("\n\n".join([header] + body + existing_extra) + "\n", encoding="utf-8")
    print(f"po entries: {translated} translated from map, {len(existing_extra)} kept from old catalog")

    result = subprocess.run(
        [str(PYBABEL), "compile", "-i", str(PO), "-o", str(PO.with_suffix(".mo")), "-f"],
        capture_output=True,
        text=True,
    )
    print(result.stdout.strip() or result.stderr.strip())
    mo = PO.with_suffix(".mo")
    print("mo bytes:", mo.stat().st_size if mo.exists() else "MISSING")
    return 0 if mo.exists() else 1


if __name__ == "__main__":
    sys.exit(main())
