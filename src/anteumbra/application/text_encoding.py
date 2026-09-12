# -*- coding: utf-8 -*-
"""Decode source files that are not UTF-8.

Webshells found on Chinese hosts are routinely GBK/GB2312, and the source viewer
used to force ``utf-8`` with ``errors="replace"``, turning every Chinese comment
and string into U+FFFD.  The bytes are decoded properly here instead.

This lives in the application layer so the web blueprints can use it without
importing infrastructure.
"""

from __future__ import annotations

import codecs
import re

__all__ = ["decode_source_bytes", "detect_charset_hint"]

# Declared charsets are ASCII, so they can be sniffed from a latin-1 view of the
# head of the file before any decoding decision is made.
_CHARSET_HINT = re.compile(rb"""charset\s*=\s*["']?\s*([A-Za-z0-9_+.-]+)""", re.IGNORECASE)
_SNIFF_BYTES = 4096

_BOMS: tuple[tuple[bytes, str], ...] = (
    (codecs.BOM_UTF8, "utf-8-sig"),
    (codecs.BOM_UTF32_LE, "utf-32-le"),
    (codecs.BOM_UTF32_BE, "utf-32-be"),
    (codecs.BOM_UTF16_LE, "utf-16-le"),
    (codecs.BOM_UTF16_BE, "utf-16-be"),
)

# Guessed only after the BOM, a strict UTF-8 attempt and the file's own
# declaration have all been ruled out.  gb18030 is a superset of GBK/GB2312 and
# comes first because this tool scans Chinese-facing hosts.
_CANDIDATES: tuple[str, ...] = ("gb18030", "big5", "cp1252")


def detect_charset_hint(data: bytes) -> str | None:
    """Return the charset the file declares in its own head, if any."""
    match = _CHARSET_HINT.search(data[:_SNIFF_BYTES])
    if not match:
        return None
    name = match.group(1).decode("ascii", errors="ignore").lower()
    # GB2312/GBK are decoded by their superset; map the aliases onto it.
    if name in {"gb2312", "gbk", "gb18030", "x-gbk", "ms936", "cp936"}:
        return "gb18030"
    if name in {"utf8", "utf-8"}:
        return "utf-8"
    try:
        codecs.lookup(name)
    except LookupError:
        return None
    return name


def decode_source_bytes(data: bytes) -> tuple[str, str]:
    """Decode file bytes, returning ``(text, encoding_used)``.

    Order of preference: a BOM, then a strict UTF-8 attempt (UTF-8 is
    self-validating, so success is conclusive), then the charset the file
    declares about itself, then the common legacy encodings.  Only when
    everything fails does it fall back to a lossy decode, and the returned label
    says so.
    """
    for bom, encoding in _BOMS:
        if data.startswith(bom):
            try:
                return data.decode(encoding), encoding
            except UnicodeDecodeError:
                break

    try:
        return data.decode("utf-8"), "utf-8"
    except UnicodeDecodeError:
        pass

    hinted = detect_charset_hint(data)
    if hinted:
        try:
            return data.decode(hinted), hinted
        except (UnicodeDecodeError, LookupError):
            pass

    for encoding in _CANDIDATES:
        try:
            return data.decode(encoding), encoding
        except (UnicodeDecodeError, LookupError):
            continue

    return data.decode("utf-8", errors="replace"), "utf-8 (lossy)"
