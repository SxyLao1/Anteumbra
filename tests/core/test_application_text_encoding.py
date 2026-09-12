# -*- coding: utf-8 -*-
"""Source files on Chinese hosts are often GBK, not UTF-8.

The viewer used to force ``utf-8`` with ``errors="replace"``, so every Chinese
comment in a webshell turned into U+FFFD.
"""

from __future__ import annotations

import codecs

import pytest

from anteumbra.application.text_encoding import (
    decode_source_bytes,
    detect_charset_hint,
)

CHINESE = "<?php // \u514d\u6740\u5927\u9a6c \u5bc6\u7801:123456 ?>\n"
REPLACEMENT = "\ufffd"


def test_gbk_source_decodes_without_replacement_characters() -> None:
    text, encoding = decode_source_bytes(CHINESE.encode("gb18030"))
    assert text == CHINESE
    assert REPLACEMENT not in text
    assert encoding == "gb18030"


def test_gb2312_source_decodes() -> None:
    text, encoding = decode_source_bytes(CHINESE.encode("gb2312"))
    assert text == CHINESE
    assert encoding == "gb18030"  # decoded via the GBK/GB18030 superset


def test_utf8_source_still_decodes_as_utf8() -> None:
    text, encoding = decode_source_bytes(CHINESE.encode("utf-8"))
    assert text == CHINESE
    assert encoding == "utf-8"


def test_utf8_bom_is_stripped() -> None:
    text, encoding = decode_source_bytes(codecs.BOM_UTF8 + CHINESE.encode("utf-8"))
    assert text == CHINESE
    assert encoding == "utf-8-sig"


def test_declared_charset_wins_over_the_guess() -> None:
    # Big5 cannot be reached by the gb18030 guess, so the in-file declaration is
    # what makes it decode correctly.
    body = "<html><head><meta charset=\"big5\"></head><body>\u4e2d\u6587</body></html>"
    payload = body.encode("big5")
    assert detect_charset_hint(payload) == "big5"
    text, encoding = decode_source_bytes(payload)
    assert "\u4e2d\u6587" in text
    assert encoding == "big5"


def test_gb2312_declaration_maps_onto_gb18030() -> None:
    assert detect_charset_hint(b"<?php // charset=gb2312 ?>") == "gb18030"


def test_ascii_is_utf8() -> None:
    text, encoding = decode_source_bytes(b"<?php echo 1; ?>\n")
    assert text == "<?php echo 1; ?>\n"
    assert encoding == "utf-8"


def test_broken_bytes_still_return_text() -> None:
    # A lone 0xFF is invalid in every candidate encoding we try.
    text, encoding = decode_source_bytes(b"<?php\xff\xfe\x00?>")
    assert isinstance(text, str)
    assert encoding.endswith(("gb18030", "big5", "cp1252", "(lossy)"))


@pytest.mark.parametrize("encoding", ["gb18030", "utf-8"])
def test_round_trip_keeps_line_count(encoding: str) -> None:
    payload = ("line\n" * 10 + "\u7ed3\u5c3e\n").encode(encoding)
    text, _ = decode_source_bytes(payload)
    assert text.count("\n") == 11
