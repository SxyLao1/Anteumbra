# -*- coding: utf-8 -*-
"""The decoder must not be derailed by a Windows path that looks dangerous.

Reported from the live log: a phpSpy sample assigns

    $program = 'c:\\windows\\system32\\cmd.exe';

The value contains "system", so the decoder treated it as a function name and
handed it to ``re.sub`` as a replacement template — where ``\\w`` is an invalid
escape.  The exception aborted the whole decode pass for that file, so nothing
that pass would have found was reported, and every scan of that file dumped a
traceback into the log.
"""

from __future__ import annotations

import logging

from anteumbra.infrastructure.detection.decoder import WebShellDecoder

WINDOWS_PATH_SAMPLE = r"""
<?php
$program = 'c:\\windows\\system32\\cmd.exe';
$program('whoami');
"""


def test_a_windows_path_is_not_mistaken_for_a_function_name():
    decoded = WebShellDecoder._inline_variable_call(WINDOWS_PATH_SAMPLE)

    assert "cmd.exe" in decoded
    assert "system32(" not in decoded, "a path must never be rewritten as a call"


def test_a_real_function_variable_is_still_inlined():
    text = "<?php $f = 'eval'; $f($_POST['x']);"

    decoded = WebShellDecoder._inline_variable_call(text)

    assert "eval($_POST['x'])" in decoded


def test_the_error_handler_variable_is_inlined_with_its_at_sign():
    text = "<?php $f = '@system'; $f($_GET['c']);"

    decoded = WebShellDecoder._inline_variable_call(text)

    assert "@system($_GET['c'])" in decoded


def test_the_reported_sample_decodes_without_raising():
    decoded = WebShellDecoder.decode(WINDOWS_PATH_SAMPLE.encode("utf-8"))

    assert isinstance(decoded, str)


def test_a_failing_decoder_is_reported_without_a_traceback(monkeypatch, caplog, tmp_path):
    """One line naming the file, not a stack dump in the live log stream."""
    from anteumbra.infrastructure.detection import decoder as decoder_module
    from anteumbra.infrastructure.detection.scanner import ScannerService

    def explode(_raw):
        raise ValueError("cannot decode this content")

    monkeypatch.setattr(decoder_module.WebShellDecoder, "decode", staticmethod(explode))
    sample = tmp_path / "broken.php"
    sample.write_bytes(b"<?php eval($_POST[1]);")
    yara_engine = type(
        "EngineStub", (), {"compiled_rules": object(), "scan_data": lambda *_a, **_k: []}
    )()
    scanner = ScannerService(None, yara_engine, None)

    with caplog.at_level(logging.DEBUG):
        result = scanner._scan_decoded(sample, logging.getLogger("test.decoder"))

    assert result is None
    warnings = [record for record in caplog.records if record.levelno == logging.WARNING]
    assert warnings, "the skipped decoder pass has to be visible"
    assert warnings[0].exc_info is None, "a per-file condition must not dump a traceback"
    assert "broken.php" in warnings[0].getMessage()
