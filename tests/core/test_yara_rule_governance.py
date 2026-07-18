import logging
from pathlib import Path
from types import SimpleNamespace

import pytest
import yara

from anteumbra.infrastructure.detection.yara_engine import YaraEngine


RULES_DIR = (
    Path(__file__).resolve().parents[2]
    / "src"
    / "anteumbra"
    / "rules"
    / "webshell"
)


@pytest.fixture(scope="module")
def engine():
    provider = SimpleNamespace(get=lambda: {"timeouts": {"scan_timeout": 30}})
    return YaraEngine(
        RULES_DIR,
        logging.getLogger("test.yara.governance"),
        provider,
    )


def _rule_names(engine, data):
    return {match.rule_name for match in engine.scan_data(data, "rule-test")}


def test_every_bundled_file_compiles_independently_and_is_bounded():
    rule_files = sorted(RULES_DIR.glob("*.yar"))

    assert rule_files
    assert max(path.stat().st_size for path in rule_files) < 64 * 1024
    for path in rule_files:
        yara.compile(filepath=str(path))


def test_thor_shards_preserve_expected_rule_inventory():
    shards = sorted(RULES_DIR.glob("WShell_THOR_Webshells_*.yar"))
    identifiers = []

    assert len(shards) == 9
    assert not (RULES_DIR / "WShell_THOR_Webshells.yar").exists()
    for shard in shards:
        source = shard.read_text(encoding="utf-8")
        assert "GNU-GPLv2" in source
        rules = [rule.identifier for rule in yara.compile(filepath=str(shard))]
        assert 1 <= len(rules) <= 75
        identifiers.extend(rules)

    assert len(identifiers) == 613
    assert len(set(identifiers)) == 613


def test_engine_loads_all_bundled_files_without_errors(engine):
    assert engine.compiled_rules
    assert engine.load_errors == {}
    assert len(engine.compiled_rules) >= 654


@pytest.mark.parametrize(
    ("payload", "expected_rule"),
    [
        (b"<?php eval($_POST['x']);", "PHP_Direct_Superglobal_Eval"),
        (
            b"<?php $f=base64_decode('YXNzZXJ0');$f($_POST['x']);",
            "PHP_Decoded_Dynamic_Execution",
        ),
        (
            b"<% x=Request(\"p\") : Eval x %>",
            "ASP_Request_Dynamic_Execution",
        ),
        (
            b'<%@ Page Language="C#" %><script runat="server">'
            b'ProcessStartInfo p=new ProcessStartInfo();'
            b'p.FileName="cmd.exe"; Process.Start(p); x=box.Text;</script>',
            "ASPX_Command_Process_Behavior",
        ),
        (
            b'<%@ page import="java.util.*" %><% String x=request.getParameter("q");'
            b'Class c=Class.forName(new String(new byte[]{1}));'
            b'c.getMethod("x").invoke(null); %>',
            "JSP_Reflective_Command_Execution",
        ),
    ],
)
def test_generic_behavior_rules(engine, payload, expected_rule):
    assert expected_rule in _rule_names(engine, payload)


def test_jsp_javascript_eval_is_not_a_webshell_signal(engine):
    payload = (
        b'<%@ page language="java" %><html><script>'
        b'const value = eval(document.getElementById("formula").value);'
        b'</script></html>'
    )

    assert _rule_names(engine, payload) == set()
