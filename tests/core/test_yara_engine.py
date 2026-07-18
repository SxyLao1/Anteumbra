import logging
from types import SimpleNamespace

from anteumbra.infrastructure.config.registry import ConfigRegistry
from anteumbra.infrastructure.detection.yara_engine import (
    CompositeYaraRules,
    YaraEngine,
    _CompiledRuleFile,
    get_bundled_rules_path,
    resolve_yara_rules_path,
)


VALID_RULE = r'''
rule Test_PHP_Dynamic_Execution {
    meta:
        severity = "high"
    strings:
        $sink = "eval($_POST"
    condition:
        $sink
}
'''


def _configure_scanning(monkeypatch, timeout=5):
    monkeypatch.setattr(
        ConfigRegistry,
        "get_raw_config",
        classmethod(lambda cls: {
            "filesizes": {"max_scan_file_size_mb": 10},
            "timeouts": {"scan_timeout": timeout},
        }),
    )


def test_invalid_file_does_not_disable_valid_rules(monkeypatch, tmp_path):
    _configure_scanning(monkeypatch)
    (tmp_path / "good.yar").write_text(VALID_RULE, encoding="utf-8")
    (tmp_path / "broken.yar").write_text(
        "rule Broken { condition:",
        encoding="utf-8",
    )
    sample = tmp_path / "sample.php"
    sample.write_text("<?php eval($_POST['x']);", encoding="utf-8")

    engine = YaraEngine(tmp_path, logging.getLogger("test.yara.invalid"))

    assert engine.compiled_rules
    assert len(engine.compiled_rules) == 1
    assert engine.loaded_rule_files == ("good.yar",)
    assert "broken.yar" in engine.load_errors
    assert [match.rule_name for match in engine.scan(sample)] == [
        "Test_PHP_Dynamic_Execution"
    ]


def test_runtime_failure_is_isolated_to_one_compiled_file():
    calls = []

    class BrokenRules:
        def __iter__(self):
            return iter(())

        def match(self, **kwargs):
            raise RuntimeError("bad runtime rule")

    class GoodRules:
        def __iter__(self):
            return iter(())

        def match(self, **kwargs):
            calls.append(kwargs)
            return [SimpleNamespace(rule="Good", namespace="good", meta={})]

    compiled = CompositeYaraRules([
        _CompiledRuleFile("broken.yar", "broken", BrokenRules(), 1),
        _CompiledRuleFile("good.yar", "good", GoodRules(), 1),
    ], logging.getLogger("test.yara.runtime"))

    matches = compiled.match(data=b"payload", timeout=3)

    assert [match.rule for match in matches] == ["Good"]
    assert "broken.yar" in compiled.last_match_errors
    assert calls[0]["data"] == b"payload"
    assert 1 <= calls[0]["timeout"] <= 3


def test_failed_reload_retains_previous_working_rules(monkeypatch, tmp_path):
    _configure_scanning(monkeypatch)
    rule_path = tmp_path / "active.yar"
    rule_path.write_text(VALID_RULE, encoding="utf-8")
    engine = YaraEngine(tmp_path, logging.getLogger("test.yara.reload"))

    rule_path.write_text("rule Broken { condition:", encoding="utf-8")

    assert engine.reload() is False
    assert engine.compiled_rules
    assert engine.loaded_rule_files == ("active.yar",)
    matches = engine.scan_data(b"eval($_POST", "reload-test")
    assert [match.rule_name for match in matches] == [
        "Test_PHP_Dynamic_Execution"
    ]


def test_empty_configured_directory_uses_bundled_rules(tmp_path):
    resolved = resolve_yara_rules_path(
        tmp_path,
        logging.getLogger("test.yara.fallback"),
    )

    assert resolved == get_bundled_rules_path().resolve()
    assert next(resolved.glob("*.yar"), None) is not None


def test_direct_engine_uses_defaults_when_registry_is_unavailable(monkeypatch, tmp_path):
    (tmp_path / "good.yar").write_text(VALID_RULE, encoding="utf-8")
    monkeypatch.setattr(
        ConfigRegistry,
        "get_raw_config",
        classmethod(lambda cls: (_ for _ in ()).throw(RuntimeError("not ready"))),
    )
    monkeypatch.setattr(
        ConfigRegistry,
        "initialize",
        classmethod(lambda cls: (_ for _ in ()).throw(FileNotFoundError("missing"))),
    )
    engine = YaraEngine(tmp_path, logging.getLogger("test.yara.defaults"))

    matches = engine.scan_data(b"eval($_POST", "defaults-test")

    assert [match.rule_name for match in matches] == [
        "Test_PHP_Dynamic_Execution"
    ]
