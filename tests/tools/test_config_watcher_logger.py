"""Runtime-owned configuration history tests."""

from pathlib import Path


def test_config_history_uses_explicit_runtime_paths(tmp_path):
    from anteumbra.application.config_history_service import ConfigHistoryLogger

    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "one.yar").write_text("rule one { condition: true }", encoding="utf-8")
    (rules_dir / "two.yar").write_text("rule two { condition: true }", encoding="utf-8")
    history_file = tmp_path / "data" / "config_history.json"
    history = ConfigHistoryLogger(history_file, rules_dir=rules_dir)

    assert history.log_reload(
        {
            "website": [{"name": "Alpha"}, {"name": "Beta"}],
            "notifier": {"enabled": True},
        },
        ["website", "notifier.enabled"],
        12.345,
    )

    record = history.get_history()[0]
    assert history.history_file == history_file.resolve()
    assert record["changed_keys"] == ["website", "notifier.enabled"]
    assert record["duration_ms"] == 12.35
    assert record["config_summary"]["websites_count"] == 2
    assert record["config_summary"]["yara_rules_count"] == 2


def test_config_history_instances_do_not_share_state(tmp_path):
    from anteumbra.application.config_history_service import ConfigHistoryLogger

    first = ConfigHistoryLogger(tmp_path / "first" / "history.json")
    second = ConfigHistoryLogger(tmp_path / "second" / "history.json")

    assert first.log_reload({"website": {"name": "Alpha"}}, ["website"], 1.0)

    assert len(first.get_history()) == 1
    assert first.get_history()[0]["config_summary"]["websites_count"] == 1
    assert second.get_history() == []
    assert second.clear_history() is True
    assert Path(second.history_file).exists()
