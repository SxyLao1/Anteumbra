"""The bundled agent skill: packaging, export, and the operator content it must carry."""

from __future__ import annotations

from pathlib import Path

import pytest
from click.testing import CliRunner

REQUIRED_TOPICS = (
    "discover_web_services",
    "list_listening_ports",
    "list_sites",
    "validate_config",
    "list_detections",
    "list_quarantine",
    "add_site",
    "update_site",
    "set_config_value",
    "set_env_value",
    'pip install "anteumbra[mcp]"',
    "--allow-write",
    "authorization code",
    "POP3",
    "quarantine.auto_quarantine_enabled",
    "ip_blocker.auto_block_enabled",
    "anteumbra --home",
    "anteumbra skill export",
    "***REDACTED***",
    "中文速查",
)


def _package_skill_root() -> Path:
    import anteumbra

    return Path(anteumbra.__file__).parent / "skills"


def _skill_text() -> str:
    return (_package_skill_root() / "anteumbra" / "SKILL.md").read_text(encoding="utf-8")


def test_packaged_skill_is_present_with_frontmatter():
    import anteumbra

    assert (Path(anteumbra.__file__).parent / "skills").is_dir()
    text = _skill_text()

    assert text.startswith("---\n")
    header = text.split("---", 2)[1]
    assert "name: anteumbra" in header
    assert "description:" in header


def test_skill_covers_every_required_operator_topic():
    text = _skill_text()
    lower = text.lower()

    for topic in REQUIRED_TOPICS:
        assert topic in text or topic.lower() in lower, topic
    for phrase in (
        "verification checklist",
        "safety rules",
        "stop and ask",
        "never print a secret",
    ):
        assert phrase in lower, phrase


def test_export_skill_writes_the_skill_into_a_named_directory(tmp_path):
    from anteumbra.cli.skill_commands import export_skill

    written = export_skill(_package_skill_root(), tmp_path)

    assert written == [tmp_path / "anteumbra" / "SKILL.md"]
    assert (tmp_path / "anteumbra" / "SKILL.md").read_text(encoding="utf-8") == _skill_text()


def test_export_skill_is_flat_on_request(tmp_path):
    from anteumbra.cli.skill_commands import export_skill

    export_skill(_package_skill_root(), tmp_path, flat=True)

    assert (tmp_path / "SKILL.md").is_file()
    assert not (tmp_path / "anteumbra").exists()


def test_export_skill_refuses_to_overwrite_without_force(tmp_path):
    import click

    from anteumbra.cli.skill_commands import export_skill

    export_skill(_package_skill_root(), tmp_path)
    (tmp_path / "anteumbra" / "SKILL.md").write_text("mine\n", encoding="utf-8")

    with pytest.raises(click.ClickException, match="already exists"):
        export_skill(_package_skill_root(), tmp_path)

    export_skill(_package_skill_root(), tmp_path, force=True)
    assert (tmp_path / "anteumbra" / "SKILL.md").read_text(encoding="utf-8") == _skill_text()


def test_export_skill_reports_a_missing_bundle(tmp_path):
    import click

    from anteumbra.cli.skill_commands import export_skill

    with pytest.raises(click.ClickException, match="Reinstall the anteumbra package"):
        export_skill(tmp_path / "not-a-package", tmp_path / "out")


def test_skill_export_command_copies_the_file(tmp_path):
    from anteumbra.cli.main import cli

    result = CliRunner().invoke(cli, ["skill", "export", str(tmp_path)])

    assert result.exit_code == 0, result.output
    assert (tmp_path / "anteumbra" / "SKILL.md").is_file()
    assert "Skill exported to" in result.output


def test_skill_show_prints_the_bundled_document():
    from anteumbra.cli.main import cli

    result = CliRunner().invoke(cli, ["skill", "show"])

    assert result.exit_code == 0, result.output
    assert "name: anteumbra" in result.output
    assert "discover_web_services" in result.output


def test_skill_group_help_explains_the_export_target():
    from anteumbra.cli.main import cli

    result = CliRunner().invoke(cli, ["skill", "--help"])

    assert result.exit_code == 0, result.output
    assert "export" in result.output
    assert "show" in result.output
