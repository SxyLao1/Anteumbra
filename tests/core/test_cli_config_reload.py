"""CLI configuration parse semantics."""

from click.testing import CliRunner


def test_config_reload_parses_without_claiming_to_reload_service(tmp_path):
    from anteumbra.cli.main import cli

    target = tmp_path / "instance" / "config.toml"
    runner = CliRunner()
    initialized = runner.invoke(
        cli,
        ["config", "init", "--output", str(target), "--force"],
    )
    assert initialized.exit_code == 0, initialized.output

    result = runner.invoke(
        cli,
        ["config", "reload", "--config", str(target)],
    )

    assert result.exit_code == 0, result.output
    assert f"Config parsed successfully: {target.resolve()}" in result.output
    assert "Enabled websites: 1" in result.output
    assert "running Anteumbra service is unchanged" in result.output
    assert "registry reloaded" not in result.output.lower()
