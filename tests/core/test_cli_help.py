"""CLI discoverability and non-destructive default behavior."""

from click.testing import CliRunner


def test_top_level_help_explains_package_and_runtime_locations():
    from anteumbra.cli.main import cli

    result = CliRunner().invoke(cli, ["--help"])

    assert result.exit_code == 0, result.output
    assert "--home DIRECTORY" in result.output
    assert "anteumbra install INSTANCE_DIR" in result.output
    assert "Python package location" in result.output
    assert "anteumbra COMMAND --help" in result.output


def test_install_help_explains_instance_directory_and_preservation():
    from anteumbra.cli.main import cli

    result = CliRunner().invoke(cli, ["install", "--help"])

    assert result.exit_code == 0, result.output
    assert "INSTANCE_DIR" in result.output
    assert "does not install Python package code" in result.output
    assert "config.toml and .env files are always preserved" in result.output
    normalized = " ".join(result.output.split())
    assert "preserve config and .env" in normalized


def test_short_help_alias_is_available():
    from anteumbra.cli.main import cli

    result = CliRunner().invoke(cli, ["-h"])

    assert result.exit_code == 0, result.output
    assert "Commands:" in result.output
