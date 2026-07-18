from click.testing import CliRunner


def test_config_validate_rejects_invalid_proxy_network(tmp_path):
    from anteumbra.cli.main import cli

    site = tmp_path / "site"
    site.mkdir()
    config = tmp_path / "config.toml"
    config.write_text(
        """
[website]
name = "Site"
path = "site"
port = 80
enabled = true

[web_admin]
port = 8080
allowed_ips = ["127.0.0.1"]
trusted_proxy_ips = ["not-an-ip"]
""".strip(),
        encoding="utf-8",
    )

    result = CliRunner().invoke(cli, ["config", "validate", "--config", str(config)])

    assert result.exit_code != 0
    assert "trusted_proxy_ips contains an invalid IP/CIDR" in result.output
