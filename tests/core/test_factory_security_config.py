"""Web factory first-run secret persistence tests."""

import os


def test_first_run_adds_missing_secrets_without_overwriting_env(tmp_path, monkeypatch):
    from anteumbra.infrastructure.config.registry import ConfigRegistry
    from anteumbra.interfaces.web import factory

    config_path = tmp_path / "config.toml"
    config_path.write_text("[web_admin]\nport = 8080\n", encoding="utf-8")
    env_path = tmp_path / ".env"
    env_path.write_text("CUSTOM_SETTING=preserved\n", encoding="utf-8")

    monkeypatch.delenv("ANTEUMBRA_PASSWORD_HASH", raising=False)
    monkeypatch.delenv("ANTEUMBRA_SECRET_KEY", raising=False)
    monkeypatch.setattr(ConfigRegistry, "_config_path", config_path)
    monkeypatch.setattr(
        ConfigRegistry,
        "get_raw_config",
        classmethod(lambda cls: {
            "web_admin": {"password_hash": ""},
            "security": {"secret_key": ""},
        }),
    )
    monkeypatch.setattr(
        ConfigRegistry,
        "initialize",
        classmethod(lambda cls, *_args, **_kwargs: None),
    )

    factory._ensure_password_configured()

    env_text = env_path.read_text(encoding="utf-8")
    assert "CUSTOM_SETTING=preserved" in env_text
    assert "ANTEUMBRA_PASSWORD_HASH=" in env_text
    assert "ANTEUMBRA_SECRET_KEY=" in env_text
    assert "change_this_to_a_random_32_char_string" not in env_text
    assert len(os.environ["ANTEUMBRA_SECRET_KEY"]) >= 43
