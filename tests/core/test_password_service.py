"""Runtime-owned password and first-run secret tests."""

from __future__ import annotations

import os

from dotenv import dotenv_values
from werkzeug.security import check_password_hash


class _Config:
    def __init__(self, path, values):
        self.path = path
        self.values = values
        self.reload_count = 0

    def get(self):
        return self.values

    def reload(self):
        self.reload_count += 1
        return self.values


def test_first_run_adds_missing_secrets_without_overwriting_env(
    tmp_path,
    monkeypatch,
):
    from anteumbra.application.password_service import PasswordService

    config_path = tmp_path / "deployment" / "config.toml"
    config_path.parent.mkdir()
    config_path.write_text("[web_admin]\nport = 8080\n", encoding="utf-8")
    env_path = config_path.parent / ".env"
    env_path.write_text("CUSTOM_SETTING=preserved\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("ANTEUMBRA_PASSWORD_HASH", raising=False)
    monkeypatch.delenv("ANTEUMBRA_SECRET_KEY", raising=False)
    provider = _Config(
        config_path,
        {
            "web_admin": {"password_hash": ""},
            "security": {"secret_key": ""},
        },
    )

    generated = PasswordService(provider).ensure_initial_secrets()

    values = dotenv_values(env_path)
    assert generated is not None and len(generated) == 16
    assert values["CUSTOM_SETTING"] == "preserved"
    assert check_password_hash(values["ANTEUMBRA_PASSWORD_HASH"], generated)
    assert len(values["ANTEUMBRA_SECRET_KEY"]) >= 43
    assert os.environ["ANTEUMBRA_SECRET_KEY"] == values["ANTEUMBRA_SECRET_KEY"]
    assert provider.reload_count == 1


def test_valid_existing_secrets_are_not_rewritten(tmp_path):
    from anteumbra.application.password_service import PasswordService

    provider = _Config(
        tmp_path / "config.toml",
        {
            "web_admin": {"password_hash": "configured"},
            "security": {"secret_key": "persistent-secret"},
        },
    )

    assert PasswordService(provider).ensure_initial_secrets() is None
    assert provider.reload_count == 0
    assert not (tmp_path / ".env").exists()


def test_set_password_uses_config_directory_and_reloads_provider(
    tmp_path,
    monkeypatch,
):
    from anteumbra.application.password_service import PasswordService

    deployment = tmp_path / "deployment"
    elsewhere = tmp_path / "elsewhere"
    deployment.mkdir()
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    monkeypatch.delenv("ANTEUMBRA_PASSWORD_HASH", raising=False)
    provider = _Config(
        deployment / "config.toml",
        {
            "web_admin": {"password_hash": "old"},
            "security": {"secret_key": "persistent-secret"},
        },
    )
    service = PasswordService(provider)

    success, message = service.set_password("N3w!RuntimePass")

    assert success is True
    assert "active" in message
    stored_hash = dotenv_values(deployment / ".env")["ANTEUMBRA_PASSWORD_HASH"]
    assert check_password_hash(stored_hash, "N3w!RuntimePass")
    assert provider.reload_count == 1
    assert not (elsewhere / ".env").exists()


def test_set_password_is_visible_in_real_config_provider(tmp_path, monkeypatch):
    from anteumbra.application.password_service import PasswordService
    from anteumbra.infrastructure.config.provider import TomlConfigProvider

    site_path = tmp_path / "site"
    site_path.mkdir()
    config_path = tmp_path / "config.toml"
    config_path.write_text(
        "\n".join(
            (
                "[[website]]",
                'name = "Test"',
                f'path = "{site_path.as_posix()}"',
                "port = 80",
                "",
                "[web_admin]",
                'password_hash = "${ANTEUMBRA_PASSWORD_HASH:-old-hash}"',
                "",
                "[security]",
                'secret_key = "persistent-secret"',
            )
        ),
        encoding="utf-8",
    )
    (tmp_path / ".env").write_text(
        "ANTEUMBRA_PASSWORD_HASH=old-hash\n",
        encoding="utf-8",
    )
    monkeypatch.delenv("ANTEUMBRA_PASSWORD_HASH", raising=False)
    provider = TomlConfigProvider(config_path)

    success, _message = PasswordService(provider).set_password("N3w!RuntimePass")

    assert success is True
    current_hash = provider.get()["web_admin"]["password_hash"]
    assert current_hash != "old-hash"
    assert check_password_hash(current_hash, "N3w!RuntimePass")


def test_password_strength_rejects_common_and_patterned_values(tmp_path):
    from anteumbra.application.password_service import PasswordService

    service = PasswordService(_Config(tmp_path / "config.toml", {}))

    assert service.check_strength("password")[0] is False
    assert service.check_strength("Abc12345")[0] is False
    assert service.check_strength("AAA-secure-123")[0] is False
    assert service.check_strength("R7!fK2@pQ9")[0] is True
