"""Tests for instance-owned runtime configuration."""

from __future__ import annotations

from pathlib import Path

import pytest

from anteumbra.infrastructure.config.provider import (
    TomlConfigProvider,
    parse_websites,
    resolve_config_path,
)


def _write_config(
    path: Path,
    *,
    name: str,
    site_id: str | None = None,
    enabled: bool = True,
) -> None:
    path.write_text(
        "\n".join(
            (
                "[[website]]",
                f'id = "{site_id or name.lower()}"',
                f'name = "{name}"',
                f'path = "{path.parent.as_posix()}/{name.lower()}"',
                "port = 8080",
                f"enabled = {str(enabled).lower()}",
                "",
            )
        ),
        encoding="utf-8",
    )


def test_explicit_missing_config_does_not_fall_back(tmp_path, monkeypatch):
    fallback = tmp_path / "config.toml"
    _write_config(fallback, name="Fallback")
    monkeypatch.chdir(tmp_path)

    with pytest.raises(FileNotFoundError, match="does not exist"):
        resolve_config_path(tmp_path / "missing.toml")


def test_providers_have_independent_state(tmp_path):
    alpha_path = tmp_path / "alpha.toml"
    beta_path = tmp_path / "beta.toml"
    _write_config(alpha_path, name="Alpha")
    _write_config(beta_path, name="Beta")

    alpha = TomlConfigProvider(alpha_path)
    beta = TomlConfigProvider(beta_path)

    assert alpha.path == alpha_path.resolve()
    assert beta.path == beta_path.resolve()
    assert alpha.get_enabled_websites()[0].site_id == "alpha"
    assert beta.get_enabled_websites()[0].site_id == "beta"


def test_returned_values_cannot_mutate_provider_state(tmp_path):
    config_path = tmp_path / "config.toml"
    _write_config(config_path, name="Alpha")
    provider = TomlConfigProvider(config_path)

    values = provider.get()
    values["website"][0]["name"] = "Changed"
    websites = provider.get_websites()
    websites[0].name = "Changed"

    assert provider.get()["website"][0]["name"] == "Alpha"
    assert provider.get_websites()[0].name == "Alpha"


def test_reload_is_atomic_and_preserves_last_valid_snapshot(tmp_path):
    config_path = tmp_path / "config.toml"
    _write_config(config_path, name="Alpha")
    provider = TomlConfigProvider(config_path)

    _write_config(config_path, name="Beta")
    provider.reload()
    assert provider.generation == 2
    assert provider.get_enabled_websites()[0].site_id == "beta"

    config_path.write_text("not = [valid", encoding="utf-8")
    with pytest.raises(Exception):
        provider.reload()

    assert provider.generation == 2
    assert provider.get_enabled_websites()[0].site_id == "beta"


def test_disabled_sites_remain_addressable_but_not_resolvable(tmp_path):
    websites = parse_websites(
        {
            "website": [
                {
                    "id": "alpha",
                    "name": "Alpha",
                    "path": str(tmp_path / "alpha"),
                    "port": 80,
                    "enabled": False,
                },
                {
                    "id": "beta",
                    "name": "Beta",
                    "path": str(tmp_path / "beta"),
                    "port": 8080,
                    "enabled": True,
                },
            ]
        }
    )

    assert [site.site_id for site in websites] == ["alpha", "beta"]


def test_duplicate_site_ids_are_rejected(tmp_path):
    with pytest.raises(ValueError, match="Duplicate website.id"):
        parse_websites(
            {
                "website": [
                    {"id": "same", "name": "Alpha", "path": tmp_path / "a", "port": 80},
                    {"id": "same", "name": "Beta", "path": tmp_path / "b", "port": 81},
                ]
            }
        )


def test_site_rename_preserves_id_and_uses_current_configured_name(tmp_path):
    config_path = tmp_path / "config.toml"
    _write_config(config_path, name="Old Name", site_id="primary")
    provider = TomlConfigProvider(config_path)

    _write_config(config_path, name="New Name", site_id="primary")
    provider.reload()
    identity = provider.resolve_site_identity(
        tmp_path / "old-record.php",
        site_id="primary",
        site_name="Old Name",
    )

    assert identity.site_id == "primary"
    assert identity.site_name == "New Name"


def test_legacy_site_id_is_reserved_for_unassigned_records(tmp_path):
    with pytest.raises(ValueError, match="reserved for unassigned"):
        parse_websites(
            {
                "website": {
                    "id": "legacy",
                    "name": "Legacy Site",
                    "path": tmp_path / "legacy",
                    "port": 80,
                }
            }
        )
