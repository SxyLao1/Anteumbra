"""Deterministic RFC 6238 and persistence coverage for the single-admin TOTP service."""

from pathlib import Path

from anteumbra.application.totp_service import TotpService


class _Provider:
    def __init__(self, path: Path):
        self.path = path
        self._data = {"web_admin": {"username": "admin", "totp_enabled": False}}

    def get(self):
        import tomllib

        self._data = tomllib.loads(self.path.read_text(encoding="utf-8"))
        return self._data

    def reload(self):
        self.get()


def _provider(tmp_path: Path) -> _Provider:
    config = tmp_path / "config.toml"
    config.write_text(
        "[web_admin]\nusername='admin'\ntotp_enabled=false\n",
        encoding="utf-8",
    )
    return _Provider(config)


def test_rfc6238_known_vector_and_window():
    secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
    assert TotpService._counter_code(secret, 1_111_111_111 // 30) == "050471"
    assert TotpService.verify_code(secret, "050471", now=1_111_111_111)
    assert TotpService.verify_code(secret, "050471", now=1_111_111_140)
    assert not TotpService.verify_code(secret, "050471", now=1_111_111_200)


def test_enable_disable_persists_secret_only_in_env(tmp_path, monkeypatch):
    provider = _provider(tmp_path)
    service = TotpService(provider)
    secret = service.generate_secret()
    recovery = service.generate_recovery_codes()

    service.enable(secret, recovery)
    assert service.enabled is True
    assert service.secret == secret
    assert service.recovery_hashes == [service.recovery_hash(code) for code in recovery]
    assert "ANTEUMBRA_TOTP_SECRET" in (tmp_path / ".env").read_text(encoding="utf-8")
    assert secret not in (tmp_path / "config.toml").read_text(encoding="utf-8")
    assert "totp_enabled = true" in (tmp_path / "config.toml").read_text(encoding="utf-8")

    assert service.consume_recovery_code(recovery[0]) is True
    assert service.consume_recovery_code(recovery[0]) is False
    assert len(service.recovery_hashes) == len(recovery) - 1

    service.disable()
    assert service.enabled is False
    assert service.secret == ""
    assert service._config.get()["web_admin"]["totp_enabled"] is False
