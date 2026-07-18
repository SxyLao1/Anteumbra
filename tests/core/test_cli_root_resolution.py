def test_local_runtime_config_precedes_registered_install(monkeypatch, tmp_path):
    from anteumbra.infrastructure.config import install_registry
    from anteumbra.cli import main as cli_main

    local_runtime = tmp_path / "local-runtime"
    local_runtime.mkdir()
    (local_runtime / "config.toml").write_text("[web_admin]\nport = 8080\n", encoding="utf-8")
    registered = tmp_path / "registered-runtime"
    registered.mkdir()

    monkeypatch.chdir(local_runtime)
    monkeypatch.delenv("ANTEUMBRA_HOME", raising=False)
    monkeypatch.setattr(
        install_registry,
        "get_install_info",
        lambda: {"install_path": str(registered)},
    )

    assert cli_main._find_project_root() == local_runtime.resolve()
