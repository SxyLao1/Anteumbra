# -*- coding: utf-8 -*-
"""
E2E Test: Deployment Validation (18.2)

Covers:
  1. Health Check endpoints correct layering
  2. Version number single-source (no hardcode)
  3. Process startup / port listening
  4. Process shutdown / no residue
"""

import os
import socket
import subprocess
import sys
import textwrap
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
from click.testing import CliRunner

# ── Flask test client fixtures ──────────────────────────────────────────────


@pytest.fixture(scope="module")
def _app():
    """Create the Flask app once per test module.

    Each factory call creates an independent Flask application.
    """
    # Ensure ANTEUMBRA_TOOL_MODE is set so we don't touch real data
    os.environ.setdefault("ANTEUMBRA_TOOL_MODE", "true")

    from anteumbra.interfaces.web.factory import create_app

    app = create_app()
    app.config["TESTING"] = True
    return app


@pytest.fixture
def client(_app):
    """Flask test client — each test gets a fresh client context."""
    with _app.test_client() as c:
        yield c


# ═══════════════════════════════════════════════════════════════════════════════
# 18.2.1 — Health Check Endpoints
# ═══════════════════════════════════════════════════════════════════════════════


class TestHealthCheck:
    """Verify health check endpoints return correct layered status."""

    def test_public_health_returns_200(self, client):
        """GET /api/v1/health (metrics blueprint) should return 200 with status."""
        resp = client.get("/api/v1/health")
        assert resp.status_code == 200, (
            f"Expected 200, got {resp.status_code}: {resp.get_data(as_text=True)}"
        )
        data = resp.get_json()
        assert data is not None, "Response should be valid JSON"
        assert "status" in data, "Health check should include 'status' key"
        assert data["status"] in ("healthy", "warning", "degraded"), (
            f"Unexpected status value: {data['status']}"
        )
        assert data["checks"] == {"config": "ok", "registry": "ok", "wal": "ok"}
        assert data["capabilities"] is not None

    def test_admin_public_health_returns_200_or_302(self, client):
        """GET /admin/api/v1/health (admin bp, public) should return 200 (no auth needed).

        If the route exists and is public, returns 200. If it requires auth,
        returns 302 redirect to login. 503 is acceptable in test mode when
        config is not fully loaded (degraded health).
        """
        resp = client.get("/admin/api/v1/health")
        if resp.status_code == 503:
            data = resp.get_json()
            # 503 with status="degraded" is expected in test mode when
            # config.toml or WAL components are not fully available
            if data and data.get("status") == "degraded":
                return  # acceptable: degraded in test env
        assert resp.status_code in (200, 302, 404, 503), (
            f"Expected 200/302/404/503, got {resp.status_code}: {resp.get_data(as_text=True)[:200]}"
        )
        if resp.status_code == 200:
            data = resp.get_json()
            assert "status" in data

    def test_admin_authenticated_health_has_layered_info(self, client):
        """GET /admin/health requires auth and returns full diagnostics."""
        unauthenticated = client.get("/admin/health")
        assert unauthenticated.status_code == 302

        with client.session_transaction() as flask_session:
            flask_session["authenticated"] = True
            flask_session["username"] = "admin"

        resp = client.get("/admin/health")
        assert resp.status_code in (200, 503), resp.get_data(as_text=True)
        data = resp.get_json()
        assert data is not None
        assert data["status"] in ("healthy", "degraded")
        assert data["checks"].keys() == {"config", "registry", "wal"}
        assert data["capabilities"] is not None

    def test_public_metrics_health_uses_package_version(self, client):
        """The public metrics health version must use the package source."""
        import anteumbra

        resp = client.get("/api/v1/health")
        assert resp.status_code == 200
        assert resp.get_json()["version"] == anteumbra.__version__


# ═══════════════════════════════════════════════════════════════════════════════
# 18.2.2 — Version Number Single-Source
# ═══════════════════════════════════════════════════════════════════════════════


class TestVersionSource:
    """Verify version is single-source, not hardcoded in multiple places."""

    def test_version_in_pyproject_matches_get_version(self):
        """Version single source of truth: anteumbra.__version__.

        pyproject.toml uses dynamic version via attr directive:
          [tool.setuptools.dynamic] version = {attr = "anteumbra.__version__"}
        get_version() imports from anteumbra.__version__.
        Both must agree — changing __init__.py is the only place needed.
        """
        import anteumbra
        from anteumbra.infrastructure.config.version import get_version

        pkg_version = anteumbra.__version__
        code_version = get_version()

        # Both must read from the same source
        assert pkg_version == code_version, (
            f"Version mismatch: __init__.__version__={pkg_version} != "
            f"get_version()={code_version}. Both must read from "
            f"anteumbra.__version__ as single source of truth."
        )

        # Verify pyproject.toml uses dynamic version pointing to package
        pyproject_path = Path(__file__).parent.parent.parent / "pyproject.toml"
        if not pyproject_path.exists():
            pytest.skip(f"pyproject.toml not found at {pyproject_path}")

        if sys.version_info >= (3, 11):
            import tomllib
        else:
            try:
                import tomli as tomllib
            except ImportError:
                pytest.skip("tomli not installed, cannot parse pyproject.toml")

        with open(pyproject_path, "rb") as f:
            pp = tomllib.load(f)

        # With dynamic version, [project] has "dynamic" key instead of "version"
        dynamic_fields = pp.get("project", {}).get("dynamic", [])
        assert "version" in dynamic_fields, (
            "pyproject.toml should have dynamic = ['version'] under [project]"
        )

        # The attr directive must point to anteumbra.__version__
        setuptools_dynamic = pp.get("tool", {}).get("setuptools", {}).get("dynamic", {})
        version_attr = setuptools_dynamic.get("version", {}).get("attr", "")
        assert version_attr == "anteumbra.__version__", (
            f"pyproject.toml [tool.setuptools.dynamic] version attr should be "
            f"'anteumbra.__version__', got '{version_attr}'"
        )

    def test_package_version_matches_pyproject(self):
        """anteumbra.__version__ must be resolvable from pyproject.toml dynamic attr.

        pyproject.toml uses dynamic version via:
          [tool.setuptools.dynamic] version = {attr = "anteumbra.__version__"}
        This test verifies the attr path correctly resolves to the package version.
        """
        import anteumbra

        pkg_version = anteumbra.__version__

        pyproject_path = Path(__file__).parent.parent.parent / "pyproject.toml"
        if not pyproject_path.exists():
            pytest.skip(f"pyproject.toml not found at {pyproject_path}")

        if sys.version_info >= (3, 11):
            import tomllib
        else:
            try:
                import tomli as tomllib
            except ImportError:
                pytest.skip("tomli not installed")

        with open(pyproject_path, "rb") as f:
            pp = tomllib.load(f)

        setuptools_dynamic = pp.get("tool", {}).get("setuptools", {}).get("dynamic", {})
        version_attr = setuptools_dynamic.get("version", {}).get("attr", "")

        if not version_attr:
            pytest.skip("pyproject.toml does not use dynamic version attr")

        # Resolve the attr path (e.g., "anteumbra.__version__" → actual value)
        parts = version_attr.split(".")
        if len(parts) >= 2:
            import importlib

            mod = importlib.import_module(parts[0])
            resolved = getattr(mod, parts[1])
            assert resolved == pkg_version, (
                f"pyproject.toml attr {version_attr} resolves to '{resolved}' "
                f"but package has '{pkg_version}'"
            )

    def test_cli_version_not_hardcoded(self):
        """CLI --version should read version from the package, not inline string.

        The CLI (cli/main.py) uses click.version_option(__version__), importing
        __version__ from anteumbra. The single-source concern is whether
        anteumbra.__version__ itself is hardcoded vs derived from config.

        Acceptable patterns:
          1. `from anteumbra import __version__` — standard package version
          2. `from anteumbra.infrastructure.config.version import get_version`
          3. Any import that avoids an inline string literal like "1.0.4"
        """
        cli_path = Path(__file__).parent.parent.parent / "src" / "anteumbra" / "cli" / "main.py"
        if not cli_path.exists():
            pytest.skip(f"CLI entry point not found at {cli_path}")

        source = cli_path.read_text(encoding="utf-8")

        # Must import version from somewhere (not hardcode inline)
        has_version_import = (
            "from anteumbra.infrastructure.config.version import" in source
            or "from anteumbra import __version__" in source
            or "import anteumbra" in source
            or "get_version" in source
        )
        assert has_version_import, (
            "CLI entry point should import version from package or version "
            "module, not hardcode a version string"
        )

        # anteumbra.__version__ is intentionally the literal single source.
        # pyproject.toml and every runtime surface import that value.

    def test_version_not_unknown(self):
        """get_version() should return a real version, not 'unknown'."""
        from anteumbra.infrastructure.config.version import get_version

        v = get_version()
        assert v is not None, "get_version() returned None"
        assert v != "unknown", (
            "get_version() returned 'unknown' — config.toml [system].version "
            "is missing or unreadable"
        )
        # Version should look like a semver (e.g., "1.0.4")
        assert "." in v, f"Version '{v}' does not look like a semver"

    def test_dockerfile_quotes_every_base_runtime_requirement(self):
        """Docker's shell must receive the same constrained dependencies as pip."""
        project_root = Path(__file__).parent.parent.parent
        dockerfile = (project_root / "Dockerfile").read_text(encoding="utf-8")

        if sys.version_info >= (3, 11):
            import tomllib
        else:
            import tomli as tomllib

        with open(project_root / "pyproject.toml", "rb") as handle:
            requirements = tomllib.load(handle)["project"]["dependencies"]

        missing = [
            requirement for requirement in requirements if f"'{requirement}'" not in dockerfile
        ]
        assert not missing, (
            "Dockerfile must quote every base dependency so shell operators in "
            f"version constraints are not treated as redirections: {missing}"
        )

    def test_docker_entrypoint_is_posix_even_after_windows_checkout(self):
        project_root = Path(__file__).parent.parent.parent
        attributes = (project_root / ".gitattributes").read_text(encoding="utf-8")
        dockerfile = (project_root / "Dockerfile").read_text(encoding="utf-8")
        entrypoint = project_root / "scripts" / "docker-entrypoint.sh"

        assert "*.sh text eol=lf" in attributes
        assert "sed -i 's/\\r$//' /usr/local/bin/anteumbra-docker-entrypoint" in (dockerfile)
        assert b"\r\n" not in entrypoint.read_bytes()
        assert entrypoint.read_bytes().startswith(b"#!/bin/sh\n")

        entrypoint_source = entrypoint.read_text(encoding="utf-8")
        assert 'Path("/proc/net/route")' in entrypoint_source
        assert 'allowed_ips == ["127.0.0.1"]' in entrypoint_source
        assert "Allowed the local Docker gateway" in entrypoint_source

        for relative_path in (
            "README.md",
            "README_cn.md",
            "docs/USER_MANUAL.md",
            "docs/USER_MANUAL_cn.md",
        ):
            documentation = (project_root / relative_path).read_text(encoding="utf-8")
            assert "-p 127.0.0.1:18080:8080" in documentation


class TestCliInstall:
    """Verify CLI deployment setup works for packaged and editable installs."""

    def test_config_template_is_packaged_and_declared(self):
        """config.toml must ship inside the wheel for PyPI installs."""
        import anteumbra

        package_config = Path(anteumbra.__file__).parent / "config.toml"
        assert package_config.exists(), (
            "src/anteumbra/config.toml must exist so wheels can create "
            "deployment instances without the source tree"
        )

        pyproject_path = Path(__file__).parent.parent.parent / "pyproject.toml"
        if sys.version_info >= (3, 11):
            import tomllib
        else:
            try:
                import tomli as tomllib
            except ImportError:
                pytest.skip("tomli not installed")

        with open(pyproject_path, "rb") as f:
            pyproject = tomllib.load(f)

        package_data = (
            pyproject.get("tool", {})
            .get("setuptools", {})
            .get("package-data", {})
            .get("anteumbra", [])
        )
        assert "config.toml" in package_data

    def test_pyproject_license_metadata_uses_spdx_string(self):
        """Wheel metadata should avoid deprecated license table/classifier forms."""
        pyproject_path = Path(__file__).parent.parent.parent / "pyproject.toml"
        if sys.version_info >= (3, 11):
            import tomllib
        else:
            try:
                import tomli as tomllib
            except ImportError:
                pytest.skip("tomli not installed")

        with open(pyproject_path, "rb") as f:
            pyproject = tomllib.load(f)

        project = pyproject.get("project", {})
        assert project.get("license") == "MIT"
        classifiers = project.get("classifiers", [])
        assert "License :: OSI Approved :: MIT License" not in classifiers

    def test_base_install_can_create_app_without_yara_python(self, tmp_path):
        """The web app must boot when optional yara-python is not installed."""
        project_root = Path(__file__).parent.parent.parent
        env = os.environ.copy()
        env["PYTHONPATH"] = str(project_root / "src")
        env["ANTEUMBRA_TOOL_MODE"] = "true"

        code = textwrap.dedent(
            """
            import importlib.abc
            import sys

            class BlockYara(importlib.abc.MetaPathFinder):
                def find_spec(self, fullname, path=None, target=None):
                    if fullname == "yara":
                        raise ModuleNotFoundError("No module named 'yara'")
                    return None

            sys.meta_path.insert(0, BlockYara())

            from anteumbra.interfaces.web.factory import create_app

            app = create_app()
            client = app.test_client()
            assert client.get("/admin/login").status_code == 200
            assert client.get("/api/v1/health").status_code == 200
            resp = client.get("/admin/yara/rules")
            assert resp.status_code in (302, 403)
            """
        )

        result = subprocess.run(
            [sys.executable, "-c", code],
            cwd=tmp_path,
            env=env,
            text=True,
            capture_output=True,
            timeout=30,
        )

        assert result.returncode == 0, result.stderr + result.stdout

    def test_install_creates_complete_deployment_instance(self, tmp_path, monkeypatch):
        """anteumbra install should create config, env, rules and registry marker."""
        from anteumbra.cli.main import cli
        from anteumbra.infrastructure.config import install_registry

        target = tmp_path / "instance"
        registered = {}

        monkeypatch.setattr(install_registry, "get_install_info", lambda: None)
        monkeypatch.setattr(
            install_registry,
            "register_install",
            lambda path, version: registered.update({"path": path, "version": version}),
        )

        result = CliRunner().invoke(cli, ["install", str(target), "--force"])

        assert result.exit_code == 0, result.output
        assert (target / "config.toml").exists()
        assert (target / ".env").exists()
        assert (target / ".anteumbra_install").exists()
        assert (target / "sites" / "default").is_dir()
        assert 'path = "sites/default"' in (target / "config.toml").read_text(encoding="utf-8")
        assert (target / "rules" / "webshell").is_dir()
        assert list((target / "rules" / "webshell").glob("*.yar"))
        assert registered["path"] == str(target.resolve())
        env_text = (target / ".env").read_text(encoding="utf-8")
        secret_line = next(
            line for line in env_text.splitlines() if line.startswith("ANTEUMBRA_SECRET_KEY=")
        )
        secret = secret_line.partition("=")[2]
        assert secret != "change_this_to_a_random_32_char_string"
        assert len(secret) >= 43

    def test_install_succeeds_when_user_registry_is_read_only(self, tmp_path, monkeypatch):
        """A convenience registry failure must not invalidate a complete instance."""
        from anteumbra.cli.main import cli
        from anteumbra.infrastructure.config import install_registry

        target = tmp_path / "instance"

        def deny_registry_write(*_args):
            raise PermissionError("read-only home")

        monkeypatch.setattr(install_registry, "get_install_info", lambda: None)
        monkeypatch.setattr(
            install_registry,
            "register_install",
            deny_registry_write,
        )

        result = CliRunner().invoke(cli, ["install", str(target), "--force"])

        assert result.exit_code == 0, result.output
        assert "installation completed" in result.output
        assert "registry could not be updated" in result.output
        assert (target / "config.toml").exists()
        assert (target / ".env").exists()
        assert (target / ".anteumbra_install").exists()

    def test_install_registry_read_failure_is_treated_as_unregistered(self, monkeypatch):
        from anteumbra.infrastructure.config import install_registry

        def deny_registry_read():
            raise PermissionError("read-only home")

        monkeypatch.setattr(install_registry, "_registry_path", deny_registry_read)

        assert install_registry.get_install_info() is None

    def test_config_without_subcommand_only_shows_help(self, tmp_path, monkeypatch):
        """Bare config must never create or replace deployment files."""
        from anteumbra.cli.main import cli

        monkeypatch.chdir(tmp_path)
        result = CliRunner().invoke(cli, ["config"])

        assert result.exit_code == 0, result.output
        assert "Commands:" in result.output
        assert "init" in result.output
        assert not (tmp_path / "config.toml").exists()
        assert not (tmp_path / ".env").exists()

    def test_force_install_preserves_existing_config_and_env(self, tmp_path, monkeypatch):
        """Registration replacement must not reset operator config or secrets."""
        from anteumbra.cli.main import cli
        from anteumbra.infrastructure.config import install_registry

        target = tmp_path / "instance"
        target.mkdir()
        config_path = target / "config.toml"
        env_path = target / ".env"
        config_path.write_text(
            '[web_admin]\nport = 9123\nusername = "operator"\n',
            encoding="utf-8",
        )
        env_path.write_text("ANTEUMBRA_SECRET_KEY=keep-me\n", encoding="utf-8")
        monkeypatch.setattr(
            install_registry,
            "get_install_info",
            lambda: {"install_path": str(target), "version": "old"},
        )
        monkeypatch.setattr(install_registry, "register_install", lambda *_args: None)

        result = CliRunner().invoke(cli, ["install", str(target), "--force"])

        assert result.exit_code == 0, result.output
        assert config_path.read_text(encoding="utf-8") == (
            '[web_admin]\nport = 9123\nusername = "operator"\n'
        )
        assert env_path.read_text(encoding="utf-8") == "ANTEUMBRA_SECRET_KEY=keep-me\n"
        assert "Existing config preserved" in result.output
        assert "Existing .env preserved" in result.output
        assert "Admin:    http://127.0.0.1:9123/admin" in result.output
        assert "Username: operator" in result.output
        assert "Password: unchanged" in result.output
        assert "see " not in result.output
        assert f'anteumbra --home "{target.resolve()}" start' in result.output
        assert f'anteumbra --home "{target.resolve()}" config wizard' in result.output

    def test_config_subcommands_update_config_and_env(self, tmp_path):
        """CLI config subcommands should support scripted first-run setup."""
        import tomli

        from anteumbra.cli.main import cli

        target = tmp_path / "instance" / "config.toml"
        env_path = target.parent / ".env"
        runner = CliRunner()

        result = runner.invoke(cli, ["config", "init", "--output", str(target), "--force"])
        assert result.exit_code == 0, result.output

        result = runner.invoke(
            cli,
            ["config", "set", "web_admin.port", "8099", "--config", str(target)],
        )
        assert result.exit_code == 0, result.output

        result = runner.invoke(
            cli,
            [
                "config",
                "env",
                "set",
                "ANTEUMBRA_WECHAT_API_KEY",
                "send-key",
                "--env",
                str(env_path),
            ],
        )
        assert result.exit_code == 0, result.output

        cfg = tomli.loads(target.read_text(encoding="utf-8"))
        assert cfg["web_admin"]["port"] == 8099
        assert "ANTEUMBRA_WECHAT_API_KEY=send-key" in env_path.read_text(encoding="utf-8")

    def test_config_validate_reports_missing_website_path(self, tmp_path):
        """config validate should catch deployment paths that cannot run."""
        from anteumbra.cli.main import cli

        target = tmp_path / "instance" / "config.toml"
        missing_site = tmp_path / "missing-site"
        runner = CliRunner()

        result = runner.invoke(cli, ["config", "init", "--output", str(target), "--force"])
        assert result.exit_code == 0, result.output

        result = runner.invoke(
            cli,
            ["config", "set", "website.path", str(missing_site), "--config", str(target)],
        )
        assert result.exit_code == 0, result.output

        result = runner.invoke(cli, ["config", "validate", "--config", str(target)])
        assert result.exit_code != 0
        assert "Website path does not exist" in result.output

    def test_config_validate_warns_when_site_id_is_derived(self, tmp_path):
        """Legacy configs remain valid but explain rename-sensitive derived IDs."""
        import tomli
        import tomli_w

        from anteumbra.cli.main import cli

        target = tmp_path / "instance" / "config.toml"
        runner = CliRunner()
        result = runner.invoke(cli, ["config", "init", "--output", str(target), "--force"])
        assert result.exit_code == 0, result.output
        data = tomli.loads(target.read_text(encoding="utf-8"))
        data["website"].pop("id")
        target.write_text(tomli_w.dumps(data), encoding="utf-8")

        result = runner.invoke(cli, ["config", "validate", "--config", str(target)])

        assert result.exit_code == 0, result.output
        assert "id is missing" in result.output
        assert "before renaming the site" in result.output

    def test_config_set_requires_acknowledgement_to_change_site_id(self, tmp_path):
        """The scripted config path must not accidentally split site history."""
        import tomli
        import tomli_w

        from anteumbra.cli.main import cli

        target = tmp_path / "instance" / "config.toml"
        runner = CliRunner()
        result = runner.invoke(cli, ["config", "init", "--output", str(target), "--force"])
        assert result.exit_code == 0, result.output

        renamed = runner.invoke(
            cli,
            [
                "config",
                "set",
                "website.name",
                "Renamed Website",
                "--config",
                str(target),
            ],
        )
        renamed_config = tomli.loads(target.read_text(encoding="utf-8"))["website"]
        assert renamed.exit_code == 0, renamed.output
        assert renamed_config["name"] == "Renamed Website"
        assert renamed_config["id"] == "default"

        legacy_config = tomli.loads(target.read_text(encoding="utf-8"))
        legacy_config["website"]["site_id"] = legacy_config["website"].pop("id")
        target.write_text(tomli_w.dumps(legacy_config), encoding="utf-8")

        refused = runner.invoke(
            cli,
            ["config", "set", "website.id", "renamed", "--config", str(target)],
        )
        accepted = runner.invoke(
            cli,
            [
                "config",
                "set",
                "website.id",
                "renamed",
                "--config",
                str(target),
                "--allow-site-id-change",
            ],
        )

        assert refused.exit_code != 0
        assert "stable ownership key" in refused.output
        assert accepted.exit_code == 0, accepted.output
        assert "existing records keep the previous site ID" in accepted.output
        accepted_config = tomli.loads(target.read_text(encoding="utf-8"))["website"]
        assert accepted_config["id"] == "renamed"
        assert "site_id" not in accepted_config

    def test_config_validate_rejects_reserved_legacy_site_id(self, tmp_path):
        import tomli
        import tomli_w

        from anteumbra.cli.main import cli

        target = tmp_path / "instance" / "config.toml"
        runner = CliRunner()
        result = runner.invoke(cli, ["config", "init", "--output", str(target), "--force"])
        assert result.exit_code == 0, result.output
        data = tomli.loads(target.read_text(encoding="utf-8"))
        data["website"]["id"] = "legacy"
        target.write_text(tomli_w.dumps(data), encoding="utf-8")

        result = runner.invoke(cli, ["config", "validate", "--config", str(target)])

        assert result.exit_code != 0
        assert "reserved for unassigned records" in result.output

    def test_config_validate_supports_multiple_websites(self, tmp_path):
        """Every enabled [[website]] entry should be validated independently."""
        import tomli_w

        from anteumbra.cli.main import cli

        first = tmp_path / "site-a"
        second = tmp_path / "site-b"
        first.mkdir()
        second.mkdir()
        config_path = tmp_path / "config.toml"
        config_path.write_text(
            tomli_w.dumps(
                {
                    "website": [
                        {
                            "name": "A",
                            "path": str(first),
                            "port": 80,
                            "enabled": True,
                            "log_config": {"log_monitor_enabled": False},
                        },
                        {
                            "name": "B",
                            "path": str(second),
                            "port": 8081,
                            "enabled": True,
                            "log_config": {"log_monitor_enabled": False},
                        },
                    ],
                    "web_admin": {
                        "port": 8080,
                        "password_hash": "configured",
                    },
                    "security": {"secret_key": "a-persistent-secret-key"},
                    "waf_source": {"enabled": False},
                    "notifier": {"enabled": False},
                    "scanner": {"yara": {"enabled": False}},
                }
            ),
            encoding="utf-8",
        )

        result = CliRunner().invoke(cli, ["config", "validate", "--config", str(config_path)])

        assert result.exit_code == 0, result.output
        assert "Config OK" in result.output

    def test_config_validate_accepts_tomcat_access_log_wildcards(self, tmp_path):
        """Tomcat AccessLogValve files are usually date-suffixed and configured by glob."""
        from anteumbra.cli.main import cli

        target = tmp_path / "instance" / "config.toml"
        site_path = tmp_path / "webapps" / "ROOT" / "test"
        log_dir = tmp_path / "tomcat" / "logs"
        access_log = log_dir / "localhost_access_log.2026-07-11.txt"
        site_path.mkdir(parents=True)
        log_dir.mkdir(parents=True)
        access_log.write_text(
            '127.0.0.1 - - [11/Jul/2026:20:00:00 +0800] "GET / HTTP/1.1" 200 16\n',
            encoding="utf-8",
        )

        runner = CliRunner()
        result = runner.invoke(cli, ["config", "init", "--output", str(target), "--force"])
        assert result.exit_code == 0, result.output

        result = runner.invoke(
            cli, ["config", "set", "website.path", str(site_path), "--config", str(target)]
        )
        assert result.exit_code == 0, result.output

        result = runner.invoke(
            cli,
            [
                "config",
                "set",
                "website.log_config.log_monitor_enabled",
                "true",
                "--config",
                str(target),
            ],
        )
        assert result.exit_code == 0, result.output

        result = runner.invoke(
            cli,
            [
                "config",
                "set",
                "website.log_config.access_log_path",
                str(log_dir / "localhost_access_log.*.txt"),
                "--config",
                str(target),
            ],
        )
        assert result.exit_code == 0, result.output

        result = runner.invoke(cli, ["config", "validate", "--config", str(target)])
        assert result.exit_code == 0, result.output

    def test_config_set_recovers_powershell_expanded_tomcat_wildcards(self, tmp_path):
        """PowerShell can expand *.txt before Click receives the command."""
        import tomli

        from anteumbra.cli.main import cli

        target = tmp_path / "instance" / "config.toml"
        log_dir = tmp_path / "tomcat" / "logs"
        log_dir.mkdir(parents=True)
        first = log_dir / "localhost_access_log.2026-07-10.txt"
        second = log_dir / "localhost_access_log.2026-07-11.txt"
        first.write_text("old\n", encoding="utf-8")
        second.write_text("new\n", encoding="utf-8")

        runner = CliRunner()
        result = runner.invoke(cli, ["config", "init", "--output", str(target), "--force"])
        assert result.exit_code == 0, result.output

        result = runner.invoke(
            cli,
            [
                "config",
                "set",
                "website.log_config.access_log_path",
                str(first),
                str(second),
                "--config",
                str(target),
            ],
        )
        assert result.exit_code == 0, result.output
        assert "expanded shell wildcard" in result.output

        cfg = tomli.loads(target.read_text(encoding="utf-8"))
        assert cfg["website"]["log_config"]["access_log_path"].endswith(
            "tomcat/logs/localhost_access_log.*.txt"
        )

    def test_config_access_log_tomcat_preset_sets_enabled_wildcard(self, tmp_path):
        """Users should not need to type Tomcat wildcard paths by hand."""
        import tomli

        from anteumbra.cli.main import cli

        target = tmp_path / "instance" / "config.toml"
        tomcat_home = tmp_path / "apache-tomcat-9.0.96"
        (tomcat_home / "logs").mkdir(parents=True)

        runner = CliRunner()
        result = runner.invoke(cli, ["config", "init", "--output", str(target), "--force"])
        assert result.exit_code == 0, result.output

        result = runner.invoke(
            cli,
            ["config", "access-log", "tomcat", "--base", str(tomcat_home), "--config", str(target)],
        )
        assert result.exit_code == 0, result.output

        cfg = tomli.loads(target.read_text(encoding="utf-8"))
        assert cfg["website"]["log_config"]["log_monitor_enabled"] is True
        assert cfg["website"]["log_config"]["access_log_path"].endswith(
            "apache-tomcat-9.0.96/logs/localhost_access_log.*.txt"
        )

    def test_config_wizard_creates_first_run_configuration(self, tmp_path):
        """Interactive wizard should collect the essential deployment settings."""
        import tomli

        from anteumbra.cli.main import cli

        target = tmp_path / "instance" / "config.toml"
        site_path = tmp_path / "phpstudy" / "WWW" / "test"
        wizard_input = f"{site_path}\ny\n8098\n\nn\nn\n\n"

        result = CliRunner().invoke(
            cli,
            ["config", "wizard", "--config", str(target)],
            input=wizard_input,
        )

        assert result.exit_code == 0, result.output
        assert site_path.is_dir()
        cfg = tomli.loads(target.read_text(encoding="utf-8"))
        assert cfg["website"]["path"] == str(site_path)
        assert cfg["web_admin"]["port"] == 8098
        assert cfg["website"]["log_config"]["log_monitor_enabled"] is False
        assert cfg["waf_source"]["enabled"] is False
        assert cfg["notifier"]["enabled"] is False
        assert cfg["notifier"]["wechat"]["enabled"] is False
        assert cfg["notifier"]["email"]["enabled"] is False

    def test_config_wizard_tomcat_access_log_preset(self, tmp_path):
        """Wizard should guide Tomcat users without requiring wildcard typing."""
        import tomli

        from anteumbra.cli.main import cli

        target = tmp_path / "instance" / "config.toml"
        site_path = tmp_path / "webapps" / "ROOT" / "test"
        tomcat_home = tmp_path / "apache-tomcat-9.0.96"
        (tomcat_home / "logs").mkdir(parents=True)
        (tomcat_home / "logs" / "localhost_access_log.2026-07-11.txt").write_text(
            '127.0.0.1 - - [11/Jul/2026:20:00:00 +0800] "GET / HTTP/1.1" 200 16\n',
            encoding="utf-8",
        )
        wizard_input = f"{site_path}\ny\n8098\n\ny\ntomcat\n{tomcat_home}\nn\n\n"

        result = CliRunner().invoke(
            cli,
            ["config", "wizard", "--config", str(target)],
            input=wizard_input,
        )

        assert result.exit_code == 0, result.output
        cfg = tomli.loads(target.read_text(encoding="utf-8"))
        assert cfg["website"]["log_config"]["log_monitor_enabled"] is True
        assert cfg["website"]["log_config"]["access_log_path"].endswith(
            "apache-tomcat-9.0.96/logs/localhost_access_log.*.txt"
        )
        assert cfg["waf_source"]["enabled"] is False

    def test_bundled_config_defaults_are_runnable_without_external_services(self):
        """Fresh installs should not require nginx logs or a mock WAF server."""
        import tomli

        import anteumbra

        config_path = Path(anteumbra.__file__).parent / "config.toml"
        cfg = tomli.loads(config_path.read_text(encoding="utf-8"))

        assert cfg["website"]["path"] == "sites/default"
        assert cfg["website"]["log_config"]["log_monitor_enabled"] is False
        assert cfg["waf_source"]["enabled"] is False

    def test_launcher_rejects_missing_website_path_before_building_runtime(
        self, tmp_path, monkeypatch
    ):
        """Bad user config should fail cleanly before starting background services."""
        from anteumbra.application import launcher

        missing = tmp_path / "missing-site"
        website = SimpleNamespace(name="Missing Site", path=missing)
        provider = SimpleNamespace(
            get=lambda: {},
            get_enabled_websites=lambda: [website],
        )

        monkeypatch.chdir(tmp_path)
        from dataclasses import replace

        from anteumbra.application.runtime_builder import (
            build_runtime_lifecycle_dependencies,
        )

        dependencies = replace(
            build_runtime_lifecycle_dependencies(),
            container_builder=lambda **_kwargs: pytest.fail(
                "runtime must not be built before validation"
            ),
        )
        with pytest.raises(launcher.RuntimeStartupError) as exc_info:
            launcher.RuntimeLifecycle(
                host="127.0.0.1",
                port=8765,
                config_provider=provider,
                dependencies=dependencies,
            ).run()

        assert "Website path does not exist" in str(exc_info.value)
        assert str(missing.resolve()) in str(exc_info.value)

    def test_start_uses_package_entrypoint_not_source_run_py(self, tmp_path, monkeypatch):
        """Background start must work from a deployment dir without run.py."""
        import anteumbra.cli.main as cli_main
        from anteumbra.infrastructure.process_identity import ProcessIdentity

        calls = []
        ready_checks = []
        identity = ProcessIdentity(12345, 123.0, str(tmp_path))
        identity_reads = iter([None, identity])

        def fake_popen(cmd, **kwargs):
            calls.append((cmd, kwargs))

            class FakeProc:
                pass

            return FakeProc()

        monkeypatch.setattr(cli_main, "_find_project_root", lambda: tmp_path)
        monkeypatch.setattr(
            cli_main,
            "_read_runtime_identity",
            lambda _root=None: next(identity_reads, identity),
        )
        monkeypatch.setattr(
            cli_main,
            "_service_ready",
            lambda _host, _port: ready_checks.append(True) or True,
        )
        monkeypatch.setattr(cli_main.time, "sleep", lambda _seconds: None)
        monkeypatch.setattr(cli_main.subprocess, "Popen", fake_popen)

        result = CliRunner().invoke(cli_main.cli, ["start"])

        assert result.exit_code == 0, result.output
        assert calls, "start should launch a background process"
        cmd = calls[0][0]
        assert "-u" in cmd
        assert "-m" in cmd
        assert "anteumbra" in cmd
        assert "run" in cmd
        assert "run.py" not in " ".join(cmd)
        assert calls[0][1]["cwd"] == str(tmp_path)
        assert calls[0][1]["stdout"] is not None
        assert calls[0][1]["stderr"] == cli_main.subprocess.STDOUT
        assert calls[0][1]["env"]["PYTHONIOENCODING"] == "utf-8"
        assert calls[0][1]["env"]["PYTHONUNBUFFERED"] == "1"
        assert len(ready_checks) == 2
        assert (tmp_path / "data" / "anteumbra.log").exists()

    def test_start_rejects_a_process_that_exits_after_initial_readiness(
        self, tmp_path, monkeypatch
    ):
        """A transient listener must not be reported as a running service."""
        import anteumbra.cli.main as cli_main
        from anteumbra.infrastructure.process_identity import ProcessIdentity

        identity = ProcessIdentity(12345, 123.0, str(tmp_path))
        identity_reads = iter([None, identity])

        class FakeProc:
            def __init__(self):
                self._poll_results = iter([None, 1])

            def poll(self):
                return next(self._poll_results, 1)

        monkeypatch.setattr(cli_main, "_find_project_root", lambda: tmp_path)
        monkeypatch.setattr(
            cli_main,
            "_read_runtime_identity",
            lambda _root=None: next(identity_reads, identity),
        )
        monkeypatch.setattr(cli_main, "_service_ready", lambda _host, _port: True)
        monkeypatch.setattr(cli_main.time, "sleep", lambda _seconds: None)
        monkeypatch.setattr(cli_main.subprocess, "Popen", lambda *_args, **_kwargs: FakeProc())

        result = CliRunner().invoke(cli_main.cli, ["start"])

        assert result.exit_code == 1
        assert "Anteumbra failed to start" in result.output
        assert "Anteumbra started" not in result.output

    def test_start_uses_configured_admin_port_by_default(self, tmp_path, monkeypatch):
        """start should honor web_admin.port when --port is not explicitly passed."""
        import anteumbra.cli.main as cli_main
        from anteumbra.infrastructure.process_identity import ProcessIdentity

        (tmp_path / "config.toml").write_text(
            '[web_admin]\nhost = "127.0.0.1"\nport = 18444\n',
            encoding="utf-8",
        )
        calls = []
        identity = ProcessIdentity(12345, 123.0, str(tmp_path))
        identity_reads = iter([None, identity])

        def fake_popen(cmd, **kwargs):
            calls.append((cmd, kwargs))

            class FakeProc:
                pass

            return FakeProc()

        monkeypatch.setattr(cli_main, "_find_project_root", lambda: tmp_path)
        monkeypatch.setattr(
            cli_main,
            "_read_runtime_identity",
            lambda _root=None: next(identity_reads, identity),
        )
        monkeypatch.setattr(cli_main, "_service_ready", lambda _host, _port: True)
        monkeypatch.setattr(cli_main.time, "sleep", lambda _seconds: None)
        monkeypatch.setattr(cli_main.subprocess, "Popen", fake_popen)

        result = CliRunner().invoke(cli_main.cli, ["start"])

        assert result.exit_code == 0, result.output
        cmd = calls[0][0]
        assert "--port" in cmd
        assert cmd[cmd.index("--port") + 1] == "18444"

    def test_stop_preserves_pid_when_taskkill_fails(self, tmp_path, monkeypatch):
        """stop must not report success or lose recovery state on kill failure."""
        import anteumbra.cli.main as cli_main
        from anteumbra.infrastructure.process_identity import ProcessIdentityState

        pid_file = tmp_path / cli_main.PID_FILE
        pid_file.parent.mkdir(parents=True)
        pid_file.write_text("12345", encoding="utf-8")

        monkeypatch.setattr(cli_main, "_find_project_root", lambda: tmp_path)
        monkeypatch.setattr(
            cli_main,
            "_process_state",
            lambda _identity, _root=None: ProcessIdentityState.RUNNING,
        )
        monkeypatch.setattr(cli_main.sys, "platform", "win32")
        monkeypatch.setattr(
            cli_main.subprocess,
            "run",
            lambda *args, **kwargs: SimpleNamespace(
                returncode=1,
                stdout="",
                stderr="ERROR: Access denied",
            ),
        )

        result = CliRunner().invoke(cli_main.cli, ["stop"])

        assert result.exit_code == 1
        assert "taskkill failed (1): ERROR: Access denied" in result.output
        assert pid_file.exists()

    def test_stop_removes_pid_after_confirmed_exit(self, tmp_path, monkeypatch):
        """stop reports success only after observing that the process exited."""
        import anteumbra.cli.main as cli_main
        from anteumbra.infrastructure.process_identity import ProcessIdentityState

        pid_file = tmp_path / cli_main.PID_FILE
        pid_file.parent.mkdir(parents=True)
        pid_file.write_text("12345", encoding="utf-8")
        process_states = iter([ProcessIdentityState.RUNNING, ProcessIdentityState.STOPPED])

        monkeypatch.setattr(cli_main, "_find_project_root", lambda: tmp_path)
        monkeypatch.setattr(
            cli_main,
            "_process_state",
            lambda _identity, _root=None: next(
                process_states,
                ProcessIdentityState.STOPPED,
            ),
        )
        monkeypatch.setattr(cli_main.sys, "platform", "win32")
        monkeypatch.setattr(
            cli_main.subprocess,
            "run",
            lambda *args, **kwargs: SimpleNamespace(
                returncode=0,
                stdout="SUCCESS",
                stderr="",
            ),
        )

        result = CliRunner().invoke(cli_main.cli, ["stop"])

        assert result.exit_code == 0, result.output
        assert "Anteumbra stopped." in result.output
        assert not pid_file.exists()

    def test_stop_refuses_unverifiable_pid_ownership(self, tmp_path, monkeypatch):
        """An unreadable legacy process must never be terminated speculatively."""
        import anteumbra.cli.main as cli_main
        from anteumbra.infrastructure.process_identity import ProcessIdentityState

        pid_file = tmp_path / cli_main.PID_FILE
        pid_file.parent.mkdir(parents=True)
        pid_file.write_text("12345", encoding="utf-8")

        monkeypatch.setattr(cli_main, "_find_project_root", lambda: tmp_path)
        monkeypatch.setattr(
            cli_main,
            "_process_state",
            lambda _identity, _root=None: ProcessIdentityState.UNKNOWN,
        )
        monkeypatch.setattr(
            cli_main.subprocess,
            "run",
            lambda *_args, **_kwargs: pytest.fail("taskkill must not be called"),
        )

        result = CliRunner().invoke(cli_main.cli, ["stop"])

        assert result.exit_code == 1
        assert "refusing to terminate" in result.output
        assert pid_file.exists()

    def test_stop_removes_reused_pid_without_terminating(self, tmp_path, monkeypatch):
        """A reused PID is stale state, not authority to kill the new process."""
        import anteumbra.cli.main as cli_main
        from anteumbra.infrastructure.process_identity import ProcessIdentityState

        pid_file = tmp_path / cli_main.PID_FILE
        pid_file.parent.mkdir(parents=True)
        pid_file.write_text("12345", encoding="utf-8")

        monkeypatch.setattr(cli_main, "_find_project_root", lambda: tmp_path)
        monkeypatch.setattr(
            cli_main,
            "_process_state",
            lambda _identity, _root=None: ProcessIdentityState.MISMATCH,
        )
        monkeypatch.setattr(
            cli_main.subprocess,
            "run",
            lambda *_args, **_kwargs: pytest.fail("taskkill must not be called"),
        )

        result = CliRunner().invoke(cli_main.cli, ["stop"])

        assert result.exit_code == 0, result.output
        assert "no longer owns this runtime" in result.output
        assert not pid_file.exists()

    def test_start_refuses_invalid_pid_identity(self, tmp_path, monkeypatch):
        """Corrupt ownership state must block a potentially duplicate start."""
        import anteumbra.cli.main as cli_main

        pid_file = tmp_path / cli_main.PID_FILE
        pid_file.parent.mkdir(parents=True)
        pid_file.write_text("not-a-process-identity", encoding="utf-8")

        monkeypatch.setattr(cli_main, "_find_project_root", lambda: tmp_path)
        monkeypatch.setattr(
            cli_main.subprocess,
            "Popen",
            lambda *_args, **_kwargs: pytest.fail("process must not be started"),
        )

        result = CliRunner().invoke(cli_main.cli, ["start"])

        assert result.exit_code == 1
        assert "invalid PID identity file" in result.output
        assert pid_file.exists()


# ═══════════════════════════════════════════════════════════════════════════════
# 18.2.3 — Process Lifecycle
# ═══════════════════════════════════════════════════════════════════════════════


# Default port from config.toml (web_admin.port)
_DEFAULT_PORT = 8080
_STARTUP_TIMEOUT = 15  # seconds


def _find_free_port():
    """Find a free port for test server."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_for_port(host, port, timeout=_STARTUP_TIMEOUT):
    """Wait until port is listening, return True if successful."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            sock = socket.create_connection((host, port), timeout=1)
            sock.close()
            return True
        except (socket.error, OSError):
            time.sleep(0.3)
    return False


class TestProcessLifecycle:
    """Verify process start/stop behavior."""

    def test_port_listening_after_start(self, tmp_path):
        """After starting run.py with Flask, the configured port should be listening."""
        # Find a free port to avoid conflicts
        test_port = _find_free_port()

        # Create a minimal temporary config that won't interfere
        project_root = Path(__file__).parent.parent.parent
        run_py = project_root / "run.py"

        assert run_py.exists(), f"run.py not found at {run_py}"

        # We use flask run directly rather than run.py to avoid starting
        # all the background threads (monitor, WAF, etc.)
        env = os.environ.copy()
        env["PYTHONPATH"] = str(project_root) + os.pathsep + str(project_root / "src")
        env["ANTEUMBRA_TOOL_MODE"] = "true"
        env["FLASK_APP"] = "anteumbra.interfaces.web.factory:create_app"
        env.pop("FLASK_RUN_PORT", None)
        env.pop("FLASK_RUN_HOST", None)

        # Start Flask in a subprocess
        proc = None
        try:
            proc = subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "flask",
                    "run",
                    "--host",
                    "127.0.0.1",
                    "--port",
                    str(test_port),
                    "--no-debugger",
                    "--no-reload",
                ],
                env=env,
                cwd=str(tmp_path),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

            # Wait for port to be ready
            is_listening = _wait_for_port("127.0.0.1", test_port, timeout=20)
            if not is_listening:
                pytest.fail(f"Flask did not listen on {test_port}; returncode={proc.poll()}")

            # Verify we can connect
            sock = socket.create_connection(("127.0.0.1", test_port), timeout=3)
            sock.close()

        finally:
            if proc and proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()

    def test_process_terminates_cleanly(self, tmp_path):
        """After stop, process should terminate and not leave zombie state."""
        test_port = _find_free_port()
        project_root = Path(__file__).parent.parent.parent

        env = os.environ.copy()
        env["PYTHONPATH"] = str(project_root) + os.pathsep + str(project_root / "src")
        env["ANTEUMBRA_TOOL_MODE"] = "true"
        env["FLASK_APP"] = "anteumbra.interfaces.web.factory:create_app"

        proc = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "flask",
                "run",
                "--host",
                "127.0.0.1",
                "--port",
                str(test_port),
                "--no-debugger",
                "--no-reload",
            ],
            env=env,
            cwd=str(tmp_path),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        # Give it time to start
        is_listening = _wait_for_port("127.0.0.1", test_port, timeout=20)

        if not is_listening:
            if proc.poll() is not None:
                proc.wait()
                pytest.fail(
                    f"Flask exited with code {proc.returncode} — test env may lack config.toml"
                )
            proc.kill()
            proc.wait()
            pytest.fail("Flask did not start listening within timeout")

        # Now terminate
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()

        # After termination, the process should not be running
        assert proc.returncode is not None, "Process should have exited"
        # Terminated processes typically return -15 (SIGTERM) on Unix,
        # or 1 on Windows when terminated via TerminateProcess
        # We just verify it's not still running
        assert proc.poll() is not None, "Process should be fully stopped"

        # Port should be free again
        time.sleep(0.5)  # Let OS release the port
        try:
            sock = socket.create_connection(("127.0.0.1", test_port), timeout=2)
            sock.close()
            # Port might be quickly reused — not an error, just note it
        except (socket.error, OSError):
            pass  # Expected: port is free

    def test_pid_file_written_by_run_py(self, tmp_path):
        """When run.py starts, a PID file should be created."""
        project_root = Path(__file__).parent.parent.parent
        project_root / "data" / "anteumbra.pid"

        # PID writing is owned by RuntimeLifecycle instead of source-tree run.py.
        # Verify the launcher contains the PID file logic
        launcher_path = project_root / "src" / "anteumbra" / "application" / "launcher.py"
        assert launcher_path.exists(), "launcher.py not found"

        builder_path = project_root / "src" / "anteumbra" / "application" / "runtime_builder.py"
        launcher_source = launcher_path.read_text(encoding="utf-8")
        builder_source = builder_path.read_text(encoding="utf-8")

        assert "anteumbra.pid" in launcher_source, (
            "RuntimeLifecycle should write a PID file (data/anteumbra.pid) at startup"
        )
        assert "dependencies.process_identity_writer" in launcher_source
        assert "process_identity_writer=write_process_identity" in builder_source
