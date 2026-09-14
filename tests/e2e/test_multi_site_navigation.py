# -*- coding: utf-8 -*-
"""E2E: a two-site config.toml must reach the admin frontend.

The frontend used to render every page as if the deployment watched exactly one
site — no switcher, no site column, no way to narrow a list — because nothing
ever read the ``sites`` the backend already produced.  This test builds a real
application from a real two-site configuration file, so the site list and the
scope resolution come from config parsing and the wired runtime instead of from
a stub.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

SITES = (("alpha", "Alpha", 8081), ("beta", "Beta", 8082))


def _write_config(root: Path) -> Path:
    entries = []
    for site_id, name, port in SITES:
        entries.append(
            "\n".join(
                (
                    "[[website]]",
                    f'id = "{site_id}"',
                    f'name = "{name}"',
                    f'path = "{(root / "sites" / site_id).as_posix()}"',
                    f"port = {port}",
                    "enabled = true",
                    "",
                )
            )
        )
    config = root / "config.toml"
    config.write_text(
        "\n".join(entries) + '\n[security]\nsecret_key = "multi-site-e2e-secret"\n',
        encoding="utf-8",
    )
    return config


@pytest.fixture(scope="module")
def two_site_app(tmp_path_factory):
    os.environ.setdefault("ANTEUMBRA_TOOL_MODE", "true")
    root = tmp_path_factory.mktemp("multi-site-config")
    previous_cwd = os.getcwd()
    os.chdir(root)
    try:
        from anteumbra.interfaces.web.factory import create_app

        app = create_app(str(_write_config(root)))
        app.config["TESTING"] = True
        app.config["WTF_CSRF_ENABLED"] = False
        yield app
        runtime = app.extensions["anteumbra.runtime"]
        for resource, method in (
            (runtime.quarantine, "close"),
            (runtime.registry, "close"),
            (runtime.logging, "close"),
        ):
            callback = getattr(resource, method, None)
            if callable(callback):
                callback()
    finally:
        os.chdir(previous_cwd)


@pytest.fixture
def client(two_site_app):
    with two_site_app.test_client() as test_client:
        with test_client.session_transaction() as flask_session:
            flask_session["authenticated"] = True
            flask_session["username"] = "admin"
        yield test_client


def _body(response) -> str:
    assert response.status_code == 200, response.status_code
    return response.get_data(as_text=True)


def _record(runtime, site_id: str, name: str):
    """Register one real detection for a site."""
    path = Path(runtime.config.get_website(site_id).path) / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("<?php @eval($_POST['x']); ?>", encoding="utf-8")
    runtime.registry.add(path, [f"{site_id}-rule"], None, "passive", site_id=site_id)
    return path


def test_two_configured_sites_reach_the_switcher(client):
    body = _body(client.get("/admin/"))

    assert 'id="site-switcher"' in body
    assert "Alpha · alpha" in body
    assert "Beta · beta" in body
    assert '<option value="" selected>' in body, "one aggregate entry plus one per site"


def test_scope_lives_in_the_url_and_is_remembered(client):
    assert 'data-active-site="alpha"' in _body(client.get("/admin/?site=alpha"))

    # A plain browser navigation keeps the choice...
    assert 'data-active-site="alpha"' in _body(client.get("/admin/"))
    assert client.get_cookie("anteumbra_site").value == "alpha"

    # ...and an explicit URL still wins over it, including the aggregate.
    assert 'data-active-site="beta"' in _body(client.get("/admin/?site=beta"))
    assert 'data-active-site=""' in _body(client.get("/admin/?site="))


def test_records_fragment_is_scoped_and_labelled(client, two_site_app):
    runtime = two_site_app.extensions["anteumbra.runtime"]
    _record(runtime, "alpha", "alpha-shell.php")
    _record(runtime, "beta", "beta-shell.php")

    aggregate = _body(client.get("/admin/records?compact=1", headers={"HX-Request": "true"}))
    assert "alpha-shell.php" in aggregate and "beta-shell.php" in aggregate
    assert "record-site" in aggregate, "the aggregate list labels each row's site"

    scoped = _body(
        client.get("/admin/records?compact=1&site=alpha", headers={"HX-Request": "true"})
    )
    assert "alpha-shell.php" in scoped
    assert "beta-shell.php" not in scoped
    assert "record-site" not in scoped, "a single-site list does not repeat the site"
