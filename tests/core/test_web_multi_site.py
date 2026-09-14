# -*- coding: utf-8 -*-
"""The admin frontend must expose multi-site monitoring instead of hiding it.

A deployment may watch several sites.  These tests pin the three surfaces that
make that visible and keep it honest: the nav switcher (only when there is
something to switch between), the site-scoped list pages (aggregate versus one
site, with every row labelled by its own site), and the URL/cookie precedence
that decides which scope a plain page load lands in.
"""

from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import quote

import pytest

from anteumbra.application.quarantine_service import QuarantineService
from anteumbra.domain.site import SiteIdentity
from anteumbra.infrastructure.quarantine import QuarantineStore
from anteumbra.infrastructure.suspicious_registry import SuspiciousRegistry
from anteumbra.infrastructure.wal_manager import WalManager

SITES = (("alpha", "Alpha"), ("beta", "Beta"))
FILE_NAMES = {
    "alpha": "alpha-shell.php",
    "alpha2": "alpha-shell-2.php",
    "beta": "beta-shell.php",
    "outside": "legacy-shell.php",
}


class _Events:
    def publish(self, *_args, **_kwargs):
        return None


class _Sse:
    def trigger_registry_update(self):
        return None


class _Config:
    """Minimal config port: two enabled sites and a ledger page size."""

    def __init__(self, websites, per_page: int = 20):
        self._websites = list(websites)
        self._per_page = per_page

    def get(self):
        return {"filesizes": {}, "web_admin": {"items_per_page": self._per_page}}

    def get_websites(self):
        return list(self._websites)

    def get_enabled_websites(self):
        return [site for site in self._websites if getattr(site, "enabled", True)]

    def resolve_site_identity(self, _path, site_id=None, site_name=None):
        if site_id:
            return SiteIdentity.from_values(site_id, site_name or str(site_id))
        return SiteIdentity.legacy()


def _websites(count: int):
    return [
        SimpleNamespace(
            site_id=site_id,
            name=name,
            enabled=True,
            path=Path(f"C:/srv/{site_id}"),
            port=8080,
        )
        for site_id, name in SITES[:count]
    ]


def _sample_file(tmp_path: Path, folder: str) -> Path:
    """A real file on disk whose URL form is never used by these tests."""
    target = tmp_path / folder / FILE_NAMES[folder]
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("<?php @eval($_POST['x']); ?>", encoding="utf-8")
    return target


@pytest.fixture
def detection_runtime(tmp_path):
    """A real registry and quarantine store carrying two sites plus a legacy row."""
    config = _Config(_websites(2))
    registry = SuspiciousRegistry(
        tmp_path / "runtime" / "registry.json",
        config=config,
        wal=WalManager(tmp_path / "runtime" / "registry_wal.log"),
        event_publisher=_Events(),
    )
    store = QuarantineStore(
        tmp_path / "runtime" / "quarantine",
        site_resolver=config.resolve_site_identity,
    )
    quarantine = QuarantineService(
        store,
        registry,
        site_resolver=config.resolve_site_identity,
    )

    files = {
        folder: _sample_file(tmp_path, folder)
        for folder in ("alpha", "alpha2", "beta", "outside")
    }
    registry.add(
        files["alpha"], ["alpha-rule"], None, "passive", site_id="alpha", site_name="Alpha"
    )
    registry.add(
        files["alpha2"], ["alpha-rule-2"], None, "passive", site_id="alpha", site_name="Alpha"
    )
    registry.add(files["beta"], ["beta-rule"], None, "passive", site_id="beta", site_name="Beta")
    # A record persisted before sites existed: no site of its own.
    registry.add(files["outside"], ["legacy-rule"], None, "passive")

    services = SimpleNamespace(
        config=config,
        registry=registry,
        quarantine=quarantine,
        metrics=SimpleNamespace(get=lambda: {"sites": {"alpha": {"scan_total": 3}}}),
        sse=_Sse(),
    )
    yield SimpleNamespace(
        runtime=services,
        config=config,
        registry=registry,
        quarantine=quarantine,
        files=files,
    )
    quarantine.close()
    registry.close()


@pytest.fixture(scope="module")
def _app():
    os.environ.setdefault("ANTEUMBRA_TOOL_MODE", "true")

    from anteumbra.interfaces.web.factory import create_app

    app = create_app()
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False
    return app


@pytest.fixture
def client(_app, detection_runtime, monkeypatch):
    """An authenticated client whose blueprints read the two-site runtime."""
    from anteumbra.interfaces.web import pages
    from anteumbra.interfaces.web.blueprints import (
        admin_bp,
        profiles_bp,
        quarantine_bp,
        records_bp,
    )

    runtime = detection_runtime.runtime
    for module in (pages, admin_bp, records_bp, quarantine_bp, profiles_bp):
        monkeypatch.setattr(module, "get_runtime", lambda: runtime, raising=False)

    with _app.test_client() as test_client:
        with test_client.session_transaction() as flask_session:
            flask_session["authenticated"] = True
            flask_session["username"] = "admin"
        yield test_client


def _body(response) -> str:
    assert response.status_code == 200, response.status_code
    return response.get_data(as_text=True)


def _compact(body: str) -> str:
    """Collapse template whitespace so cell assertions stay readable."""
    return " ".join(body.split())


# ── Site switcher ──────────────────────────────────────────────────────────


def test_switcher_is_absent_with_a_single_site(_app, detection_runtime, monkeypatch):
    from anteumbra.interfaces.web import pages

    runtime = detection_runtime.runtime
    runtime.config = _Config(_websites(1))
    monkeypatch.setattr(pages, "get_runtime", lambda: runtime)
    with _app.test_client() as test_client:
        with test_client.session_transaction() as flask_session:
            flask_session["authenticated"] = True
            flask_session["username"] = "admin"
        body = _body(test_client.get("/admin/"))

    assert 'id="site-switcher"' not in body
    assert "data-site-badge" not in body


def test_switcher_lists_every_site_and_the_aggregate(client):
    body = _body(client.get("/admin/"))

    assert 'id="site-switcher"' in body
    assert '<option value="" selected>' in body, "aggregate is the default scope"
    assert "Alpha · alpha" in body
    assert "Beta · beta" in body
    assert 'data-site-scope="all"' in body
    assert "All sites" in body


def test_url_site_selects_one_site_and_marks_the_shell(client):
    body = _body(client.get("/admin/?site=alpha"))

    assert 'data-site-scope="site"' in body
    assert 'data-active-site="alpha"' in body
    assert 'data-site="alpha"' in body, "the shell tells the router which site it shows"
    assert '<option value="alpha" selected>' in body
    assert "Alpha · alpha" in body


# ── URL / cookie precedence ────────────────────────────────────────────────


def test_url_beats_the_remembered_choice(client):
    assert 'data-active-site="alpha"' in _body(client.get("/admin/?site=alpha"))

    # A plain page load keeps the remembered choice...
    assert 'data-active-site="alpha"' in _body(client.get("/admin/"))
    assert client.get_cookie("anteumbra_site").value == "alpha"

    # ...and the URL still wins over it.
    assert 'data-active-site="beta"' in _body(client.get("/admin/?site=beta"))
    assert client.get_cookie("anteumbra_site").value == "beta"


def test_an_explicitly_empty_site_clears_the_scope(client):
    _body(client.get("/admin/?site=beta"))

    body = _body(client.get("/admin/?site="))

    assert 'data-active-site=""' in body
    assert 'data-site-scope="all"' in body
    assert client.get_cookie("anteumbra_site") is None, "aggregate arrived from the URL"


def test_an_unknown_site_falls_back_to_the_aggregate(client):
    _body(client.get("/admin/?site=beta"))

    body = _body(client.get("/admin/?site=ghost"))

    assert 'data-site-scope="all"' in body
    assert 'data-active-site=""' in body


def test_the_site_surface_is_translated(client):
    shell = _body(client.get("/admin/?lang=zh"))

    assert "全部站点" in shell
    assert "站点范围" in shell

    breakdown = _body(client.get("/admin/dashboard_content?lang=zh"))

    assert "站点明细" in breakdown


# ── Records ────────────────────────────────────────────────────────────────


def test_records_are_filtered_by_the_requested_site(client):
    fragment = _body(
        client.get("/admin/records?compact=1&site=alpha", headers={"HX-Request": "true"})
    )

    assert FILE_NAMES["alpha"] in fragment
    assert "alpha-rule" in fragment
    assert FILE_NAMES["beta"] not in fragment
    assert FILE_NAMES["outside"] not in fragment, "another site's record leaked in"


def test_aggregate_records_keep_every_site_and_label_each_row(client):
    fragment = _body(client.get("/admin/records?compact=1", headers={"HX-Request": "true"}))

    assert FILE_NAMES["alpha"] in fragment
    assert FILE_NAMES["beta"] in fragment
    assert FILE_NAMES["outside"] in fragment, "a record with no site stays in aggregate mode"
    assert fragment.count("record-site") == 4, "each row carries its own site"
    assert "Unassigned" in fragment, "a legacy record is not attributed to a site"
    assert 'data-site-id="alpha"' in fragment
    assert 'data-site-id="beta"' in fragment


def test_a_single_site_hides_the_site_column(client):
    fragment = _body(
        client.get("/admin/records?compact=1&site=alpha", headers={"HX-Request": "true"})
    )

    assert "record-site" not in fragment
    assert "Unassigned" not in fragment


def test_legacy_records_render_as_unassigned_in_chinese(client):
    body = _body(client.get("/admin/records?compact=1&lang=zh", headers={"HX-Request": "true"}))

    assert "未分配" in body
    assert "Legacy / unassigned" not in body


def test_the_records_fragment_carries_the_site(client, detection_runtime):
    detection_runtime.runtime.config = _Config(_websites(2), per_page=1)

    fragment = _body(
        client.get("/admin/records?compact=1&site=alpha", headers={"HX-Request": "true"})
    )

    assert "site=alpha" in fragment, "pagination must stay inside the site scope"
    assert "page=2" in fragment, "a one-row page size forces the pagination bar"


def test_a_fragment_without_a_parameter_inherits_the_remembered_scope(client):
    _body(client.get("/admin/?site=beta"))

    fragment = _body(client.get("/admin/records?compact=1", headers={"HX-Request": "true"}))

    assert "beta-rule" in fragment
    assert "alpha-rule" not in fragment


def test_records_json_reports_the_site_and_its_rows(client):
    payload = client.get("/admin/records?site=alpha").get_json()

    assert payload["site_id"] == "alpha"
    assert {record["site_id"] for record in payload["records"]} == {"alpha"}
    assert payload["records"] and all(
        record["site_unassigned"] is False for record in payload["records"]
    )


# ── Quarantine ─────────────────────────────────────────────────────────────


@pytest.fixture
def quarantined(detection_runtime):
    """Quarantine one file per site through the real service."""
    ids = {}
    for site_id, name in SITES:
        source = detection_runtime.files[site_id]
        record = detection_runtime.quarantine.quarantine_file(
            source,
            f"{site_id}-rule",
            [site_id],
            source,
            site_id,
            name,
        )
        assert record is not None
        ids[site_id] = record["quarantine_id"]
    return ids


def test_quarantine_is_filtered_by_the_requested_site(client, quarantined):
    fragment = _body(client.get("/admin/quarantine?site=beta", headers={"HX-Request": "true"}))

    assert quarantined["beta"] in fragment
    assert quarantined["alpha"] not in fragment
    assert FILE_NAMES["beta"] in fragment
    assert FILE_NAMES["alpha"] not in fragment


def test_aggregate_quarantine_labels_every_row(client, quarantined):
    fragment = _body(client.get("/admin/quarantine?status=all", headers={"HX-Request": "true"}))

    assert quarantined["alpha"] in fragment
    assert quarantined["beta"] in fragment
    assert "record-site" in fragment
    assert "Alpha" in fragment and "Beta" in fragment


def test_quarantine_fragment_carries_the_site(client, quarantined):
    fragment = _body(client.get("/admin/quarantine?site=alpha", headers={"HX-Request": "true"}))

    assert "status=all&amp;site=alpha" in fragment, "status filters stay scoped"
    detail_url = fragment.split("quarantine/detail?qid=")[1].split('"')[0]
    assert "site=alpha" in detail_url, "the detail request stays scoped"


def test_quarantine_detail_names_the_owning_site(client, quarantined):
    body = _body(
        client.get(
            f"/admin/quarantine/detail?qid={quote(quarantined['alpha'])}&site=alpha",
            headers={"HX-Request": "true"},
        )
    )

    assert "Alpha" in body
    assert "Unassigned" not in body


# ── Overview / per-site breakdown ──────────────────────────────────────────


def test_dashboard_content_shows_aggregate_totals_and_per_site_rows(client):
    body = _compact(_body(client.get("/admin/dashboard_content")))

    assert "site-breakdown" in body
    assert "All sites (aggregate)" in body
    assert "These totals cover every site" in body
    assert ">Alpha<" in body and ">Beta<" in body
    assert "Unassigned" in body, "the legacy row is reported, not dropped"
    assert "<td> - </td>" in body, "an unreadable figure renders as a dash, never as 0"


def test_dashboard_content_scoped_to_one_site_says_so(client):
    body = _body(client.get("/admin/dashboard_content?site=beta"))

    assert "These totals cover this site only" in body
    assert "Beta" in body


def test_recent_detections_label_the_rows_site(client):
    body = _body(client.get("/admin/recent-detections", headers={"HX-Request": "true"}))

    assert "Alpha" in body and "Beta" in body
    assert "Unassigned" in body


def test_shell_marks_the_site_and_offers_the_memory_shell_entry(client):
    body = _body(client.get("/admin/threats?site=alpha", headers={"Sec-Fetch-Dest": "document"}))

    assert 'data-site="alpha"' in body
    assert 'data-path="memory-shell"' in body
    assert 'data-path="memory-shell/forensics"' in body


def test_memory_shell_nav_names_both_entries_in_chinese(client):
    body = _body(client.get("/admin/threats?site=alpha&lang=zh", headers={"Sec-Fetch-Dest": "document"}))

    assert "内存马" in body
    assert ">检测<" in body
    assert ">取证<" in body


# ── File clusters ──────────────────────────────────────────────────────────


class _FakeHashEngine:
    """Deterministic similarity: same family in the name means the same hash."""

    track_name = "fake"
    threshold = 0.80

    def hash_file(self, file_path):
        family = "shared" if "shared" in str(file_path) else "solo"
        return f"hash:{family}"

    def compare(self, left, right):
        return 1.0 if left == right else 0.0


@pytest.fixture
def clustered(detection_runtime, tmp_path):
    """Two clusters: one spanning both sites, one that belongs to alpha alone."""
    from anteumbra.application.path_service import path_to_key
    from anteumbra.infrastructure.detection.file_cluster import FileClusterEngine

    engine = FileClusterEngine(_FakeHashEngine())
    files = {
        "shared_alpha": tmp_path / "alpha" / "shared-a.php",
        "shared_alpha2": tmp_path / "alpha" / "shared-b.php",
        "shared_beta": tmp_path / "beta" / "shared-c.php",
        "solo_alpha": tmp_path / "alpha" / "solo.php",
    }
    registry = detection_runtime.registry
    for key, path in files.items():
        site_id, name = ("beta", "Beta") if key == "shared_beta" else ("alpha", "Alpha")
        registry.add(path, ["cluster-rule"], None, "passive", site_id=site_id, site_name=name)
        # The registry stores normalised keys and the production graph clusters
        # those same keys, so the test feeds the engine the identical string.
        engine.cluster_file(path_to_key(path))

    detection_runtime.runtime.file_cluster_engine = engine
    return SimpleNamespace(engine=engine, files=files)


def test_file_clusters_are_scoped_and_attributed(client, clustered):
    aggregate = _body(client.get("/admin/file-clusters"))

    assert "cluster-sites" in aggregate
    assert "Alpha ×2" in aggregate and "Beta ×1" in aggregate
    assert "solo.php" in aggregate

    scoped = _body(client.get("/admin/file-clusters?site=beta"))

    assert "Beta ×1" in scoped
    assert "solo.php" not in scoped, "another site's cluster is not shown in a scoped view"


# ── Projection helpers ─────────────────────────────────────────────────────


def test_site_fields_never_invent_a_label():
    from anteumbra.application.site_read_model import site_fields

    assert site_fields({})["site_unassigned"] is True
    assert site_fields({"site_id": "", "site_name": "Alpha"})["site_unassigned"] is True
    assert site_fields({"site_id": "legacy"})["site_unassigned"] is True
    # A stored name wins; a missing one is filled from the configuration.
    assert site_fields({"site_id": "alpha", "site_name": "Stored"})["site_name"] == "Stored"
    assert site_fields({"site_id": "alpha"}, names_by_id={"alpha": "Alpha"})["site_name"] == "Alpha"


def test_cluster_attribution_prefers_the_registry_over_the_samples():
    from anteumbra.application.site_read_model import cluster_site_index, cluster_site_view

    records = [
        {"file_path": "c:/srv/alpha/a.php", "site_id": "alpha", "site_name": "Alpha"},
        {"file_path": "c:/srv/alpha/b.php", "site_id": "alpha", "site_name": "Alpha"},
        {"file_path": "c:/srv/beta/c.php", "site_id": "beta", "site_name": "Beta"},
        {"file_path": "c:/outside/d.php", "site_id": "legacy", "site_name": "Legacy"},
    ]
    index = cluster_site_index(
        records,
        cluster_id_for_paths=lambda paths: {
            "c:/srv/alpha/a.php": "cluster-1",
            "c:/srv/alpha/b.php": "cluster-1",
            "c:/srv/beta/c.php": "cluster-1",
            "c:/outside/d.php": "cluster-1",
        },
    )

    view = cluster_site_view({"cluster_id": "cluster-1"}, index)

    assert view["site_source"] == "registry"
    assert view["site_multi"] is True
    assert view["site_primary"] == {"site_id": "alpha", "site_name": "Alpha", "count": 2}
    assert view["site_counts"][-1] == {"site_id": "", "site_name": "", "count": 1}


def test_cluster_attribution_flags_a_sample_based_guess():
    from anteumbra.application.site_read_model import cluster_site_view

    view = cluster_site_view(
        {"cluster_id": "cluster-x", "sample_paths": ["c:/srv/beta/c.php"]},
        {},
        record_sites={
            "c:/srv/beta/c.php": {
                "site_id": "beta",
                "site_name": "Beta",
                "site_unassigned": False,
            }
        },
    )

    assert view["site_source"] == "sample"
    assert view["site_inferred"] is True
    assert view["site_counts"] == [{"site_id": "beta", "site_name": "Beta", "count": 1}]
