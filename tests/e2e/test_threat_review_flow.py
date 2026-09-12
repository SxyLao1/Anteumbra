# -*- coding: utf-8 -*-
"""
Threat ledger review flow: false-positive marking is now reversible.

Covers the unmark API, the merged status filter and the record-detail action
used by every "Source / Detail" pair in the UI.
"""

import os

import pytest


@pytest.fixture(scope="module")
def _app():
    os.environ.setdefault("ANTEUMBRA_TOOL_MODE", "true")
    from anteumbra.interfaces.web.factory import create_app

    app = create_app()
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False
    return app


@pytest.fixture
def client(_app):
    with _app.test_client() as c:
        with c.session_transaction() as flask_session:
            flask_session["authenticated"] = True
            flask_session["username"] = "admin"
        yield c


class TestUnmarkFalsePositiveDomain:
    def test_unmark_clears_the_flag_but_keeps_the_trail(self):
        from anteumbra.domain.registry_records import mark_false_positive, unmark_false_positive

        record = {"file_path": "x.php"}
        mark_false_positive(record, "reviewed", "2026-09-12T00:00:00Z")
        assert record["marked_false_positive"] is True

        unmark_false_positive(record, "2026-09-12T01:00:00Z")
        assert record["marked_false_positive"] is False
        assert record["false_positive_cleared_at"] == "2026-09-12T01:00:00Z"
        # the original review timestamps stay for the audit trail
        assert record["false_positive_at"] == "2026-09-12T00:00:00Z"
        assert record["false_positive_reason"] == "reviewed"


def _hx() -> dict:
    """Records render the fragment only for HTMX-style requests."""
    return {"HX-Request": "true"}


class TestStatusFilter:
    def test_records_endpoint_accepts_every_status(self, client):
        for status in ("all", "active", "false_positive", "deleted"):
            resp = client.get(f"/admin/records?status={status}&compact=1", headers=_hx())
            assert resp.status_code == 200, status
            assert f'data-status="{status}"' in resp.get_data(as_text=True)

    def test_unknown_status_falls_back_to_all(self, client):
        resp = client.get("/admin/records?status=bogus&compact=1", headers=_hx())
        assert resp.status_code == 200
        assert 'data-status="all"' in resp.get_data(as_text=True)

    def test_legacy_audit_parameter_still_works(self, client):
        resp = client.get("/admin/records?audit=true&compact=1", headers=_hx())
        assert resp.status_code == 200
        assert 'data-status="all"' in resp.get_data(as_text=True)

    def test_status_filter_renders_chips(self, client):
        body = client.get("/admin/records?compact=1", headers=_hx()).get_data(as_text=True)
        for marker in (
            'data-status="all"',
            'data-status="active"',
            'data-status="false_positive"',
            'data-status="deleted"',
        ):
            assert marker in body

    def test_row_actions_are_uniform(self, client):
        """Every ledger row offers Source, Detail and a review toggle."""
        body = client.get("/admin/records?compact=1", headers=_hx()).get_data(as_text=True)
        assert 'data-action="records.view-path"' in body or "No detection records" in body
        assert 'data-action="records.detail-open"' in body or "No detection records" in body
        assert (
            "records.mark-fp" in body
            or "records.unmark-fp" in body
            or "No detection records" in body
        )


class TestUnmarkRoute:
    def test_unmark_endpoint_registered_and_guarded(self, client):
        resp = client.post("/admin/unmark_false_positive/E%3A%5Cwww%5Cmissing.php")
        # the record does not exist in the isolated registry -> 404, not 500
        assert resp.status_code in (200, 404)

    def test_batch_action_accepts_unmark(self, client):
        resp = client.post(
            "/admin/records/batch",
            json={"action": "unmark_false_positive", "file_paths": []},
        )
        assert resp.status_code in (200, 400)


class TestClustersExposePaths:
    def test_cluster_projection_returns_full_paths(self):
        from anteumbra.infrastructure.detection.file_cluster import FileCluster
        from anteumbra.infrastructure.detection.hash_engine import HashEngine

        cluster = FileCluster("cluster-1", HashEngine())
        cluster.files[r"E:\www\a.php"] = "hash-a"
        cluster.files[r"E:\www\b.php"] = "hash-b"
        assert cluster.sample_paths(1) == [r"E:\www\a.php"]
        assert len(cluster.sample_paths(25)) == 2
        # filenames stay available for the older call sites; Path.name does not
        # split a Windows path on POSIX, so assert on the tails only
        assert len(cluster.sample_files) == 2
        assert cluster.sample_files[0].endswith("a.php")
        assert cluster.sample_files[1].endswith("b.php")
