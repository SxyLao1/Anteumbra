"""Authenticated web flow tests for runtime-owned blocking services."""

import pytest

from anteumbra.domain.blocking import BlockDecision, BlockResult
from anteumbra.domain.site import SiteIdentity
from anteumbra.infrastructure.block_ledger import BlockLedger
from anteumbra.infrastructure.ip_blocker import IPBlocker, MockDevice


@pytest.fixture
def blocking_client(tmp_path):
    from anteumbra.interfaces.web.factory import create_app

    app = create_app()
    app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
    runtime = app.extensions["anteumbra.runtime"]
    website = runtime.config.get_websites()[0]
    site = SiteIdentity.from_values(website.site_id, website.name)
    device = MockDevice("test-waf")
    runtime.ip_blocker = IPBlocker([device], retry_path=tmp_path / "retry.json")
    runtime.block_ledger = BlockLedger(tmp_path / "block_ledger.json")

    with app.test_client() as client:
        with client.session_transaction() as session:
            session["authenticated"] = True
            session["username"] = "admin"
        yield client, runtime, site, device


def test_block_route_uses_runtime_services_and_site_identity(blocking_client):
    client, runtime, site, device = blocking_client

    response = client.post(
        "/admin/blocklist/block",
        json={"ips": ["10.10.0.1"], "reason": "manual review", "site_id": site.site_id},
    )

    assert response.status_code == 200
    assert response.get_json()["success"] is True
    assert device.is_blocked("10.10.0.1")
    record = runtime.block_ledger.get_by_ip("10.10.0.1", site_id=site.site_id)
    assert record["site_name"] == site.site_name
    assert record["reason"] == "manual review"


@pytest.mark.parametrize(
    ("payload", "message"),
    [
        ({"ips": ["not-an-ip"]}, "invalid IP"),
        ({"ips": ["10.10.0.2"], "site_id": "missing-site"}, "unknown site_id"),
        ({"ips": "10.10.0.2"}, "non-empty array"),
    ],
)
def test_invalid_block_request_has_no_device_side_effect(blocking_client, payload, message):
    client, _, _, device = blocking_client

    response = client.post("/admin/api/v1/blocklist/add", json=payload)

    assert response.status_code == 400
    assert message in response.get_json()["message"]
    assert device.list_all() == []


def test_site_scoped_data_and_note_update(blocking_client):
    client, runtime, site, _ = blocking_client
    runtime.block_ledger.add_entry("10.10.0.3", site=site, reason="site event")
    runtime.block_ledger.add_entry("10.10.0.4", site=SiteIdentity.legacy(), reason="legacy")

    data = client.get(f"/admin/blocklist/data?site_id={site.site_id}").get_json()
    notes = client.post(
        "/admin/blocklist/notes",
        json={"ip": "10.10.0.3", "site_id": site.site_id, "notes": "reviewed"},
    )

    assert data["total"] == 1
    assert data["entries"][0]["site_id"] == site.site_id
    assert notes.status_code == 200
    assert runtime.block_ledger.get_by_ip("10.10.0.3", site_id=site.site_id)["notes"] == "reviewed"
    assert runtime.block_ledger.get_by_ip("10.10.0.4", site_id="legacy")["notes"] == ""


def test_unblock_route_retains_audit_record(blocking_client):
    client, runtime, site, device = blocking_client
    device.block(BlockDecision(ip="10.10.0.5", reason="setup", site=site))
    runtime.block_ledger.add_entry("10.10.0.5", site=site)

    response = client.post(
        "/admin/blocklist/unblock",
        json={"ips": ["10.10.0.5"], "site_id": site.site_id},
    )

    assert response.status_code == 200
    assert not device.is_blocked("10.10.0.5")
    assert (
        runtime.block_ledger.get_by_ip("10.10.0.5", site_id=site.site_id)["status"] == "unblocked"
    )


def test_partial_unblock_retains_failed_ip_and_other_site_state(blocking_client, tmp_path):
    client, runtime, site, device = blocking_client

    class SelectiveDevice(MockDevice):
        fail = True

        def unblock(self, ip):
            if self.fail and ip == "10.10.0.7":
                return BlockResult(self.name, False, "device refused", ip)
            return super().unblock(ip)

    second = SelectiveDevice("second-waf")
    runtime.ip_blocker = IPBlocker([device, second], retry_path=tmp_path / "retry-bulk.json")
    for ip in ("10.10.0.6", "10.10.0.7"):
        for target in (device, second):
            target.block(BlockDecision(ip=ip, reason="setup", site=site))
        runtime.block_ledger.add_entry(ip, site=site)
    runtime.block_ledger.add_entry("10.10.0.7", site=SiteIdentity.legacy())
    payload = {
        "ips": ["10.10.0.6", "10.10.0.7"],
        "site_id": site.site_id,
        "devices": [device.name, second.name],
    }

    response = client.post("/admin/blocklist/unblock", json=payload)

    assert response.status_code == 207
    assert len(response.get_json()["results"]) == 4
    assert runtime.block_ledger.get_by_ip("10.10.0.6", site_id=site.site_id)["status"] == "unblocked"
    assert runtime.block_ledger.get_by_ip("10.10.0.7", site_id=site.site_id)["status"] == "blocked"
    assert runtime.block_ledger.get_by_ip("10.10.0.7", site_id="legacy")["status"] == "blocked"
    assert second.is_blocked("10.10.0.7")

    second.fail = False
    response = client.post("/admin/blocklist/unblock", json={**payload, "ips": ["10.10.0.7"]})
    assert response.status_code == 200
    assert runtime.block_ledger.get_by_ip("10.10.0.7", site_id=site.site_id)["status"] == "unblocked"
    assert runtime.block_ledger.get_by_ip("10.10.0.7", site_id="legacy")["status"] == "blocked"


def test_unblock_reports_missing_audit_record(blocking_client):
    client, _, site, device = blocking_client
    response = client.post(
        "/admin/blocklist/unblock",
        json={"ips": ["10.10.0.8"], "site_id": site.site_id, "devices": [device.name]},
    )
    assert response.status_code == 207
    assert response.get_json()["success"] is False
    assert response.get_json()["ledger_errors"][0]["ip"] == "10.10.0.8"
