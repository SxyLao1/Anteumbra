"""End-to-end behavior for block, audit, query, export, and unblock."""

import json

import pytest

from anteumbra.domain.site import SiteIdentity
from anteumbra.infrastructure.block_ledger import BlockLedger
from anteumbra.infrastructure.ip_blocker import IPBlocker, MockDevice


@pytest.fixture
def block_runtime(tmp_path):
    site = SiteIdentity("primary", "Primary")
    device = MockDevice("test-waf")
    blocker = IPBlocker([device], retry_path=tmp_path / "retry.json")
    ledger = BlockLedger(tmp_path / "block_ledger.json")
    return site, device, blocker, ledger


def test_block_to_audit_to_unblock_flow(block_runtime):
    site, device, blocker, ledger = block_runtime

    results = blocker.block(
        ["10.99.99.1"],
        reason="Profile abc123 - AntSword scan / risk 95%",
        site=site,
        profile_id="abc123",
        risk_score=0.95,
    )
    ledger.add_entry(
        "10.99.99.1",
        site=site,
        source="auto",
        reason="AntSword scan",
        profile_id="abc123",
        blocked_by="system",
        broadcast_results=[
            {
                "device": result.device_name,
                "success": result.success,
                "message": result.message,
            }
            for result in results
        ],
    )

    assert device.is_blocked("10.99.99.1")
    assert ledger.get_by_ip("10.99.99.1", site_id="primary")["status"] == "blocked"
    assert ledger.get_stats(site_id="primary")["auto"] == 1
    assert json.loads(ledger.export_ledger("json", site_id="primary"))[0]["profile_id"] == "abc123"

    unblock_results = blocker.unblock(["10.99.99.1"])
    assert all(result.success for result in unblock_results)
    assert ledger.mark_unblocked("10.99.99.1", site_id="primary")
    assert not device.is_blocked("10.99.99.1")
    assert ledger.get_by_ip("10.99.99.1", site_id="primary")["status"] == "unblocked"


def test_query_notes_and_dedup_flow(block_runtime):
    site, _, _, ledger = block_runtime
    ledger.add_entry("10.88.77.2", site=site, source="manual", reason="First block")
    ledger.add_entry("10.88.77.2", site=site, source="auto", reason="Updated block")
    ledger.add_entry("10.88.77.3", site=site, source="manual", reason="Normal probe")

    assert ledger.update_notes(
        "10.88.77.2",
        "Suspected C2 server",
        site_id="primary",
    )
    entries, total = ledger.get_entries(
        site_id="primary",
        source_filter="auto",
        search="Updated",
    )

    assert total == 1
    assert entries[0]["notes"] == "Suspected C2 server"
    assert ledger.get_stats(site_id="primary")["total"] == 2
