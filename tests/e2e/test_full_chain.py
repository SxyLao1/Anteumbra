"""Complete WAF-to-response security workflow test."""

from __future__ import annotations

import logging
from datetime import datetime


def test_full_chain_waf_detection_quarantine_and_block(
    tmp_path,
    threat_graph,
    scanner_service,
    detection_runtime,
):
    from anteumbra.infrastructure.block_ledger import BlockLedger
    from anteumbra.infrastructure.detection.scanner import quick_scan_yara
    from anteumbra.infrastructure.models import ScanOptions

    data_dir = tmp_path / "full-chain"
    data_dir.mkdir()
    block_ledger = BlockLedger(data_dir / "block_ledger.json")
    site = detection_runtime.site
    graph = threat_graph
    graph.set_persist_path(data_dir / "threat_graph.json")

    attacker_ip = "192.168.99.66"
    attacker_ua = "AntSword/2.1.15"
    for index in range(5):
        graph.ingest_waf_event(
            {
                "timestamp": datetime.now().isoformat(),
                "src_ip": attacker_ip,
                "user_agent": attacker_ua,
                "url": f"/uploads/cmd{index}.php",
                "waf_score": 0.85,
                "waf_rule_id": "PHP_WEBSHELL_UPLOAD",
                **site.as_dict(),
            }
        )

    profiles = graph.get_active_profiles()
    assert profiles
    profile = profiles[0]
    assert attacker_ip in profile.ip_pool
    assert profile.risk_score > 0

    website = tmp_path / "www"
    website.mkdir()
    webshell = website / "cmd.php"
    webshell.write_text('<?php @eval($_POST["cmd"]); ?>', encoding="utf-8")
    scan = quick_scan_yara(
        webshell,
        ScanOptions(monitor_extensions=[".php"]),
        logging.getLogger("test.e2e.full-chain"),
        scanner_service=scanner_service,
    )

    assert scan is not None
    assert scan.is_suspicious

    detection_runtime.registry.add(
        webshell,
        scan.features,
        first_seen_ip=attacker_ip,
        detection_source="active",
        site=site,
    )
    registry_record = detection_runtime.registry.get(webshell, site.site_id)
    assert registry_record is not None
    assert registry_record["site_id"] == site.site_id

    quarantined = detection_runtime.quarantine.quarantine_file(
        webshell,
        scan.features[0] if scan.features else "webshell",
        scan.features,
        site=site,
    )

    assert quarantined is not None
    assert not webshell.exists()
    registry_record = detection_runtime.registry.get(webshell, site.site_id)
    assert registry_record["quarantine_id"] == quarantined["quarantine_id"]
    profile.target_files.add(str(webshell))

    for index in range(3):
        graph.ingest_waf_event(
            {
                "timestamp": datetime.now().isoformat(),
                "src_ip": attacker_ip,
                "user_agent": attacker_ua,
                "url": f"/admin/config{index}.php",
                "waf_score": 0.9,
                "waf_rule_id": "ADMIN_ACCESS",
                **site.as_dict(),
            }
        )

    profile = graph.query_profile(profile.profile_id)
    assert profile is not None
    assert profile.risk_score >= 0.5

    entry = block_ledger.add_entry(
        ip=attacker_ip,
        site=site,
        source="auto",
        reason=f"Profile {profile.profile_id} risk {profile.risk_score:.2f}",
        profile_id=profile.profile_id,
        blocked_by="system",
    )

    assert entry["site_id"] == site.site_id
    assert block_ledger.get_by_ip(attacker_ip, site_id=site.site_id) is not None
    entries, total = block_ledger.get_entries(site_id=site.site_id)
    assert total == 1
    assert entries[0]["ip"] == attacker_ip
    assert block_ledger.get_stats(site_id=site.site_id)["auto"] == 1
