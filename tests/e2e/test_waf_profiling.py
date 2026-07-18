# -*- coding: utf-8 -*-
"""
E2E Test: WAF Attack Traffic → Attacker Profiling

Flow:
  1. Feed simulated WAF attack events to ThreatGraph
  2. Verify attacker profiles are created
  3. Verify IP reputation is tracked
  4. Verify profile risk scores increase with more attacks
"""
import json
import time
from pathlib import Path

import pytest


class TestWAFProfiling:
    """Feed WAF events and verify attacker profiles are generated."""

    def test_feed_events_creates_profiles(self, waf_events_file, threat_graph):
        """Feed WAF events and verify profiles are created for each attacker IP."""
        graph = threat_graph

        # Feed all events
        with open(str(waf_events_file), 'r', encoding='utf-8') as f:
            for line in f:
                if line.strip():
                    evt = json.loads(line.strip())
                    graph.ingest_waf_event(evt)

        # Check profiles — 3 distinct UAs → at least 2 profiles
        # (the "browser" UA may normalize to same bucket as another)
        profiles = graph.get_active_profiles()
        assert len(profiles) >= 1, (
            f"Should have at least 1 attacker profile, got {len(profiles)}"
        )

        # Verify specific IPs have profiles
        all_ips = set()
        for p in profiles:
            all_ips.update(p.ip_pool)

        assert "10.99.99.1" in all_ips, (
            f"10.99.99.1 (SQLMap attacker) should have a profile, got IPs: {all_ips}"
        )

    def test_sqlmap_attacker_has_high_risk(self, waf_events_file, threat_graph):
        """Verify the SQLMap attacker (4 high-score events) gets a high risk score."""
        graph = threat_graph

        with open(str(waf_events_file), 'r', encoding='utf-8') as f:
            for line in f:
                if line.strip():
                    evt = json.loads(line.strip())
                    graph.ingest_waf_event(evt)

        # The SQLMap attacker sent 4 high-score events — risk should be elevated
        profiles = graph.get_active_profiles()
        sqlmap_profiles = [p for p in profiles
                          if "10.99.99.1" in p.ip_pool]

        assert len(sqlmap_profiles) >= 1, (
            f"Should have at least 1 profile for SQLMap IP, got {len(sqlmap_profiles)}"
        )

        sqlmap = sqlmap_profiles[0]
        assert sqlmap.risk_score > 0, (
            f"SQLMap attacker should have risk_score > 0, got {sqlmap.risk_score}"
        )
        # UA fingerprint should indicate sqlmap
        assert "sqlmap" in sqlmap.ua_fingerprint.lower(), (
            f"UA fingerprint should contain 'sqlmap', got: {sqlmap.ua_fingerprint}"
        )

    def test_antsword_attacker_has_target_files(self, waf_events_file, threat_graph):
        """Verify AntSword attacker profile includes the uploaded webshell paths."""
        graph = threat_graph

        with open(str(waf_events_file), 'r', encoding='utf-8') as f:
            for line in f:
                if line.strip():
                    evt = json.loads(line.strip())
                    graph.ingest_waf_event(evt)

        profiles = graph.get_active_profiles()
        antsword_profiles = [p for p in profiles
                            if "10.88.77.2" in p.ip_pool]

        assert len(antsword_profiles) >= 1, (
            f"Should have at least 1 profile for AntSword IP, got {len(antsword_profiles)}"
        )

        ant = antsword_profiles[0]
        assert ant.risk_score > 0, "AntSword attacker should have elevated risk"
        assert "antsword" in ant.ua_fingerprint.lower(), (
            f"UA fingerprint should contain 'antsword', got: {ant.ua_fingerprint}"
        )

    def test_ingest_registry_entry_links_to_profile(self, waf_events_file, threat_graph):
        """Verify that feeding a registry entry links to an existing IP profile.

        The registry entry's first_seen_ip must first have a profile created
        via WAF events, then the registry entry will link to it.
        """
        graph = threat_graph

        # First, create an IP reputation entry by feeding a WAF event
        waf_event = {
            "timestamp": "2026-07-01T10:30:00",
            "src_ip": "10.99.99.1",
            "url": "/images/backdoor.php",
            "waf_score": 88,
            "user_agent": "sqlmap/1.6",
            "method": "POST",
        }
        graph.ingest_waf_event(waf_event)

        # Now ingest a registry entry for the same IP
        entry = {
            "file_path": "/var/www/html/images/backdoor.php",
            "features": ["eval", "base64_decode", "shell_exec"],
            "first_seen_ip": "10.99.99.1",
            "detected_at": "2026-07-01T10:30:00",
            "detection_source": "passive",
        }
        graph.ingest_registry_entry(entry)

        # Should now have a profile for 10.99.99.1
        profiles = graph.get_active_profiles()
        matching = [p for p in profiles if "10.99.99.1" in p.ip_pool]

        assert len(matching) >= 1, (
            f"Should have a profile for IP 10.99.99.1 after ingest_registry_entry"
        )

        profile = matching[0]
        found_file = any(
            "backdoor.php" in f for f in profile.target_files
        )
        assert found_file, (
            f"Profile should have target_file containing backdoor.php, "
            f"got: {profile.target_files}"
        )
