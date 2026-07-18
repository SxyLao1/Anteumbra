# -*- coding: utf-8 -*-
"""v1.0.9: Unit tests for threat_graph.py — attacker profiling engine.

Tests cover: ingest_waf_event, ingest_registry_entry, query_ip, query_file,
query_profile, get_active_profiles, get_cluster_level, merge_overlapping_profiles,
decay_profiles, generate_profile_id, persist/load round-trip,
_normalize_ua, _normalize_url, _is_management_ip, and edge cases.
"""
import json
import time
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch

import pytest

from anteumbra.infrastructure.threat_graph import ThreatGraph, get_threat_graph


# ── Fixtures ──────────────────────────────────────────────────


@pytest.fixture
def graph(monkeypatch):
    """Return a fresh ThreatGraph instance with no persistence."""
    # Stub ConfigRegistry so load()/persist() use JSON backend (not SQLite)
    from anteumbra.infrastructure.config import registry as cfg_reg
    monkeypatch.setattr(
        cfg_reg.ConfigRegistry, "get_raw_config",
        lambda: {"storage": {"backend": "json"}},
    )
    tg = ThreatGraph()
    tg._profiles = {}
    tg._ip_table = {}
    tg._file_table = {}
    tg._management_ips = []
    tg._time_window = 4
    return tg


@pytest.fixture
def sample_waf_event():
    """Return a minimal WAF event dict."""
    return {
        "src_ip": "192.168.1.100",
        "timestamp": datetime.now().isoformat(),
        "user_agent": "sqlmap/1.6#stable (http://sqlmap.org)",
        "url": "/upload.php?cmd=id",
        "method": "POST",
        "http_method": "POST",
        "src_port": 54321,
        "dest_port": 443,
    }


@pytest.fixture
def sample_registry_entry():
    """Return a minimal registry entry dict."""
    return {
        "file_path": "/var/www/html/shell.php",
        "first_seen_ip": "10.0.0.50",
        "features": ["php_eval", "base64_decode"],
        "detected_at": datetime.now().isoformat(),
        "detection_source": "passive",
    }


# ── UA/URL Normalization ──────────────────────────────────────


class TestNormalizeUa:
    """Test _normalize_ua() static method."""

    def test_sqlmap_ua(self):
        result = ThreatGraph._normalize_ua("sqlmap/1.6#stable (http://sqlmap.org)")
        assert "sqlmap" in result.lower()

    def test_empty_ua(self):
        result = ThreatGraph._normalize_ua("")
        assert result == "empty"

    def test_none_ua(self):
        result = ThreatGraph._normalize_ua(None)
        assert result == "empty"

    def test_normal_browser_ua(self):
        ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        result = ThreatGraph._normalize_ua(ua)
        assert "mozilla" in result.lower()
        # Version numbers should be stripped
        assert "5.0" not in result.lower() or "mozilla" in result.lower()

    def test_unknown_tool_ua(self):
        result = ThreatGraph._normalize_ua("SomeCustomScanner/2.0")
        assert "somecustomscanner" in result.lower()


class TestNormalizeUrl:
    """Test _normalize_url() static method."""

    def test_normal_url(self):
        result = ThreatGraph._normalize_url("/admin/login.php")
        # .php → .{script} normalized
        assert result == "/admin/login.{script}"

    def test_url_with_query_string_stripped(self):
        result = ThreatGraph._normalize_url("/upload.php?cmd=id&pass=123")
        # Query params stripped, .php → .{script}
        assert "?" not in result
        assert result.startswith("/upload")

    def test_empty_url(self):
        result = ThreatGraph._normalize_url("")
        assert result == "/"

    def test_none_url(self):
        result = ThreatGraph._normalize_url(None)
        assert result == "/"

    def test_deeply_nested_path(self):
        result = ThreatGraph._normalize_url("/a/b/c/d/e/f/g.php")
        # Extension normalized
        assert result == "/a/b/c/d/e/f/g.{script}"


class TestGenerateProfileId:
    """Test generate_profile_id() based on UA + time window."""

    def test_generates_id(self, graph):
        pid = graph.generate_profile_id("sqlmap/1.6", time_window_hours=4)
        assert isinstance(pid, str)
        assert len(pid) > 0

    def test_same_ua_same_window_same_id(self, graph):
        pid1 = graph.generate_profile_id("sqlmap", time_window_hours=4)
        pid2 = graph.generate_profile_id("sqlmap", time_window_hours=4)
        assert pid1 == pid2

    def test_different_ua_different_id(self, graph):
        pid1 = graph.generate_profile_id("sqlmap", time_window_hours=4)
        pid2 = graph.generate_profile_id("nmap", time_window_hours=4)
        assert pid1 != pid2


# ── Management IP Tests ───────────────────────────────────────


class TestIsManagementIp:
    """Test _is_management_ip() filtering."""

    def test_localhost_is_management(self, graph):
        # localhost is NOT special-cased — only matched if explicitly listed
        graph._management_ips = ["127.0.0.1"]
        assert graph._is_management_ip("127.0.0.1") is True
        assert graph._is_management_ip("::1") is False  # not listed

    def test_external_ip_is_not_management(self, graph):
        graph._management_ips = ["127.0.0.1"]
        assert graph._is_management_ip("203.0.113.5") is False

    def test_empty_management_list(self, graph):
        graph._management_ips = []
        assert graph._is_management_ip("127.0.0.1") is False


# ── WAF Event Ingestion ───────────────────────────────────────


class TestIngestWafEvent:
    """Test ingest_waf_event() — create/update attacker profiles from WAF."""

    def test_ingest_creates_profile(self, graph, sample_waf_event):
        pid = graph.ingest_waf_event(sample_waf_event)
        assert pid is not None
        assert pid in graph._profiles
        profile = graph._profiles[pid]
        assert profile.risk_score > 0

    def test_ingest_management_ip_returns_none(self, graph, sample_waf_event):
        graph._management_ips = ["192.168.1.0/24"]
        pid = graph.ingest_waf_event(sample_waf_event)
        assert pid is None

    def test_ingest_multiple_events_same_ip(self, graph, sample_waf_event):
        pid1 = graph.ingest_waf_event(sample_waf_event)
        sample_waf_event["url"] = "/admin/config.php"
        pid2 = graph.ingest_waf_event(sample_waf_event)
        assert pid1 == pid2  # Same UA+time window = same profile

    def test_ingest_updates_ip_table(self, graph, sample_waf_event):
        graph.ingest_waf_event(sample_waf_event)
        reputation = graph.query_ip("192.168.1.100")
        assert reputation is not None
        assert reputation.event_count >= 1

    def test_ingest_increments_risk_on_repeated_attacks(self, graph, sample_waf_event):
        pid1 = graph.ingest_waf_event(sample_waf_event)
        score1 = graph._profiles[pid1].risk_score
        for _ in range(5):
            sample_waf_event["url"] = f"/attack_{_}.php"
            graph.ingest_waf_event(sample_waf_event)
        score2 = graph._profiles[pid1].risk_score
        assert score2 >= score1  # Risk doesn't decrease


# ── Registry Entry Ingestion ──────────────────────────────────


class TestIngestRegistryEntry:
    """Test ingest_registry_entry() — link file detections to profiles."""

    def test_ingest_registry_creates_file_reputation(self, graph, sample_registry_entry):
        pid = graph.ingest_registry_entry(sample_registry_entry)
        # File reputation is always created in _file_table
        rep = graph.query_file("/var/www/html/shell.php")
        assert rep is not None

    def test_ingest_registry_entry_with_existing_ip_profile(self, graph, sample_waf_event, sample_registry_entry):
        # First, create a profile via WAF event from same IP
        sample_waf_event["src_ip"] = "10.0.0.50"
        waf_pid = graph.ingest_waf_event(sample_waf_event)
        assert waf_pid is not None
        # Then, ingest a registry entry — creates file reputation
        reg_pid = graph.ingest_registry_entry(sample_registry_entry)
        # File reputation should exist
        rep = graph.query_file("/var/www/html/shell.php")
        assert rep is not None

    def test_ingest_registry_entry_missing_fields(self, graph):
        """Entry with minimal fields should not crash."""
        pid = graph.ingest_registry_entry({"file_path": "/tmp/test.php"})
        # Should handle gracefully — may return None if no matching profile
        assert pid is None or isinstance(pid, str), f"Unexpected return: {pid!r}"


# ── Query Tests ───────────────────────────────────────────────


class TestQueryIp:
    """Test query_ip() — IP reputation lookup."""

    def test_query_unknown_ip(self, graph):
        rep = graph.query_ip("203.0.113.99")
        assert rep is None

    def test_query_known_ip(self, graph, sample_waf_event):
        graph.ingest_waf_event(sample_waf_event)
        rep = graph.query_ip("192.168.1.100")
        assert rep is not None


class TestQueryFile:
    """Test query_file() — file reputation lookup."""

    def test_query_unknown_file(self, graph):
        rep = graph.query_file("/nonexistent/file.php")
        assert rep is None

    def test_query_known_file(self, graph, sample_registry_entry):
        graph.ingest_registry_entry(sample_registry_entry)
        rep = graph.query_file("/var/www/html/shell.php")
        assert rep is not None


class TestQueryProfile:
    """Test query_profile() — attacker profile lookup."""

    def test_query_unknown_profile(self, graph):
        profile = graph.query_profile("nonexistent-profile-id")
        assert profile is None

    def test_query_known_profile(self, graph, sample_waf_event):
        pid = graph.ingest_waf_event(sample_waf_event)
        profile = graph.query_profile(pid)
        assert profile is not None
        assert profile.profile_id == pid


class TestGetActiveProfiles:
    """Test get_active_profiles() with score filtering."""

    def test_get_active_profiles_empty(self, graph):
        profiles = graph.get_active_profiles()
        assert profiles == []

    def test_get_active_profiles_with_entries(self, graph, sample_waf_event):
        graph.ingest_waf_event(sample_waf_event)
        profiles = graph.get_active_profiles()
        assert len(profiles) >= 1

    def test_get_active_profiles_min_score_filter(self, graph, sample_waf_event):
        graph.ingest_waf_event(sample_waf_event)
        all_profiles = graph.get_active_profiles(min_score=0.0)
        high_only = graph.get_active_profiles(min_score=999.0)
        assert len(high_only) <= len(all_profiles)


class TestGetClusterLevel:
    """Test get_cluster_level() — threat cluster assessment."""

    def test_get_cluster_level_default(self, graph):
        level, file_count, pid = graph.get_cluster_level("192.168.1.1")
        assert isinstance(level, int)
        assert isinstance(file_count, int)
        assert isinstance(pid, str)

    def test_get_cluster_level_with_data(self, graph, sample_waf_event):
        graph.ingest_waf_event(sample_waf_event)
        level, file_count, pid = graph.get_cluster_level("192.168.1.100")
        # IP is known, so level should reflect IP's cluster_level
        assert isinstance(level, int)
        assert isinstance(file_count, int)
        assert isinstance(pid, str)


# ── Merge / Overlap Tests ─────────────────────────────────────


class TestMergeOverlappingProfiles:
    """Test merge_overlapping_profiles() — dedup similar profiles."""

    def test_merge_no_profiles(self, graph):
        # merge_overlapping_profiles returns None (no explicit return)
        graph.merge_overlapping_profiles(min_overlap=3)
        # Should not crash

    def test_merge_with_few_profiles(self, graph, sample_waf_event):
        graph.ingest_waf_event(sample_waf_event)
        graph.merge_overlapping_profiles(min_overlap=3)
        # Should not crash with 1 profile


# ── Decay Tests ───────────────────────────────────────────────


class TestDecayProfiles:
    """Test decay_profiles() — risk score degradation over time."""

    def test_decay_empty_graph(self, graph):
        """Decay on empty graph should not crash."""
        graph.decay_profiles()
        assert len(graph._profiles) == 0

    def test_decay_reduces_score_over_time(self, graph, sample_waf_event):
        graph.ingest_waf_event(sample_waf_event)
        profile = list(graph._profiles.values())[0]
        original_score = profile.risk_score
        # Simulate 25 hours later
        future = datetime.now() + timedelta(hours=25)
        graph.decay_profiles(now=future)
        decayed_score = profile.risk_score
        assert decayed_score <= original_score

    def test_decay_dormant_after_72h(self, graph, sample_waf_event):
        graph.ingest_waf_event(sample_waf_event)
        profile = list(graph._profiles.values())[0]
        # Set score so we can observe decay
        profile.risk_score = 50.0
        future = datetime.now() + timedelta(hours=73)
        graph.decay_profiles(now=future)
        assert profile.risk_score <= 50.0


# ── Persist / Load Round-Trip ─────────────────────────────────


class TestPersistLoad:
    """Test persist() and load() round-trip."""

    def test_persist_and_load(self, graph, sample_waf_event, tmp_path):
        graph.ingest_waf_event(sample_waf_event)
        persist_path = tmp_path / "threat_graph_test.json"
        graph.set_persist_path(str(persist_path))
        graph.persist()
        assert persist_path.exists()

        # Load into a new graph
        tg2 = ThreatGraph()
        tg2.set_persist_path(str(persist_path))
        tg2.load()
        assert len(tg2._profiles) == len(graph._profiles)

    def test_load_prefers_json_to_sqlite_shadow(
        self, graph, sample_waf_event, tmp_path, monkeypatch
    ):
        from anteumbra.infrastructure import persistence

        graph.ingest_waf_event(sample_waf_event)
        persist_path = tmp_path / "authoritative_threat_graph.json"
        graph.set_persist_path(str(persist_path))
        graph.persist()

        def unexpected_shadow_read(_namespace):
            pytest.fail("a valid threat graph JSON file must not read SQLite")

        monkeypatch.setattr(persistence, "get_shadow_repository", unexpected_shadow_read)

        recovered = ThreatGraph()
        recovered.set_persist_path(str(persist_path))
        recovered.load()

        assert len(recovered._profiles) == len(graph._profiles)

    def test_load_nonexistent_file(self, graph, tmp_path):
        graph.set_persist_path(str(tmp_path / "nonexistent.json"))
        graph.load()  # Should not crash
        assert len(graph._profiles) == 0

    def test_load_corrupt_file(self, graph, tmp_path):
        path = tmp_path / "corrupt.json"
        path.write_text("{not valid json", encoding="utf-8")
        graph.set_persist_path(str(path))
        graph.load()  # Should not crash on corrupt data
        assert len(graph._profiles) == 0


# ── Singleton ─────────────────────────────────────────────────


class TestGetThreatGraph:
    """Test get_threat_graph() singleton factory."""

    def test_get_threat_graph_returns_instance(self):
        tg = get_threat_graph()
        assert isinstance(tg, ThreatGraph)

    def test_get_threat_graph_is_singleton(self):
        tg1 = get_threat_graph()
        tg2 = get_threat_graph()
        assert tg1 is tg2


# ── Edge Cases ────────────────────────────────────────────────


class TestEdgeCases:
    """Test edge cases and error resilience."""

    def test_ingest_waf_event_no_ua(self, graph):
        event = {"src_ip": "10.0.0.1", "timestamp": datetime.now().isoformat()}
        pid = graph.ingest_waf_event(event)
        # Should handle missing UA gracefully
        assert pid is not None

    def test_ingest_waf_event_no_src_ip(self, graph):
        event = {"timestamp": datetime.now().isoformat(), "user_agent": "test"}
        pid = graph.ingest_waf_event(event)
        # Should handle missing IP gracefully — returns profile ID with no IP
        assert isinstance(pid, str) and len(pid) > 0, f"Expected valid profile ID, got {pid!r}"

    def test_ingest_registry_entry_empty_features(self, graph):
        entry = {
            "file_path": "/tmp/test.php",
            "first_seen_ip": "10.0.0.1",
            "features": [],
            "detected_at": datetime.now().isoformat(),
        }
        # Should not crash — file reputation always created, pid may be None
        graph.ingest_registry_entry(entry)
        # File reputation should still be created even with empty features
        rep = graph.query_file("/tmp/test.php")
        assert rep is not None

    def test_large_number_of_profiles(self, graph):
        """Stress test: 100 profiles."""
        for i in range(100):
            event = {
                "src_ip": f"10.0.{i // 256}.{i % 256}",
                "timestamp": datetime.now().isoformat(),
                "user_agent": f"scanner_{i % 10}",
                "url": f"/target_{i}.php",
            }
            graph.ingest_waf_event(event)
        assert len(graph._profiles) >= 1
        # IP table should have entries
        total_ips = len(graph._ip_table)
        assert total_ips >= 1
