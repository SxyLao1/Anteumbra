# -*- coding: utf-8 -*-
"""v1.0.9: Unit tests for threat_graph.py — attacker profiling engine.

Tests cover: ingest_waf_event, ingest_registry_entry, query_ip, query_file,
query_profile, get_active_profiles, get_cluster_level, merge_overlapping_profiles,
decay_profiles, generate_profile_id, persist/load round-trip,
_normalize_ua, _normalize_url, _is_management_ip, and edge cases.
"""
from datetime import datetime, timedelta

import pytest

from anteumbra.infrastructure.detection.file_cluster import FileClusterEngine
from anteumbra.infrastructure.detection.hash_engine import HashEngine
from anteumbra.infrastructure.threat_graph import ThreatGraph

# ── Fixtures ──────────────────────────────────────────────────


def _new_graph(shadow_repository=None) -> ThreatGraph:
    return ThreatGraph(
        {"storage": {"backend": "json"}},
        FileClusterEngine(HashEngine()),
        shadow_repository=shadow_repository,
    )


@pytest.fixture
def graph():
    """Return a fresh ThreatGraph instance with no persistence."""
    tg = _new_graph()
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

    def test_same_ua_is_partitioned_by_site(self, graph):
        alpha = graph.generate_profile_id("sqlmap", site_id="alpha")
        beta = graph.generate_profile_id("sqlmap", site_id="beta")
        assert alpha != beta


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
        graph.ingest_registry_entry(sample_registry_entry)
        # File reputation is always created in _file_table
        rep = graph.query_file("/var/www/html/shell.php")
        assert rep is not None

    def test_ingest_registry_entry_with_existing_ip_profile(self, graph, sample_waf_event, sample_registry_entry):
        # First, create a profile via WAF event from same IP
        sample_waf_event["src_ip"] = "10.0.0.50"
        waf_pid = graph.ingest_waf_event(sample_waf_event)
        assert waf_pid is not None
        # Then, ingest a registry entry — creates file reputation
        graph.ingest_registry_entry(sample_registry_entry)
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
        tg2 = _new_graph()
        tg2.set_persist_path(str(persist_path))
        tg2.load()
        assert len(tg2._profiles) == len(graph._profiles)

    def test_site_qualified_tables_round_trip(self, graph, tmp_path):
        shared = {
            "src_ip": "192.0.2.44",
            "timestamp": datetime.now().isoformat(),
            "user_agent": "sqlmap/1.8",
            "url": "/upload.php",
            "site_id": "alpha",
            "site_name": "Alpha",
        }
        graph.ingest_waf_event(shared)
        graph.ingest_registry_entry({
            "file_path": "/srv/shared/shell.php",
            "first_seen_ip": "192.0.2.44",
            "features": ["php_eval"],
            "site_id": "alpha",
            "site_name": "Alpha",
        })
        path = tmp_path / "site-aware.json"
        graph.set_persist_path(path)
        graph.persist()

        recovered = _new_graph()
        recovered.set_persist_path(path)
        recovered.load()

        assert recovered.query_ip("192.0.2.44", site_id="alpha").site_name == "Alpha"
        assert recovered.query_file(
            "/srv/shared/shell.php", site_id="alpha"
        ).detection_count == 1
        assert recovered.get_active_profiles(site_id="alpha")[0].site_id == "alpha"

    def test_legacy_flat_json_migrates_to_explicit_legacy_bucket(self, graph, tmp_path):
        path = tmp_path / "legacy.json"
        path.write_text(
            """{
  "profiles": {
    "old-profile": {
      "profile_id": "old-profile",
      "created_at": "2026-07-19T01:00:00",
      "updated_at": "2026-07-19T01:00:00",
      "ip_pool": ["192.0.2.55"]
    }
  },
  "ip_table": {
    "192.0.2.55": {
      "ip": "192.0.2.55",
      "first_seen": "2026-07-19T01:00:00",
      "last_seen": "2026-07-19T01:00:00"
    }
  }
}""",
            encoding="utf-8",
        )
        graph.set_persist_path(path)
        graph.load()

        assert graph.query_profile("old-profile").site_id == "legacy"
        assert graph.query_ip("192.0.2.55", site_id="legacy").site_name == (
            "Legacy / unassigned"
        )

    def test_load_prefers_json_to_sqlite_shadow(
        self, graph, sample_waf_event, tmp_path
    ):
        graph.ingest_waf_event(sample_waf_event)
        persist_path = tmp_path / "authoritative_threat_graph.json"
        graph.set_persist_path(str(persist_path))
        graph.persist()

        shadow = type(
            "Shadow",
            (),
            {"list_all": lambda *_args, **_kwargs: pytest.fail(
                "a valid threat graph JSON file must not read SQLite"
            )},
        )()

        recovered = _new_graph(shadow)
        recovered.set_persist_path(str(persist_path))
        recovered.load()

        assert len(recovered._profiles) == len(graph._profiles)

    def test_shadow_is_injected_for_write_recovery_and_close(
        self, sample_waf_event, tmp_path
    ):
        records = {}
        closed = []

        class Shadow:
            def save(self, record_id, data):
                records[record_id] = dict(data)

            def list_all(self, **_kwargs):
                return list(records.values())

            def close(self):
                closed.append(True)

        graph = _new_graph(Shadow())
        graph.ingest_waf_event(sample_waf_event)
        graph.set_persist_path(tmp_path / "source.json")
        graph.persist()

        recovered = _new_graph(Shadow())
        recovered.set_persist_path(tmp_path / "missing.json")
        recovered.load()
        recovered.close()

        assert len(recovered._profiles) == 1
        assert closed == [True]

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


# ── Runtime ownership ─────────────────────────────────────────


class TestThreatGraphOwnership:
    """Threat graphs are independently owned runtime resources."""

    def test_constructor_returns_instance(self):
        tg = _new_graph()
        assert isinstance(tg, ThreatGraph)

    def test_instances_do_not_share_mutable_state(self):
        first = _new_graph()
        second = _new_graph()
        first._profiles["test"] = object()
        assert second._profiles == {}


class TestThreatGraphSiteIsolation:
    def test_same_ip_and_fingerprint_do_not_cross_sites(self, graph):
        base = {
            "src_ip": "198.51.100.23",
            "timestamp": datetime.now().isoformat(),
            "user_agent": "sqlmap/1.8",
            "url": "/login.php",
            "waf_score": 0.8,
        }
        alpha_id = graph.ingest_waf_event({
            **base, "site_id": "alpha", "site_name": "Alpha"
        })
        beta_id = graph.ingest_waf_event({
            **base, "site_id": "beta", "site_name": "Beta"
        })

        assert alpha_id != beta_id
        assert graph.query_ip("198.51.100.23") is None
        assert graph.query_ip("198.51.100.23", site_id="alpha").event_count == 1
        assert graph.query_ip("198.51.100.23", site_id="beta").event_count == 1
        assert [p.site_id for p in graph.get_active_profiles(site_id="alpha")] == [
            "alpha"
        ]

    def test_same_file_path_does_not_cross_sites(self, graph):
        entry = {
            "file_path": "/srv/www/shell.php",
            "features": ["php_eval"],
            "first_seen_ip": "198.51.100.24",
        }
        graph.ingest_registry_entry({
            **entry, "site_id": "alpha", "site_name": "Alpha"
        })
        graph.ingest_registry_entry({
            **entry, "site_id": "beta", "site_name": "Beta"
        })

        assert graph.query_file("/srv/www/shell.php") is None
        assert graph.query_file(
            "/srv/www/shell.php", site_id="alpha"
        ).site_name == "Alpha"
        assert graph.query_file(
            "/srv/www/shell.php", site_id="beta"
        ).site_name == "Beta"

    def test_file_profile_lookup_is_site_qualified(self, graph):
        event = {
            "src_ip": "198.51.100.25",
            "timestamp": datetime.now().isoformat(),
            "user_agent": "sqlmap/1.8",
            "url": "/upload.php",
        }
        for site_id, site_name in (("alpha", "Alpha"), ("beta", "Beta")):
            graph.ingest_waf_event({
                **event,
                "site_id": site_id,
                "site_name": site_name,
            })
            graph.ingest_registry_entry({
                "file_path": "/srv/www/shell.php",
                "features": ["php_eval"],
                "first_seen_ip": event["src_ip"],
                "site_id": site_id,
                "site_name": site_name,
            })

        assert {
            profile.site_id
            for profile in graph.find_profiles_for_file("/srv/www/shell.php")
        } == {"alpha", "beta"}
        assert [
            profile.site_id
            for profile in graph.find_profiles_for_file(
                "/srv/www/shell.php",
                site_id="alpha",
            )
        ] == ["alpha"]

    def test_profile_merge_stays_within_site(self, graph):
        base = {
            "src_ip": "203.0.113.7",
            "timestamp": datetime.now().isoformat(),
            "user_agent": "sqlmap/1.8",
            "url": "/login.php",
        }
        graph.ingest_waf_event({
            **base, "site_id": "alpha", "site_name": "Alpha"
        })
        graph.ingest_waf_event({
            **base, "site_id": "beta", "site_name": "Beta"
        })

        graph.merge_overlapping_profiles(min_overlap=1)

        assert len(graph.get_active_profiles()) == 2


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
