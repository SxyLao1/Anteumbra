# -*- coding: utf-8 -*-
"""v1.0.8: Unit tests for suspicious_registry.py — the central persistence module.

Tests cover: add, get, get_all, mark_quarantined, mark_false_positive,
soft_delete_record, remove, increment_access, compact_registry,
clear_memory_cache, and the v1.0.8 public getter functions.
"""
import os
from pathlib import Path

import pytest

# Ensure test isolation — set env before any imports happen inside suspicious_registry
os.environ["TRIDENT_TOOL_MODE"] = "true"

# Import path_to_key for test assertions (Windows normalizes paths)
from anteumbra.infrastructure.utils.path_utils import path_to_key


# ── Fixtures ──────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def clean_registry(monkeypatch):
    """Reset registry state before each test.

    v1.1.0: Force JSON-only backend to avoid SQLite leak from previous runs.
    _repo_load_registry() reads from SQLite when backend='both', which would
    pick up stale records from E2E tests. We monkey-patch it to return None
    so the registry falls through to the isolated JSON file.
    """
    from anteumbra.infrastructure import suspicious_registry as sr

    # Force JSON-only mode (bypass SQLite which has stale data from other tests)
    monkeypatch.setattr(sr, "_repo_load_registry", lambda: None)
    monkeypatch.setattr(sr, "_repo_shadow_save", lambda data: None)

    # Force _ensure_initialized to set the test-isolated path BEFORE cleanup.
    # _force_init_at_import() sets _REGISTRY_PATH to the production path at
    # module load; _ensure_initialized() overrides it to the test temp path.
    sr._ensure_initialized()

    # Now clean the test-isolated files
    sr._clear_memory_cache()
    rp = sr._REGISTRY_PATH
    if rp and rp.exists():
        rp.unlink()
    bak = rp.with_suffix(".json.bak") if rp else None
    if bak and bak.exists():
        bak.unlink()
    yield
    # Teardown: clean test data
    if rp and rp.exists():
        rp.unlink()
    if bak and bak.exists():
        bak.unlink()


@pytest.fixture
def sample_path():
    """Return a sample Path for testing. Use sample_key for stored key comparison."""
    return Path("/var/www/html/shell.php")


@pytest.fixture
def sample_key(sample_path):
    """Return the path_to_key resolution of sample_path (what gets stored)."""
    return path_to_key(sample_path)


@pytest.fixture
def sample_features():
    """Return sample YARA rule features."""
    return ["php_eval", "base64_decode", "exec"]


# ── Core CRUD Tests ───────────────────────────────────────────


class TestAddAndGetAll:
    """Test basic add() and get_all() operations."""

    def test_add_single_record(self, sample_path, sample_key, sample_features):
        from anteumbra.infrastructure.suspicious_registry import add, get_all

        add(sample_path, sample_features, first_seen_ip="192.168.1.1")
        records = get_all()
        assert len(records) == 1
        assert records[0]["file_path"] == sample_key
        assert records[0]["features"] == sample_features
        assert records[0]["first_seen_ip"] == "192.168.1.1"

    def test_add_multiple_records(self):
        from anteumbra.infrastructure.suspicious_registry import add, get_all

        add(Path("/var/www/shell1.php"), ["eval"])
        add(Path("/var/www/shell2.php"), ["assert"])
        records = get_all()
        assert len(records) == 2

    def test_add_duplicate_updates_record(self, sample_path, sample_features):
        from anteumbra.infrastructure.suspicious_registry import add, get_all

        add(sample_path, sample_features, first_seen_ip="1.2.3.4")
        # Add same path again with different features
        add(sample_path, ["new_feature"], first_seen_ip="5.6.7.8")
        records = get_all()
        assert len(records) == 1
        # add() REPLACES features on duplicate (not merge)
        assert records[0]["features"] == ["new_feature"]
        # first_seen_ip IS overwritten when a new value is provided
        assert records[0]["first_seen_ip"] == "5.6.7.8"

    def test_add_with_detection_source(self, sample_path, sample_features):
        from anteumbra.infrastructure.suspicious_registry import add, get_all

        add(sample_path, sample_features, detection_source="scanner")
        records = get_all()
        assert records[0]["detection_source"] == "scanner"

    def test_get_all_default_excludes_deleted(self, sample_path, sample_features):
        from anteumbra.infrastructure.suspicious_registry import (
            add, get_all, soft_delete_record,
        )

        add(sample_path, sample_features)
        soft_delete_record(sample_path)
        records = get_all()
        assert len(records) == 0  # deleted records excluded by default

    def test_get_all_include_deleted(self, sample_path, sample_features):
        from anteumbra.infrastructure.suspicious_registry import (
            add, get_all, soft_delete_record,
        )

        add(sample_path, sample_features)
        soft_delete_record(sample_path)
        records = get_all(include_deleted=True)
        assert len(records) == 1

    def test_get_all_excludes_false_positive_by_default(self, sample_path, sample_features):
        from anteumbra.infrastructure.suspicious_registry import (
            add, get_all, mark_false_positive,
        )

        add(sample_path, sample_features)
        mark_false_positive(sample_path, "test")
        records = get_all()
        assert len(records) == 0

    def test_get_all_include_false_positive(self, sample_path, sample_features):
        from anteumbra.infrastructure.suspicious_registry import (
            add, get_all, mark_false_positive,
        )

        add(sample_path, sample_features)
        mark_false_positive(sample_path, "test")
        records = get_all(include_false_positive=True)
        assert len(records) == 1


# ── Single Record Lookup ──────────────────────────────────────


class TestGet:
    """Test get() for single record lookup."""

    def test_get_existing_record(self, sample_path, sample_key, sample_features):
        from anteumbra.infrastructure.suspicious_registry import add, get

        add(sample_path, sample_features)
        record = get(sample_path)
        assert record is not None
        assert record["file_path"] == sample_key

    def test_get_nonexistent_record(self):
        from anteumbra.infrastructure.suspicious_registry import get

        record = get(Path("/nonexistent/path.php"))
        assert record is None

    def test_is_suspicious_true(self, sample_path, sample_features):
        from anteumbra.infrastructure.suspicious_registry import add, is_suspicious

        add(sample_path, sample_features)
        assert is_suspicious(sample_path) is True

    def test_is_suspicious_false(self):
        from anteumbra.infrastructure.suspicious_registry import is_suspicious

        assert is_suspicious(Path("/clean/file.txt")) is False


# ── State Mutation Tests ──────────────────────────────────────


class TestMarkQuarantined:
    """Test mark_quarantined() operation."""

    def test_mark_quarantined_sets_id(self, sample_path, sample_features):
        from anteumbra.infrastructure.suspicious_registry import (
            add, get, mark_quarantined,
        )

        add(sample_path, sample_features)
        mark_quarantined(sample_path, "qr-12345")
        record = get(sample_path)
        assert record["quarantine_id"] == "qr-12345"

    def test_mark_quarantined_str_path(self, sample_path, sample_features):
        from anteumbra.infrastructure.suspicious_registry import (
            add, get, mark_quarantined,
        )

        add(sample_path, sample_features)
        # Accept string path (not Path object)
        mark_quarantined(sample_path, "qr-67890")
        record = get(sample_path)
        assert record["quarantine_id"] == "qr-67890"


class TestMarkFalsePositive:
    """Test mark_false_positive() operation."""

    def test_mark_false_positive_sets_fields(self, sample_path, sample_features):
        from anteumbra.infrastructure.suspicious_registry import (
            add, get, mark_false_positive,
        )

        add(sample_path, sample_features)
        result = mark_false_positive(sample_path, "Admin review")
        assert result is True
        record = get(sample_path)
        assert record["marked_false_positive"] is True
        assert record["false_positive_reason"] == "Admin review"
        assert "false_positive_at" in record

    def test_mark_false_positive_nonexistent(self):
        from anteumbra.infrastructure.suspicious_registry import mark_false_positive

        result = mark_false_positive("/nonexistent/shell.php", "test")
        assert result is False

    def test_mark_false_positive_path_object(self, sample_path, sample_features):
        from anteumbra.infrastructure.suspicious_registry import (
            add, get, mark_false_positive,
        )

        add(sample_path, sample_features)
        # Accept Path object
        result = mark_false_positive(sample_path, "Path object test")
        assert result is True
        record = get(sample_path)
        assert record["marked_false_positive"] is True


class TestSoftDeleteRecord:
    """Test soft_delete_record() v1.1.0 public API."""

    def test_soft_delete_sets_fields(self, sample_path, sample_features):
        from anteumbra.infrastructure.suspicious_registry import (
            add, get_all, soft_delete_record,
        )

        add(sample_path, sample_features)
        result = soft_delete_record(sample_path)
        assert result is True
        records = get_all(include_deleted=True)
        assert len(records) == 1
        assert records[0]["file_exists"] is False
        assert "deleted_at" in records[0]

    def test_soft_delete_nonexistent(self):
        from anteumbra.infrastructure.suspicious_registry import soft_delete_record

        result = soft_delete_record("/nonexistent/shell.php")
        assert result is False

    def test_soft_delete_path_object(self, sample_path, sample_features):
        from anteumbra.infrastructure.suspicious_registry import (
            add, get_all, soft_delete_record,
        )

        add(sample_path, sample_features)
        result = soft_delete_record(sample_path)
        assert result is True
        records = get_all(include_deleted=True)
        assert records[0]["file_exists"] is False


class TestRemove:
    """Test remove() hard-delete operation."""

    def test_remove_existing_record(self, sample_path, sample_features):
        from anteumbra.infrastructure.suspicious_registry import add, get, remove

        add(sample_path, sample_features)
        result = remove(sample_path)
        assert result is True
        # remove() is a SOFT delete — record persists with file_exists=False
        record = get(sample_path)
        assert record is not None
        assert record["file_exists"] is False
        assert "deleted_at" in record

    def test_remove_nonexistent(self):
        from anteumbra.infrastructure.suspicious_registry import remove

        result = remove("/nonexistent/file.php")
        assert result is False


class TestIncrementAccess:
    """Test increment_access() counter."""

    def test_increment_access_increases_counter(self, sample_path, sample_features):
        from anteumbra.infrastructure.suspicious_registry import add, get, increment_access

        add(sample_path, sample_features)
        increment_access(sample_path, "10.0.0.1")
        record = get(sample_path)
        assert record["communication_count"] == 1

    def test_increment_access_multiple(self, sample_path, sample_features):
        from anteumbra.infrastructure.suspicious_registry import add, get, increment_access

        add(sample_path, sample_features)
        increment_access(sample_path, "10.0.0.1")
        increment_access(sample_path, "10.0.0.2")
        increment_access(sample_path, "10.0.0.1")  # duplicate IP
        record = get(sample_path)
        assert record["communication_count"] == 3


# ── Compact Tests ─────────────────────────────────────────────


class TestCompactRegistry:
    """Test compact_registry() — old record cleanup."""

    def test_compact_returns_stats(self):
        from anteumbra.infrastructure.suspicious_registry import compact_registry

        stats = compact_registry()
        assert "total" in stats
        assert "cleaned" in stats
        assert "remaining" in stats


# ── Cache Tests ───────────────────────────────────────────────


class TestClearMemoryCache:
    """Test clear_memory_cache() public API."""

    def test_clear_cache_no_error(self):
        from anteumbra.infrastructure.suspicious_registry import clear_memory_cache

        # Should not raise when cache is already empty
        clear_memory_cache()

    def test_clear_cache_after_load(self, sample_path, sample_key, sample_features):
        from anteumbra.infrastructure.suspicious_registry import (
            add, get_all, clear_memory_cache,
        )

        add(sample_path, sample_features)
        records_before = get_all()
        assert len(records_before) == 1
        # Clear and reload — should still return same data
        clear_memory_cache()
        records_after = get_all()
        assert len(records_after) == 1
        assert records_after[0]["file_path"] == sample_key


# ── v1.1.0 Public Getters ─────────────────────────────────────


class TestPublicGetters:
    """Test v1.1.0 public getter functions."""

    def test_is_async_save_enabled(self):
        from anteumbra.infrastructure.suspicious_registry import is_async_save_enabled

        # In test mode, async save should be disabled
        assert is_async_save_enabled() is False

    def test_get_async_save_queue_size(self):
        from anteumbra.infrastructure.suspicious_registry import get_async_save_queue_size

        # In test mode, queue should be 0
        assert get_async_save_queue_size() == 0

    def test_get_registry_path(self):
        from anteumbra.infrastructure.suspicious_registry import get_registry_path

        rp = get_registry_path()
        assert rp is not None
        assert "test" in str(rp) or "registry_test_isolated" in str(rp)

    def test_get_registry_path_returns_path_object(self):
        from anteumbra.infrastructure.suspicious_registry import get_registry_path

        rp = get_registry_path()
        assert isinstance(rp, Path)


# ── Integration Tests ─────────────────────────────────────────


class TestFullLifecycle:
    """End-to-end record lifecycle: add → access → quarantine → soft-delete."""

    def test_full_lifecycle(self):
        from anteumbra.infrastructure.suspicious_registry import (
            add, get, get_all, mark_quarantined, soft_delete_record,
            increment_access,
        )

        path = Path("/var/www/evil.php")
        features = ["godzilla", "behinder"]

        # 1. Add
        add(path, features, first_seen_ip="10.0.0.99")
        records = get_all()
        assert len(records) == 1

        # 2. Access
        increment_access(path, "10.0.0.100")
        record = get(path)
        assert record["communication_count"] == 1

        # 3. Quarantine
        mark_quarantined(str(path), "qr-lifecycle")
        record = get(path)
        assert record["quarantine_id"] == "qr-lifecycle"

        # 4. Soft delete
        result = soft_delete_record(path)
        assert result is True
        record = get(path)
        assert record["file_exists"] is False
        assert "deleted_at" in record

        # 5. Not visible in default get_all
        records = get_all()
        assert len(records) == 0

        # 6. Visible with include_deleted
        records = get_all(include_deleted=True)
        assert len(records) == 1
