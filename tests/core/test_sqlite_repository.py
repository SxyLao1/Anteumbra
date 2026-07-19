"""Tests for core/repositories/sqlite_repository.py"""
import pytest
from anteumbra.infrastructure.persistence.sqlite_repository import SqliteRepository, DualWriteRepository
from anteumbra.infrastructure.persistence.json_repository import JsonRepository


@pytest.fixture
def sql_repo(temp_dir):
    p = temp_dir / "test.db"
    repo = SqliteRepository(str(p))
    yield repo
    repo.close()


class TestSqliteRepository:
    def test_save_and_get(self, sql_repo):
        sql_repo.save("rec-1", {"file_path": "/tmp/test.php", "features": ["a", "b"]})
        r = sql_repo.get("rec-1")
        assert r is not None
        assert "file_path" in r

    def test_registry_preserves_site_metadata_and_raw_fields(self, sql_repo):
        sql_repo.save(
            "rec-site",
            {
                "file_path": "/tmp/site.php",
                "features": ["rule"],
                "site_id": "alpha",
                "site_name": "Alpha",
                "false_positive_reason": "reviewed",
            },
        )

        record = sql_repo.get("rec-site")

        assert record["site_id"] == "alpha"
        assert record["site_name"] == "Alpha"
        assert record["false_positive_reason"] == "reviewed"
        assert sql_repo.query({"site_id": "alpha"})[0]["record_id"] == "rec-site"

    def test_delete(self, sql_repo):
        sql_repo.save("rec-x", {"file_path": "/tmp/x.php"})
        assert sql_repo.delete("rec-x") is True
        assert sql_repo.get("rec-x") is None

    def test_count(self, sql_repo):
        assert sql_repo.count() == 0
        sql_repo.save("a", {"file_path": "/a"})
        sql_repo.save("b", {"file_path": "/b"})
        assert sql_repo.count() == 2

    def test_list_all_pagination(self, sql_repo):
        for i in range(10):
            sql_repo.save(f"r{i}", {"file_path": f"/tmp/{i}.php", "detected_at": f"2026-06-28T12:0{i}:00"})
        page = sql_repo.list_all(limit=3, offset=0)
        assert len(page) == 3

    def test_site_qualified_ledger_crud(self, temp_dir):
        repo = SqliteRepository(
            str(temp_dir / "ledger.db"),
            table_name="block_ledger_entries",
            key_column="record_id",
            sort_column="blocked_at",
        )
        try:
            repo.save("alpha|10.0.0.1", {
                "record_id": "alpha|10.0.0.1",
                "site_id": "alpha",
                "site_name": "Alpha",
                "ip": "10.0.0.1",
                "source": "manual",
                "reason": "test block",
                "broadcast_devices": ["stdout"],
                "broadcast_status": "success",
            })

            entry = repo.get("alpha|10.0.0.1")

            assert entry["ip"] == "10.0.0.1"
            assert entry["site_id"] == "alpha"
            assert repo.query({"site_id": "alpha"})[0]["source"] == "manual"
        finally:
            repo.close()

    def test_scan_history(self, sql_repo):
        sql_repo.save_scan("scan-test", {
            "scan_id": "scan-test", "target_dir": "/tmp", "status": "completed",
            "total_files": 100, "findings": [{"file": "a.php"}]
        })
        s = sql_repo.get_scan("scan-test")
        assert s is not None
        assert s["status"] == "completed"

    def test_transaction_context(self, sql_repo):
        with sql_repo.transaction():
            sql_repo.save("tx-test", {"file_path": "/tx.php"})
        assert sql_repo.get("tx-test") is not None


class TestDualWriteRepository:
    def test_dual_write_save_and_read(self, temp_dir):
        import time
        jp = temp_dir / "dual.json"
        sp = temp_dir / "dual.db"
        json_repo = JsonRepository(jp, key_field="file_path")
        sql_repo = SqliteRepository(str(sp))
        dual = DualWriteRepository(json_repo, sql_repo)
        dual.save("dual-test", {"file_path": "/tmp/dual_test.php", "features": ["test_feature"],
                                 "detected_at": "2026-06-28T12:00:00"})
        r = dual.get("dual-test")
        assert r is not None
        assert "test_feature" in str(r)
        assert dual.count() >= 1
        sql_repo.close()
        time.sleep(0.1)  # Allow WAL to flush before temp dir cleanup

    def test_dual_write_reads_json_as_the_authoritative_copy(self, temp_dir):
        jp = temp_dir / "authoritative.json"
        sp = temp_dir / "authoritative.db"
        json_repo = JsonRepository(jp, key_field="record_id")
        sql_repo = SqliteRepository(str(sp))
        dual = DualWriteRepository(json_repo, sql_repo)
        dual.save("record", {"file_path": "/json.php", "site_id": "alpha"})
        sql_repo.save("record", {"file_path": "/stale.sqlite.php", "site_id": "beta"})

        assert dual.get("record")["file_path"] == "/json.php"
        sql_repo.close()


def test_persistence_package_has_no_process_global_repository_factory():
    from anteumbra.infrastructure import persistence

    assert not hasattr(persistence, "get_repository")
    assert not hasattr(persistence, "get_shadow_repository")
    assert not hasattr(persistence, "clear_repository_cache")
