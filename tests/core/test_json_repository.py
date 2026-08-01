"""Tests for core/repositories/json_repository.py"""
import json

import pytest

from anteumbra.infrastructure.persistence.json_repository import JsonRepository


class TestJsonRepository:
    @pytest.fixture
    def repo(self, temp_dir):
        p = temp_dir / "test.json"
        return JsonRepository(p, key_field="id")

    def test_save_and_get(self, repo):
        repo.save("rec-1", {"id": "rec-1", "name": "test", "score": 95})
        r = repo.get("rec-1")
        assert r is not None
        assert r["name"] == "test"
        assert r["score"] == 95

    def test_update_existing(self, repo):
        repo.save("rec-1", {"id": "rec-1", "name": "original"})
        repo.save("rec-1", {"id": "rec-1", "name": "updated", "extra": True})
        r = repo.get("rec-1")
        assert r["name"] == "updated"
        assert r["extra"] is True

    def test_delete(self, repo):
        repo.save("rec-1", {"id": "rec-1", "name": "test"})
        assert repo.delete("rec-1") is True
        assert repo.get("rec-1") is None
        assert repo.delete("nonexistent") is False

    def test_count(self, repo):
        assert repo.count() == 0
        repo.save("a", {"id": "a"})
        repo.save("b", {"id": "b"})
        assert repo.count() == 2
        assert repo.count({"id": "a"}) == 1

    def test_list_all_pagination(self, repo):
        for i in range(10):
            repo.save(f"rec-{i}", {"id": f"rec-{i}", "idx": i})
        page = repo.list_all(limit=3, offset=0)
        assert len(page) == 3
        page2 = repo.list_all(limit=3, offset=3)
        assert len(page2) == 3

    def test_query_with_filters(self, repo):
        repo.save("a", {"id": "a", "status": "active", "score": 90})
        repo.save("b", {"id": "b", "status": "deleted", "score": 50})
        repo.save("c", {"id": "c", "status": "active", "score": 80})
        results = repo.query({"status": "active"})
        assert len(results) == 2

    def test_flush_persistence(self, temp_dir):
        p = temp_dir / "flush_test.json"
        repo = JsonRepository(p, key_field="id")
        repo.save("x", {"id": "x", "data": "hello"})
        repo.flush()
        # Re-load from disk
        repo2 = JsonRepository(p, key_field="id")
        assert repo2.get("x") is not None
        r = repo2.get("x")
        assert r["data"] == "hello"

    def test_load_from_array_format(self, temp_dir):
        p = temp_dir / "array_test.json"
        p.write_text(json.dumps([
            {"uid": "xxx", "name": "Alice"},
            {"uid": "yyy", "name": "Bob"},
        ]))
        repo = JsonRepository(p, key_field="uid")
        assert repo.count() == 2
        assert repo.get("xxx")["name"] == "Alice"

    def test_nonexistent_file(self, temp_dir):
        p = temp_dir / "nonexistent.json"
        repo = JsonRepository(p, key_field="id")
        assert repo.count() == 0

    def test_complex_data(self, repo):
        data = {
            "id": "complex",
            "tags": ["a", "b", "c"],
            "meta": {"nested": True, "count": 42},
            "path": "C:\\Users\\test\\data.json",
        }
        repo.save("complex", data)
        r = repo.get("complex")
        assert r["tags"] == ["a", "b", "c"]
        assert r["meta"]["nested"] is True
        assert "C:\\Users" in r["path"]

    def test_len(self, repo):
        assert len(repo) == 0
        repo.save("x", {"id": "x"})
        assert len(repo) == 1
