# -*- coding: utf-8 -*-
"""Guard: one detection must not get more expensive as the Registry grows.

The store used to rewrite the entire JSON file — and, through the shadow sync,
every SQLite row — on each detection: measured 28 ms per write at 940 records,
54 ms at 2,000 and 206 ms at 10,000, all inside the Registry lock.  A single row
per change makes the cost independent of the record count (1.5 ms / 1.6 ms /
3.0 ms on the same data).

This test fails loudly if the per-write cost ever tracks the record count again.
"""

from __future__ import annotations

import json
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from anteumbra.domain.site import SiteIdentity  # noqa: E402
from anteumbra.infrastructure.persistence.sqlite_repository import SqliteRepository  # noqa: E402
from anteumbra.infrastructure.suspicious_registry import SuspiciousRegistry  # noqa: E402
from anteumbra.infrastructure.wal_manager import WalManager  # noqa: E402

SEED_RECORDS = 3_000
SAMPLES = 50
# The old whole-file path cost ~80 ms per write at this size; one row costs ~2 ms.
BUDGET_MS = 5.0


class ConfigStub:
    def get(self):
        return {"filesizes": {"registry_compact_days": 30}}

    def resolve_site_identity(self, file_path, site_id=None, site_name=None):
        return SiteIdentity("default", "Default Website")


class EventsStub:
    def publish(self, *_args, **_kwargs):
        return None


def _seed(repository: SqliteRepository, count: int) -> None:
    for index in range(count):
        repository.save(
            f"default:c:/seed/{index}.php",
            {
                "file_path": f"c:/seed/{index}.php",
                "site_id": "default",
                "site_name": "Default Website",
                "detected_at": f"2026-01-01T00:{index % 60:02d}:00+00:00",
                "features": ["seed"],
                "content_hash": f"seed{index}",
            },
        )


def test_one_write_stays_cheap_with_thousands_of_records(tmp_path):
    repository = SqliteRepository(str(tmp_path / "anteumbra.db"))
    _seed(repository, SEED_RECORDS)
    registry_path = tmp_path / "suspicious_registry.json"
    registry_path.with_name(f"{registry_path.name}.sqlite-authority").write_text(
        "sqlite\n", encoding="utf-8"
    )

    registry = SuspiciousRegistry(
        registry_path,
        config=ConfigStub(),
        wal=WalManager(tmp_path / "wal.log"),
        event_publisher=EventsStub(),
        shadow_repository=repository,
    )
    try:
        assert len(registry.get_all(include_deleted=True)) == SEED_RECORDS

        timings = []
        for index in range(SAMPLES):
            started = time.perf_counter()
            registry.add(
                f"c:/seed/{index}.php",
                ["rule"],
                None,
                "passive",
                content_hash=f"hash{index}",
                alert_emitted=True,
            )
            timings.append((time.perf_counter() - started) * 1000)

        median = statistics.median(timings)
        assert median < BUDGET_MS, (
            f"one write costs {median:.1f} ms with {SEED_RECORDS} records "
            f"(budget {BUDGET_MS} ms); the store is rewriting more than one record"
        )
    finally:
        registry.close()

    snapshot = json.loads(registry_path.read_text(encoding="utf-8"))
    assert len(snapshot) == SEED_RECORDS, "the readable snapshot stays complete"
