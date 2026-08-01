"""Durable scan-history service and filesystem adapter tests."""

from types import SimpleNamespace

import pytest

from anteumbra.application.scan_history_service import ScanHistoryService
from anteumbra.infrastructure.scan_history import FileScanHistoryStore

_SCAN_ID = "a3f1c5d7e9b2a4c6"


def _result(**overrides):
    values = {
        "scan_id": _SCAN_ID,
        "target_dir": "C:/sites/example",
        "start_time": 100.0,
        "end_time": 101.2,
        "status": "completed",
        "site_id": "example",
        "site_name": "Example",
        "total_files": 4,
        "scanned_files": 4,
        "new_findings": 1,
        "known_findings": 1,
        "clean": 2,
        "errors": 0,
        "findings": [{"file_path": "C:/sites/example/shell.php"}],
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def test_scan_history_service_persists_bounded_result_atomically(tmp_path):
    directory = tmp_path / "runtime-data" / "scans"
    service = ScanHistoryService(FileScanHistoryStore(directory))

    service.record(_result(findings=[{"index": index} for index in range(250)]))

    stored = service.get_result(_SCAN_ID)
    assert stored is not None
    assert stored["scan_id"] == _SCAN_ID
    assert stored["duration"] == 1.2
    assert len(stored["findings"]) == 200
    assert not list(directory.glob("*.tmp"))
    assert (directory / f"{_SCAN_ID}.json").exists()
    assert service.list_summaries() == [
        {
            "scan_id": _SCAN_ID,
            "target_dir": "C:/sites/example",
            "site_id": "example",
            "site_name": "Example",
            "start_time": 100.0,
            "end_time": 101.2,
            "status": "completed",
            "total_files": 4,
            "scanned_files": 4,
            "new_findings": 1,
            "known_findings": 1,
            "clean": 2,
            "duration": 1.2,
        }
    ]


@pytest.mark.parametrize("scan_id", ["../outside", r"..\\outside", "not-a-scan-id"])
def test_scan_history_store_rejects_path_components(tmp_path, scan_id):
    store = FileScanHistoryStore(tmp_path / "scans")

    with pytest.raises(ValueError, match="invalid scan_id"):
        store.get(scan_id)
    with pytest.raises(ValueError, match="invalid scan_id"):
        store.save(scan_id, {"scan_id": scan_id})

    assert not (tmp_path / "outside.json").exists()


def test_scan_history_store_skips_corrupt_records(tmp_path):
    directory = tmp_path / "scans"
    directory.mkdir()
    (directory / f"{'b' * 16}.json").write_text("{broken", encoding="utf-8")

    assert FileScanHistoryStore(directory).list_records() == []