"""Tests for domain entities."""

from anteumbra.domain.entities import (
    DetectionSource,
    FileRecord,
    FileStatus,
    QuarantineRecord,
    ScanResult,
)


class TestFileRecord:
    def test_create_minimal(self):
        r = FileRecord(file_path="/tmp/test.php")
        assert r.file_path == "/tmp/test.php"
        assert r.status == FileStatus.ACTIVE
        assert r.is_active is True

    def test_create_full(self):
        r = FileRecord(
            file_path="C:\\www\\shell.php",
            display_name="shell.php",
            features=["php_eval", "base64_decode"],
            detection_source=DetectionSource.ACTIVE,
            first_seen_ip="10.0.0.1",
            file_size=1234,
        )
        assert r.file_path == "C:/www/shell.php"  # Normalized
        assert r.detection_source == DetectionSource.ACTIVE
        assert r.first_seen_ip == "10.0.0.1"

    def test_quarantined_status(self):
        r = FileRecord(file_path="/tmp/q.php", quarantine_id="q-abc123")
        assert r.status == FileStatus.QUARANTINED
        assert r.is_active is False

    def test_false_positive_status(self):
        r = FileRecord(file_path="/tmp/fp.php", marked_false_positive=True)
        assert r.status == FileStatus.FALSE_POSITIVE

    def test_deleted_status(self):
        r = FileRecord(file_path="/tmp/del.php", deleted_at="2026-06-28T12:00:00Z")
        assert r.status == FileStatus.DELETED

    def test_roundtrip_dict(self):
        original = FileRecord(
            file_path="/var/www/x.php",
            features=["a", "b", "c"],
            detection_source=DetectionSource.WAF,
            metadata={"key": "value"},
        )
        data = original.to_dict()
        restored = FileRecord.from_dict(data)
        assert restored.file_path == original.file_path
        assert restored.features == original.features
        assert restored.detection_source == original.detection_source
        assert restored.metadata == {"key": "value"}

    def test_auto_display_name(self):
        r = FileRecord(file_path="/var/www/html/backdoor.php")
        assert r.display_name == "backdoor.php"

    def test_auto_timestamp(self):
        r = FileRecord(file_path="/tmp/a.php")
        assert r.detected_at  # Auto-generated

    def test_default_values(self):
        r = FileRecord(file_path="/tmp/b.php")
        assert r.features == []
        assert r.file_exists is True
        assert r.communication_count == 0
        assert r.alerted is False
        assert r.marked_false_positive is False
        assert r.quarantine_id is None


class TestScanResult:
    def test_to_record(self):
        from pathlib import Path

        sr = ScanResult(
            Path("/tmp/malware.php"),
            is_suspicious=True,
            score=0.95,
            engine="yara",
            features=["php_webshell"],
            detection_source=DetectionSource.PASSIVE,
        )
        record = sr.to_record()
        assert isinstance(record, FileRecord)
        assert record.file_path == "/tmp/malware.php"
        assert record.features == ["php_webshell"]


class TestQuarantineRecord:
    def test_create(self):
        qr = QuarantineRecord(
            quarantine_id="q-001",
            original_path="/tmp/bad.php",
            quarantine_path="data/quarantine/q-001",
            rule_name="php_webshell",
            features=["eval"],
        )
        assert qr.quarantine_id == "q-001"
        assert qr.original_path == "/tmp/bad.php"
        assert qr.created_at is not None
