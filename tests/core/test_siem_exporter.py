"""Tests for core/siem_exporter.py and utils/siem_formatter.py"""
import json
import pytest
from pathlib import Path
from anteumbra.infrastructure.utils.siem_formatter import SIEMFormatter, format_event
from anteumbra.infrastructure.monitoring.siem_exporter import SIEMExporter
from anteumbra.domain import DomainEvent


class TestSIEMFormatter:
    @pytest.fixture
    def sample_event(self):
        return {
            "id": "evt-001",
            "detected_at": "2026-06-28T12:00:00Z",
            "file_path": "/var/www/uploads/webshell.php",
            "display_name": "webshell.php",
            "features": ["php_eval", "base64_decode", "exec"],
            "rule_name": "php_webshell_generic",
            "source_ip": "192.168.1.100",
            "severity": "high",
            "confidence": 90,
        }

    def test_json_lines_format(self, sample_event):
        fmt = SIEMFormatter({"format": "json_lines"})
        line = fmt.format_event(sample_event)
        assert line.startswith("{")
        assert line.endswith("}")
        data = json.loads(line)
        assert data["detection"]["rule_name"] == "php_webshell_generic"

    def test_cef_format(self, sample_event):
        fmt = SIEMFormatter({"format": "cef"})
        line = fmt.format_event(sample_event)
        assert line.startswith("CEF:0|Anteumbra|")
        assert "fpath=/var/www/uploads/webshell.php" in line

    def test_syslog_format(self, sample_event):
        fmt = SIEMFormatter({"format": "syslog"})
        line = fmt.format_event(sample_event)
        assert line.startswith("<")

    def test_batch_format(self, sample_event):
        fmt = SIEMFormatter({"format": "json_lines"})
        events = [sample_event, sample_event]
        result = fmt.format_batch(events)
        lines = result.strip().split("\n")
        assert len(lines) == 2

    def test_format_switch(self, sample_event):
        r1 = format_event(sample_event, {"format": "json"})
        assert "  " in r1  # Pretty-printed
        r2 = format_event(sample_event, {"format": "json_lines"})
        assert "  " not in r2  # Compact


class TestSIEMExporter:
    def test_disabled_by_default(self):
        exporter = SIEMExporter({})
        assert exporter.enabled is False

    def test_enabled_with_file_output(self, temp_dir):
        p = temp_dir / "siem_test.jsonl"
        exporter = SIEMExporter({
            "enabled": True,
            "format": "json_lines",
            "export_file": str(p),
            "rotate_mb": 100,
        })
        assert exporter.enabled is True

        event = {"id": "test", "detected_at": "2026-06-28T12:00:00Z",
                 "file_path": "/tmp/test.php", "features": ["a"],
                 "rule_name": "test_rule", "source_ip": "10.0.0.1"}
        result = exporter.emit(event)
        assert result is not None
        assert p.exists()
        content = p.read_text(encoding="utf-8")
        assert "test_rule" in content

    def test_emit_batch(self, temp_dir):
        p = temp_dir / "batch_test.jsonl"
        exporter = SIEMExporter({
            "enabled": True,
            "format": "json_lines",
            "export_file": str(p),
        })
        events = [
            {"id": f"evt-{i}", "detected_at": f"2026-06-28T12:{i:02d}:00Z",
             "file_path": f"/tmp/{i}.php", "features": ["x"],
             "rule_name": f"rule_{i}", "source_ip": "10.0.0.1"}
            for i in range(5)
        ]
        count = exporter.emit_batch(events)
        assert count == 5
        lines = p.read_text(encoding="utf-8").strip().split("\n")
        assert len(lines) == 5

    def test_export_existing(self, temp_dir):
        p = temp_dir / "export_test.jsonl"
        exporter = SIEMExporter({
            "enabled": True, "format": "json_lines", "export_file": str(p),
        })
        records = [
            {"id": "r1", "detected_at": "2026-06-28T12:00:00Z",
             "file_path": "/tmp/a.php", "display_name": "a.php",
             "features": ["php_eval"], "first_seen_ip": "10.0.0.1"},
        ]
        count = exporter.export_existing(records)
        assert count == 1
        assert p.exists()


def test_siem_handler_exports_registry_events(monkeypatch):
    from anteumbra.plugins.siem_handler import SIEMHandlerPlugin

    emitted = []
    monkeypatch.setattr(
        "anteumbra.infrastructure.monitoring.siem_exporter.emit_detection_event",
        lambda payload: emitted.append(payload),
    )
    plugin = SIEMHandlerPlugin()
    plugin.activate({"enabled": True})

    plugin.on_event(DomainEvent(
        "record_added",
        0,
        "registry",
        {"file_path": "/tmp/shell.php", "features": ["YARA:test"]},
    ))

    assert emitted == [{"file_path": "/tmp/shell.php", "features": ["YARA:test"]}]
