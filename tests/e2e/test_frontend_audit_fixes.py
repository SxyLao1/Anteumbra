# -*- coding: utf-8 -*-
"""
Regression tests for the 2026-09-12 frontend audit fixes.

Covers three defects found by driving the real UI:
  * the SIEM panel linked to an unsupported ``csv`` format (HTTP 500)
  * the quarantine page rendered the dashboard shell without its SSE token,
    so the live stream logged "Token missing"
  * inner pages lost the shared component baselines (header action row,
    stat-card label spacing, button heights)
"""

import os

import pytest


class TestSiemCsvExport:
    def test_formatter_supports_csv(self):
        from anteumbra.infrastructure.utils.siem_formatter import SIEMFormatter

        formatter = SIEMFormatter({"format": "csv"})
        header = formatter.csv_header()
        row = formatter.format_event(
            {
                "id": "abc",
                "detected_at": "2026-09-12T00:00:00Z",
                "file_path": r"E:\www\shell.php",
                "display_name": "shell.php",
                "features": ["YARA:Eval", "YARA:Cmd"],
                "source_ip": "127.0.0.1",
            }
        )
        assert header.split(",")[0] == "event_time"
        assert row.count(",") >= len(formatter.CSV_COLUMNS) - 1
        assert "shell.php" in row
        # features are joined so the row stays one physical CSV line
        assert "YARA:Eval|YARA:Cmd" in row
        assert "\n" not in row

    def test_exporter_accepts_csv_and_rejects_unknown_format(self, tmp_path):
        from anteumbra.infrastructure.monitoring.siem_exporter import SIEMExporter

        exporter = SIEMExporter(
            {
                "enabled": True,
                "format": "json_lines",
                "export_file": str(tmp_path / "events.csv"),
            }
        )
        exporter.set_format("csv")
        assert exporter.format == "csv"
        count = exporter.export_existing(
            [{"id": "1", "file_path": r"E:\www\a.php", "display_name": "a.php", "features": []}]
        )
        assert count == 1
        content = (tmp_path / "events.csv").read_text(encoding="utf-8").splitlines()
        assert content[0].startswith("event_time,")
        assert len(content) == 2

        with pytest.raises(ValueError):
            exporter.set_format("parquet")
        exporter.close()


class TestQuarantineShellToken:
    @pytest.fixture(scope="class")
    @classmethod
    def _app(cls):
        os.environ.setdefault("ANTEUMBRA_TOOL_MODE", "true")
        from anteumbra.interfaces.web.factory import create_app

        app = create_app()
        app.config["TESTING"] = True
        app.config["WTF_CSRF_ENABLED"] = False
        return app

    def test_quarantine_page_carries_sse_token(self, _app):
        """The shell needs a non-empty sse-token meta or the stream stays off."""
        with _app.test_client() as client:
            with client.session_transaction() as flask_session:
                flask_session["authenticated"] = True
                flask_session["username"] = "admin"
            resp = client.get("/admin/quarantine")
            assert resp.status_code == 200
            body = resp.get_data(as_text=True)
            assert 'name="sse-token" content=""' not in body
            assert 'name="sse-token" content="' in body
