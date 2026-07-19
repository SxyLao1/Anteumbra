"""Memory-shell tracing and site-isolation tests."""

from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace

from anteumbra.infrastructure.detection.memory_shell_tracer import (
    MemoryShellTracer,
    trace_memory_shell,
)


def _write_access_log(path):
    path.write_text(
        "\n".join(
            [
                '192.168.1.100 - - [28/Jun/2026:08:15:30 +0800] "POST /uploads/shell.php HTTP/1.1" 201 1234 "-" "AntSword/2.1"',
                '192.168.1.100 - - [28/Jun/2026:08:16:00 +0800] "PUT /images/backdoor.jsp HTTP/1.1" 200 567 "-" "curl/7.88"',
                '10.0.0.1 - - [28/Jun/2026:08:17:00 +0800] "GET /index.html HTTP/1.1" 200 890 "-" "Mozilla/5.0"',
            ]
        )
        + "\n",
        encoding="utf-8",
    )


def test_trace_without_logs_returns_low_confidence():
    result = MemoryShellTracer(lookback_hours=1).trace(
        "10.0.0.1",
        datetime(2026, 6, 28, 12, 0, 0),
        log_paths=[],
    )

    assert result["found"] is False
    assert result["confidence"] == "low"
    assert "No upload activity" in result["summary"]


def test_trace_ranks_likely_uploads_and_handles_aware_time(tmp_path):
    access_log = tmp_path / "access.log"
    _write_access_log(access_log)

    result = MemoryShellTracer(lookback_hours=24).trace(
        "192.168.1.100",
        datetime(2026, 6, 28, 9, 0, 0, tzinfo=timezone.utc),
        log_paths=[access_log],
    )

    assert result["found"] is True
    assert result["writes"] == 2
    assert result["candidates"][0]["path"] == "/uploads/shell.php"
    assert result["candidates"][0]["score"] >= 8


def test_registry_cross_reference_is_site_qualified(tmp_path):
    access_log = tmp_path / "access.log"
    _write_access_log(access_log)
    calls = []

    def records(**kwargs):
        calls.append(kwargs)
        return [
            {
                "file_path": "C:/sites/alpha/uploads/shell.php",
                "detected_at": "2026-06-28T00:00:00+00:00",
                "features": ["php-eval"],
                "quarantine_id": "Q-alpha",
                "site_id": "alpha",
            }
        ]

    result = MemoryShellTracer(registry_reader=records).trace(
        "192.168.1.100",
        datetime(2026, 6, 28, 9, 0, 0),
        [access_log],
        site_id="alpha",
    )

    assert result["confidence"] == "high"
    assert result["matched"]["qid"] == "Q-alpha"
    assert result["matched"]["match"] == "suffix"
    assert calls == [
        {
            "include_deleted": True,
            "include_false_positive": False,
            "site_id": "alpha",
        }
    ]


def test_default_logs_are_selected_for_only_the_requested_site(tmp_path):
    alpha_log = tmp_path / "alpha.log"
    beta_log = tmp_path / "beta.log"
    _write_access_log(alpha_log)
    _write_access_log(beta_log)
    provider = SimpleNamespace(
        get_enabled_websites=lambda: [
            SimpleNamespace(
                site_id="alpha",
                log_config={"access_log_path": str(alpha_log)},
            ),
            SimpleNamespace(
                site_id="beta",
                log_config={"access_log_path": str(beta_log)},
            ),
        ]
    )

    result = MemoryShellTracer(config_provider=provider).trace(
        "192.168.1.100",
        datetime(2026, 6, 28, 9, 0, 0),
        site_id="beta",
    )

    assert result["total"] == 2
    assert result["site_id"] == "beta"


def test_one_shot_helper_has_no_hidden_runtime_dependency(tmp_path):
    access_log = tmp_path / "access.log"
    _write_access_log(access_log)

    result = trace_memory_shell(
        "192.168.1.100",
        datetime(2026, 6, 28, 9, 0, 0),
        [access_log],
    )

    assert result["found"] is True
    assert result["matched"] is None
