import json
import logging
from datetime import datetime
from types import SimpleNamespace


def test_recent_waf_upload_takes_precedence_over_access_log_analysis(tmp_path):
    from anteumbra.infrastructure.monitoring.detection_attribution import (
        resolve_first_seen_ip,
    )

    waf_log = tmp_path / "waf_events.jsonl"
    waf_log.write_text(
        json.dumps(
            {
                "timestamp": datetime.now().isoformat(),
                "src_ip": "203.0.113.24",
                "method": "POST",
            }
        ),
        encoding="utf-8",
    )

    def unexpected_analyzer(*_args, **_kwargs):
        raise AssertionError("WAF attribution must short-circuit access-log analysis")

    source_ip = resolve_first_seen_ip(
        tmp_path / "shell.php",
        website=SimpleNamespace(log_config={"log_monitor_enabled": True}),
        logger=logging.getLogger("test.detection-attribution"),
        waf_log=waf_log,
        analyzer_factory=unexpected_analyzer,
    )

    assert source_ip == "203.0.113.24"
