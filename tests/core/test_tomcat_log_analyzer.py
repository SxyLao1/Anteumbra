import logging
import os
import time
from pathlib import Path

from anteumbra.infrastructure.models import ScanOptions, Website
from anteumbra.infrastructure.monitoring.log_analyzer import LogAnalyzer, resolve_access_log_path


def _write_utf8(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_resolve_tomcat_wildcard_selects_newest_access_log(tmp_path):
    old_log = tmp_path / "localhost_access_log.2024-08-29.txt"
    new_log = tmp_path / "localhost_access_log.2024-08-30.txt"
    _write_utf8(old_log, "old\n")
    _write_utf8(new_log, "new\n")
    old_time = time.time() - 3600
    os.utime(old_log, (old_time, old_time))

    selected = resolve_access_log_path(str(tmp_path / "localhost_access_log.*.txt"))

    assert selected == new_log


def test_log_analyzer_matches_tomcat_shell_access(tmp_path):
    log_path = tmp_path / "logs" / "localhost_access_log.2024-08-30.txt"
    shell_path = tmp_path / "webapps" / "ROOT" / "test" / "shell.jsp"
    _write_utf8(shell_path, "<%-- lab --%>")
    _write_utf8(
        log_path,
        "\n".join(
            [
                '172.17.0.2 - - [30/Aug/2024:10:00:00 +0800] "GET /test/index.jsp HTTP/1.1" 200 128',
                '172.17.0.2 - - [30/Aug/2024:10:00:02 +0800] "POST /test/shell.jsp HTTP/1.1" 200 -',
            ]
        ),
    )

    website = Website(
        name="TomcatLab",
        path=shell_path.parent,
        port=18080,
        enabled=True,
        scan_options=ScanOptions(
            access_log_path=str(tmp_path / "logs" / "localhost_access_log.*.txt")
        ),
    )

    analyzer = LogAnalyzer(website, logging.getLogger("test.tomcat_log_analyzer"))
    result = analyzer.analyze_shell_access(shell_path)

    assert analyzer.log_type == "tomcat"
    assert result is not None
    assert result["suspicious_ips"] == {"172.17.0.2": 1}
