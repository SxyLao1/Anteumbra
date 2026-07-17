"""Multi-site access-log application service tests."""

from types import SimpleNamespace


def test_analyzes_each_enabled_log_configuration(tmp_path):
    from anteumbra.application.log_analysis_service import analyze_access_logs

    nginx_log = tmp_path / "nginx-access.log"
    tomcat_log = tmp_path / "localhost_access_log.2026-07-17.txt"
    nginx_log.write_text(
        '10.0.0.1 - - [17/Jul/2026:12:00:01 +0800] "GET /index.php HTTP/1.1" 200 12 "-" "Mozilla/5.0"\n',
        encoding="utf-8",
    )
    tomcat_log.write_text(
        '10.0.0.2 - - [17/Jul/2026:12:00:02 +0800] "POST /cmd.jsp HTTP/1.1" 200 32\n',
        encoding="utf-8",
    )
    websites = [
        SimpleNamespace(
            name="Nginx",
            log_config={
                "log_monitor_enabled": True,
                "access_log_path": str(nginx_log),
            },
        ),
        SimpleNamespace(
            name="Tomcat",
            log_config={
                "log_monitor_enabled": True,
                "access_log_path": str(tmp_path / "localhost_access_log.*.txt"),
            },
        ),
        SimpleNamespace(
            name="Disabled",
            log_config={"log_monitor_enabled": False},
        ),
    ]

    results = analyze_access_logs(websites)

    assert [result["website"] for result in results] == ["Nginx", "Tomcat", "Disabled"]
    assert [result["status"] for result in results] == ["ok", "ok", "disabled"]
    assert results[0]["selected_path"] == str(nginx_log)
    assert results[1]["selected_path"] == str(tomcat_log)
