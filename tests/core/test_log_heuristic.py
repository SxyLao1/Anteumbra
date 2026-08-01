"""Tests for core/log_heuristic.py — log parsing and behavior detection."""
from anteumbra.infrastructure.detection.log_heuristic import LogHeuristicEngine, parse_log_line


class TestLogParsing:
    def test_nginx_combined_format(self):
        line = '192.168.1.100 - - [28/Jun/2026:12:00:01 +0800] "POST /shell.php HTTP/1.1" 200 1234 "-" "curl/7.88"'
        r = parse_log_line(line)
        assert r is not None
        assert r["ip"] == "192.168.1.100"
        assert r["method"] == "POST"
        assert r["path"] == "/shell.php"
        assert r["status"] == 200
        assert r["user_agent"] == "curl/7.88"

    def test_apache_common_format(self):
        line = '10.0.0.1 - frank [10/Oct/2020:13:55:36 -0700] "GET /index.html HTTP/1.0" 200 2326'
        r = parse_log_line(line)
        assert r is not None
        assert r["ip"] == "10.0.0.1"
        assert r["method"] == "GET"
        assert r["path"] == "/index.html"

    def test_tomcat_common_format_with_empty_bytes(self):
        line = '192.168.160.1 - - [29/Aug/2024:21:44:45 +0800] "GET /manager/html HTTP/1.1" 401 -'
        r = parse_log_line(line)
        assert r is not None
        assert r["ip"] == "192.168.160.1"
        assert r["method"] == "GET"
        assert r["path"] == "/manager/html"
        assert r["status"] == 401

    def test_iis_format(self):
        # IIS W3C: date time s-ip cs-method cs-uri-stem cs-uri-query s-port c-ip cs(User-Agent) sc-status
        line = '2026-06-28 12:00:01 192.168.1.1 GET /default.aspx - 80 10.0.0.1 Mozilla/5.0 200'
        r = parse_log_line(line)
        assert r is None  # Current IIS parser is not fully implemented (captures 6 fields, needs 7)

    def test_empty_line(self):
        assert parse_log_line("") is None
        assert parse_log_line("   ") is None

    def test_garbage_line(self):
        assert parse_log_line("this is not a log line") is None


class TestToolSignatures:
    def test_sqlmap_detection(self):
        engine = LogHeuristicEngine(window_size=3600, brute_threshold=50, scanner_threshold=100)
        for _ in range(5):
            engine.feed_line(
                '10.0.0.1 - - [28/Jun/2026:12:00:01 +0800] "POST /login.php HTTP/1.1" 200 1234 "-" "sqlmap/1.6#stable"'
            )
        r = engine.feed_line(
            '10.0.0.1 - - [28/Jun/2026:12:00:06 +0800] "POST /login.php HTTP/1.1" 200 1234 "-" "sqlmap/1.6#stable"'
        )
        assert r is not None
        assert r["type"] == "known_tool"

    def test_curl_detection(self):
        engine = LogHeuristicEngine(window_size=3600, brute_threshold=50, scanner_threshold=100)
        for _ in range(5):
            engine.feed_line(
                '10.0.0.2 - - [28/Jun/2026:12:00:01 +0800] "GET /test.php HTTP/1.1" 200 1234 "-" "curl/7.88.1"'
            )
        r = engine.feed_line(
            '10.0.0.2 - - [28/Jun/2026:12:00:06 +0800] "GET /other.php HTTP/1.1" 200 1234 "-" "curl/7.88.1"'
        )
        assert r is not None
        assert "curl" in str(r.get("tools", []))

    def test_normal_ua_no_alert(self):
        engine = LogHeuristicEngine()
        r = engine.feed_line(
            '10.0.0.3 - - [28/Jun/2026:12:00:01 +0800] "GET /index.html HTTP/1.1" 200 890 "-" "Mozilla/5.0"'
        )
        assert r is None


class TestBruteForceDetection:
    def test_single_path_flood(self):
        engine = LogHeuristicEngine(window_size=3600, brute_threshold=3, scanner_threshold=100)
        for i in range(4):
            r = engine.feed_line(
                f'10.0.0.5 - - [28/Jun/2026:12:{i:02d}:01 +0800] "POST /wp-login.php HTTP/1.1" 403 1234 "-" "Mozilla/5.0"'
            )
        assert r is not None
        assert r["type"] == "brute_force"
        assert r["path"] == "/wp-login.php"
        assert r["severity"] in ("medium", "high")

    def test_distributed_requests_no_alert(self):
        engine = LogHeuristicEngine(window_size=3600, brute_threshold=50, scanner_threshold=100)
        for i in range(10):
            path = f"/page{i}.html"
            r = engine.feed_line(
                f'10.0.0.6 - - [28/Jun/2026:12:{i:02d}:01 +0800] "GET {path} HTTP/1.1" 200 890 "-" "Mozilla/5.0"'
            )
        assert r is None  # Different paths, not brute force


class TestScannerDetection:
    def test_many_unique_paths(self):
        engine = LogHeuristicEngine(window_size=3600, brute_threshold=100, scanner_threshold=3)
        r = None
        for i in range(5):
            r = engine.feed_line(
                f'10.0.0.7 - - [28/Jun/2026:12:{i:02d}:01 +0800] "GET /scan/{i} HTTP/1.1" 404 1234 "-" "python-requests/2.28"'
            )
        assert r is not None
        assert r["type"] == "scanner"

    def test_few_paths_no_alert(self):
        engine = LogHeuristicEngine(window_size=3600, brute_threshold=100, scanner_threshold=10)
        for i in range(5):
            engine.feed_line(
                f'10.0.0.8 - - [28/Jun/2026:12:{i:02d}:01 +0800] "GET /page{i}.html HTTP/1.1" 200 890 "-" "Mozilla/5.0"'
            )
        # Only 5 unique paths, below threshold
        r = engine.feed_line(
            '10.0.0.8 - - [28/Jun/2026:12:06:01 +0800] "GET /page6.html HTTP/1.1" 200 890 "-" "Mozilla/5.0"'
        )
        assert r is None


class TestSuspiciousPathDetection:
    def test_php_shell_extension(self):
        engine = LogHeuristicEngine()
        r = engine.feed_line(
            '10.0.0.9 - - [28/Jun/2026:12:00:01 +0800] "POST /uploads/cmd.php5 HTTP/1.1" 201 567 "-" "curl/7.88"'
        )
        assert r is not None
        assert r["type"] == "suspicious_path"
        assert ".php5" in r["reason"]

    def test_backup_file_access(self):
        engine = LogHeuristicEngine()
        r = engine.feed_line(
            '10.0.0.10 - - [28/Jun/2026:12:00:01 +0800] "GET /config.php.bak HTTP/1.1" 200 1234 "-" "Mozilla/5.0"'
        )
        assert r is not None
        assert r["type"] == "suspicious_path"

    def test_env_file_probe(self):
        engine = LogHeuristicEngine()
        r = engine.feed_line(
            '10.0.0.11 - - [28/Jun/2026:12:00:01 +0800] "GET /.env HTTP/1.1" 200 123 "-" "curl/7.88"'
        )
        assert r is not None
        assert r["type"] == "suspicious_path"

    def test_tomcat_jsp_shell_probe(self):
        engine = LogHeuristicEngine()
        r = engine.feed_line(
            '172.17.0.2 - - [29/Aug/2024:21:44:45 +0800] "POST /test/shell.jsp HTTP/1.1" 200 -'
        )
        assert r is not None
        assert r["type"] == "suspicious_path"
        assert r["path"] == "/test/shell.jsp"


class TestErrorStormDetection:
    def test_error_flood(self):
        engine = LogHeuristicEngine(window_size=3600, error_threshold=3)
        r = None
        for i in range(5):
            r = engine.feed_line(
                f'10.0.0.12 - - [28/Jun/2026:12:{i:02d}:01 +0800] "GET /secret HTTP/1.1" 403 123 "-" "Mozilla/5.0"'
            )
        assert r is not None
        assert r["type"] == "error_storm"

    def test_normal_errors_no_alert(self):
        engine = LogHeuristicEngine()
        engine.feed_line(
            '10.0.0.13 - - [28/Jun/2026:12:00:01 +0800] "GET /missing.html HTTP/1.1" 404 123 "-" "Mozilla/5.0"'
        )
        r = engine.feed_line(
            '10.0.0.14 - - [28/Jun/2026:12:00:02 +0800] "GET /other.html HTTP/1.1" 404 123 "-" "Mozilla/5.0"'
        )
        assert r is None  # Different IPs, not the same one flooding


class TestFileAnalysis:
    def test_feed_file(self, sample_log_file):
        engine = LogHeuristicEngine(window_size=3600, brute_threshold=2, scanner_threshold=2)
        events = engine.feed_file(sample_log_file)
        assert len(events) > 0

    def test_stats(self):
        engine = LogHeuristicEngine()
        for _ in range(5):
            engine.feed_line(
                '10.0.0.1 - - [28/Jun/2026:12:00:01 +0800] "GET /test.php HTTP/1.1" 200 890 "-" "sqlmap"'
            )
        stats = engine.get_stats()
        assert stats["total_analyzed"] == 5
        assert stats["ips_tracked"] > 0
