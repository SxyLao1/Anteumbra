# Trident v1.9.5: Shared test fixtures
import tempfile
from pathlib import Path

import pytest


@pytest.fixture
def temp_dir():
    """Temporary directory for file-based tests."""
    with tempfile.TemporaryDirectory() as d:
        yield Path(d)

@pytest.fixture
def sample_log_file(temp_dir):
    """Sample Nginx access log for log_heuristic tests."""
    p = temp_dir / "access.log"
    lines = [
        '192.168.1.100 - - [28/Jun/2026:08:15:30 +0800] "POST /uploads/shell.php HTTP/1.1" 201 1234 "-" "AntSword/2.1"',
        '192.168.1.100 - - [28/Jun/2026:08:16:00 +0800] "GET /uploads/shell.php HTTP/1.1" 200 567 "-" "Mozilla/5.0"',
        '10.0.0.1 - - [28/Jun/2026:08:17:00 +0800] "GET /index.php HTTP/1.1" 200 890 "-" "Mozilla/5.0"',
        '192.168.1.200 - - [28/Jun/2026:08:18:00 +0800] "POST /wp-admin/admin-ajax.php HTTP/1.1" 200 1234 "-" "sqlmap/1.6#stable"',
    ]
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return p

@pytest.fixture
def sample_registry_entries():
    """Sample detection records for cross-reference tests."""
    return [
        {"file_path": "E:\\www\\uploads\\shell.php", "display_name": "shell.php",
         "detected_at": "2026-06-28T08:20:00", "features": ["php_eval", "base64_decode"],
         "file_exists": True, "quarantine_id": ""},
        {"file_path": "/var/www/html/backdoor.jsp", "display_name": "backdoor.jsp",
         "detected_at": "2026-06-27T12:00:00", "features": ["java_runtime_exec"],
         "file_exists": True, "quarantine_id": "q-abc123"},
    ]
