#!/usr/bin/env python3
"""
Anteumbra v1.0 API Compatibility Test
Ensures core APIs remain stable across refactoring.

Usage:
    python tests/compatibility/test_v178_api.py

Rules:
    - This test MUST pass before any release
    - Breaking changes require documentation in ADR
"""
import sys
import os
import unittest
import tempfile
import json
from pathlib import Path

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, PROJECT_ROOT)


class TestConfigAPI(unittest.TestCase):
    """Test version and config loader APIs."""

    def test_version_import(self):
        from anteumbra.infrastructure.config.version import get_version
        version = get_version()
        self.assertIsInstance(version, str)
        self.assertRegex(version, r"^\d+\.\d+\.\d+([.-][a-zA-Z0-9.]+)?$")
        self.assertNotEqual(version, "unknown")

    def test_config_load(self):
        from anteumbra.infrastructure.config.loader import load_config
        cfg = load_config()
        self.assertIn("system", cfg)
        self.assertIn("web_admin", cfg)


class TestRegistryAPI(unittest.TestCase):
    """Test suspicious_registry function-level APIs."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        os.environ["TRIDENT_TOOL_MODE"] = "true"

    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
        os.environ.pop("TRIDENT_TOOL_MODE", None)

    def test_add_and_get_all(self):
        from anteumbra.infrastructure.suspicious_registry import add, get_all, _clear_memory_cache
        _clear_memory_cache()
        add(Path("/tmp/test.php"), ["eval", "base64"])
        records = get_all(include_deleted=True)
        self.assertIsInstance(records, list)

    def test_get_all_filter(self):
        from anteumbra.infrastructure.suspicious_registry import get_all
        records = get_all(include_deleted=False, include_false_positive=False)
        self.assertIsInstance(records, list)


class TestWALAPI(unittest.TestCase):
    """Test WAL manager APIs."""

    def test_wal_info(self):
        from anteumbra.infrastructure import wal_manager
        info = wal_manager.get_wal_info()
        self.assertIsInstance(info, dict)

    def test_wal_read(self):
        from anteumbra.infrastructure import wal_manager
        records = wal_manager.read_wal_records(limit=10)
        self.assertIsInstance(records, list)


class TestSIEMFormatter(unittest.TestCase):
    """Test SIEM formatter APIs."""

    def test_json_lines_format(self):
        from anteumbra.infrastructure.utils.siem_formatter import format_event
        event = {
            "file_path": "/tmp/shell.php",
            "rule_name": "php_eval_backdoor",
            "severity": "high",
        }
        output = format_event(event)
        parsed = json.loads(output)
        self.assertIn("event_id", parsed)
        self.assertIn("source", parsed)
        self.assertIn("detection", parsed)

    def test_cef_format(self):
        from anteumbra.infrastructure.utils.siem_formatter import SIEMFormatter
        fmt = SIEMFormatter({"format": "cef"})
        event = {"file_path": "/tmp/shell.php", "rule_name": "test", "severity": "high"}
        output = fmt.format_event(event)
        self.assertTrue(output.startswith("CEF:0|Anteumbra|WebShellDetector|"))


class TestYaraEngineAPI(unittest.TestCase):
    """Test YARA engine APIs."""

    def test_get_engine(self):
        from anteumbra.infrastructure.detection.yara_engine import get_yara_engine
        engine = get_yara_engine()
        self.assertIsNotNone(engine)


def run_tests():
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromModule(sys.modules[__name__])
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
