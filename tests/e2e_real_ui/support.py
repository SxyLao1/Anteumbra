"""Isolation helpers for browser-only real-runtime acceptance tests."""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
from pathlib import Path

PASSWORD = "e2e-real-ui-password"


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def write_instance(
    root: Path, password_hash: str, port: int, lab=None, memory_ports=None, access_logs=False
) -> tuple[Path, Path, Path]:
    portal, shop = root / "sites" / "portal", root / "sites" / "shop"
    portal.mkdir(parents=True, exist_ok=True)
    shop.mkdir(parents=True, exist_ok=True)
    rules = root / "rules" / "webshell"
    rules.mkdir(parents=True)
    (rules / "e2e_marker.yar").write_text(
        'rule E2E_Real_UI_Marker { strings: $m = "ANTEUMBRA_E2E_MARKER" condition: $m }\n',
        encoding="utf-8",
    )
    config = f'''[system]
project_root = "."
[[website]]
id = "portal"
name = "Portal test site"
path = "{portal.as_posix()}"
port = 18080
enabled = true
[[website]]
id = "shop"
name = "Shop test site"
path = "{shop.as_posix()}"
port = 18081
enabled = true
[web_admin]
host = "127.0.0.1"
port = {port}
username = "admin"
password_hash = "{password_hash}"
allowed_ips = ["127.0.0.1"]
[paths]
data_dir = "data"
yara_rules_path = "rules/webshell"
[quarantine]
auto_quarantine_enabled = false
[waf_source]
enabled = false
[ip_blocker]
enabled = false
[siem]
enabled = false
[notifier]
enabled = false
[plugins]
enabled = true
builtin = ["stdout_logger"]
[scanner]
scan_existing_on_start = false
[scanner.yara]
enabled = true
'''
    if lab is not None:
        import tomli_w
        import tomllib

        data = tomllib.loads(config)
        data["waf_source"] = {
            "enabled": True,
            "type": "mock",
            "url": lab.url,
            "poll_interval": 1,
            "site_id": "portal",
            "site_name": "Portal test site",
        }
        data["ip_blocker"] = {
            "enabled": True,
            "auto_block_enabled": False,
            "retry_interval_seconds": 120,
            "devices": [
                {"name": "Device A", "type": "http", "url": lab.url + "/device-a/block"},
                {"name": "Device B", "type": "http", "url": lab.url + "/device-b/block"},
            ],
        }
        data["siem"] = {
            "enabled": True,
            "format": "json_lines",
            "export_file": "data/siem/events.jsonl",
            "syslog_host": "127.0.0.1",
            "syslog_port": lab.syslog_port,
            "syslog_protocol": "udp",
        }
        data["plugins"]["builtin"] = [
            "stdout_logger",
            "siem_handler",
            "threat_graph_handler",
            "notifier_handler",
        ]
        data["notifier"] = {
            "enabled": True,
            "email": {"enabled": False},
            "wechat": {"enabled": False},
            "webhook": {"enabled": True, "url": lab.url + "/webhook"},
        }
        config = tomli_w.dumps(data)
    if memory_ports:
        import tomli_w
        import tomllib

        data = tomllib.loads(config)
        for site, target_port in zip(data["website"], memory_ports):
            site["port"] = target_port
        data["plugins"]["builtin"].append("memory_shell_probe")
        data["plugins"]["memory_shell_probe"] = {
            "enabled": True,
            "auto_probe_on_detection": False,
            "site_ids": ["portal", "shop"],
            "host": "127.0.0.1",
            "scheme": "http",
            "http_timeout_seconds": 3,
            "artifact_ttl_seconds": 30,
            "directory_prefix": "mb-",
            "forensics_enabled": True,
            "heap_dump_enabled": True,
            "forensics_timeout_seconds": 5,
            "forensics_max_dump_mb": 1,
        }
        config = tomli_w.dumps(data)
    if access_logs:
        import tomli_w
        import tomllib

        data = tomllib.loads(config)
        for site in data["website"]:
            log_path = root / "test-inputs" / (site["id"] + "-access.log")
            log_path.parent.mkdir(exist_ok=True)
            log_path.touch()
            site["log_config"] = {
                "log_monitor_enabled": True,
                "access_log_path": log_path.as_posix(),
                "filter_internal_ip": False,
            }
        config = tomli_w.dumps(data)
    path = root / "config.toml"
    path.write_text(config, encoding="utf-8")
    return path, portal, shop


def start_runtime(root: Path, port: int, artifacts: Path) -> tuple[subprocess.Popen, object]:
    log = artifacts / f"runtime-{port}.log"
    stream = log.open("w", encoding="utf-8")
    env = {key: value for key, value in os.environ.items() if not key.startswith("ANTEUMBRA_")}
    env.update(
        {
            "ANTEUMBRA_HOME": str(root),
            "ANTEUMBRA_PASSWORD_HASH": "",
            "ANTEUMBRA_SECRET_KEY": "e2e-only-secret",
            "PYTHONIOENCODING": "utf-8",
            "PYTHONUNBUFFERED": "1",
            "PYTHONPATH": str(Path(__file__).resolve().parents[2] / "src"),
        }
    )
    process = subprocess.Popen(
        [
            sys.executable,
            "-u",
            "-m",
            "anteumbra",
            "--home",
            str(root),
            "run",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
        ],
        cwd=root,
        env=env,
        stdout=stream,
        stderr=subprocess.STDOUT,
    )
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if process.poll() is not None:
            stream.close()
            raise RuntimeError(f"real runtime exited; see {log}")
        with socket.socket() as probe:
            probe.settimeout(0.2)
            try:
                if probe.connect_ex(("127.0.0.1", port)) == 0:
                    return process, stream
            except OSError:
                pass
        time.sleep(0.2)
    stop_runtime(process, stream)
    raise RuntimeError(f"real runtime did not bind; see {log}")


def stop_runtime(process: subprocess.Popen, stream) -> None:
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=12)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
    stream.close()
