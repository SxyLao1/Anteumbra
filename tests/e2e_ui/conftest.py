# -*- coding: utf-8 -*-
"""
E2E UI Tests — shared fixtures (Playwright + Flask test server)

Each test gets a FRESH Flask server (function scope) to avoid state
accumulation that causes intermittent timeouts.
"""
import sys
import socket
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
from werkzeug.security import generate_password_hash
from playwright.sync_api import sync_playwright


TEST_PASSWORD = "test_anteumbra"
TEST_HASH = generate_password_hash(TEST_PASSWORD)

CHROMIUM_UNSAFE_PORTS = {
    1, 7, 9, 11, 13, 15, 17, 19, 20, 21, 22, 23, 25, 37, 42, 43, 53, 69,
    77, 79, 87, 95, 101, 102, 103, 104, 109, 110, 111, 113, 115, 117, 119,
    123, 135, 137, 139, 143, 161, 179, 389, 427, 465, 512, 513, 514, 515,
    526, 530, 531, 532, 540, 548, 554, 556, 563, 587, 601, 636, 989, 990,
    993, 995, 1719, 1720, 1723, 2049, 3659, 4045, 5060, 5061, 6000, 6566,
    6665, 6666, 6667, 6668, 6669, 6697, 10080,
}

# ── Session-scoped browser (expensive to restart) ─────────────
_pw_instance = None
_browser_instance = None


def _find_free_port() -> int:
    for _ in range(100):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        if port not in CHROMIUM_UNSAFE_PORTS:
            return port
    raise RuntimeError("Could not find a Chromium-safe free port")


@pytest.fixture(scope="session")
def browser():
    """Launch Playwright Chromium once for the whole session."""
    global _pw_instance, _browser_instance
    _pw_instance = sync_playwright().start()
    _browser_instance = _pw_instance.chromium.launch(headless=True)
    yield _browser_instance
    _browser_instance.close()
    _pw_instance.stop()


@pytest.fixture
def runtime_server(monkeypatch, tmp_path):
    """Start a FRESH Flask app for each test — no state accumulation."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("ANTEUMBRA_TOOL_MODE", "true")
    monkeypatch.setenv("PYTEST_CURRENT_TEST", "true")
    monkeypatch.setenv("ANTEUMBRA_HOME", str(tmp_path))

    # Monkey-patch credentials
    import anteumbra.interfaces.web.auth as auth_mod
    original_get_creds = auth_mod.get_admin_credentials

    def _test_credentials():
        return ("admin", TEST_HASH, ["127.0.0.1"])

    auth_mod.get_admin_credentials = _test_credentials

    project_root = Path(__file__).resolve().parent.parent.parent
    sys.path.insert(0, str(project_root))

    from anteumbra.interfaces.web.factory import create_app
    app = create_app()
    app.config["TESTING"] = True
    app.config["SERVER_NAME"] = None

    port = _find_free_port()
    base_url = f"http://127.0.0.1:{port}"

    from anteumbra.interfaces.web.factory import create_runtime_server
    server = create_runtime_server(app, "127.0.0.1", port)
    server_thread = threading.Thread(
        target=server.serve_forever,
        daemon=True,
        name=f"AnteumbraTestServer-{port}",
    )
    server_thread.start()

    import requests
    deadline = time.time() + 10
    while time.time() < deadline:
        try:
            r = requests.get(f"{base_url}/admin/login", timeout=1)
            if r.status_code in (200, 302, 401, 403):
                break
        except Exception:
            time.sleep(0.2)
    else:
        raise RuntimeError(f"Flask server did not start on {base_url}")

    runtime = app.extensions["anteumbra.runtime"]
    yield SimpleNamespace(url=base_url, runtime=runtime)

    # Teardown
    server.shutdown()
    server_thread.join(timeout=5.0)
    server.server_close()
    auth_mod.get_admin_credentials = original_get_creds
    for resource, method in (
        (runtime.quarantine, "close"),
        (runtime.registry, "close"),
        (runtime.block_ledger, "close"),
        (runtime.notifier, "shutdown"),
    ):
        callback = getattr(resource, method, None)
        if callable(callback):
            callback()


@pytest.fixture
def server_url(runtime_server):
    return runtime_server.url


@pytest.fixture
def runtime(runtime_server):
    return runtime_server.runtime


@pytest.fixture
def page(server_url, browser):
    """Authenticated page — fresh context per test."""
    context = browser.new_context(viewport={"width": 1440, "height": 900})
    pg = context.new_page()

    # Login
    pg.goto(f"{server_url}/admin/login")
    pg.wait_for_selector("form.login-form", timeout=5000)
    pg.fill("input[name='username']", "admin")
    pg.fill("input[name='password']", TEST_PASSWORD)
    pg.click("button.login-btn")
    pg.wait_for_url("**/admin/", timeout=5000)

    yield pg
    context.close()


@pytest.fixture
def unauthenticated_page(server_url, browser):
    """Clean page — no login."""
    context = browser.new_context(viewport={"width": 1440, "height": 900})
    pg = context.new_page()
    yield pg
    context.close()


# ── Helper: navigate without waiting for CDN scripts ───────────
def go(page, url, **kw):
    """Navigate to target URL cleanly: first unload the current page
    (killing any active SSE connections), then go to the target.
    Uses wait_until='commit' to avoid blocking on CDN <script> tags."""
    kw.setdefault("wait_until", "commit")
    kw.setdefault("timeout", 20000)
    page.goto("about:blank", wait_until="commit", timeout=10000)
    page.wait_for_timeout(200)
    return page.goto(url, **kw)
