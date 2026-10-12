"""Real isolated runtime fixtures. Business state enters only via files and browser UI."""

import json
import os
import re
import shutil
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

import pytest
from playwright.sync_api import sync_playwright
from werkzeug.security import generate_password_hash

from .memory_target import MemoryTarget
from .receivers import ExternalLab
from .support import PASSWORD, free_port, start_runtime, stop_runtime, write_instance

ARTIFACTS = Path(
    os.environ.get(
        "ANTEUMBRA_E2E_ARTIFACTS", Path(tempfile.gettempdir()) / "anteumbra-e2e-artifacts"
    )
)


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    report = outcome.get_result()
    setattr(item, "report_" + report.when, report)


def pytest_configure(config):
    config.addinivalue_line(
        "markers", "expected_http_error(path, status): UI-asserted failure response"
    )
    config.addinivalue_line("markers", "access_logs: configure owned access-log input files")


@pytest.fixture(scope="session")
def browser():
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        yield browser
        browser.close()


@pytest.fixture(params=[(1440, 900), (390, 844)], ids=["desktop", "mobile"])
def real_instance(tmp_path, browser, request, external_lab, memory_targets):
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    port = free_port()
    root = tmp_path / "instance"
    _, portal, shop = write_instance(
        root,
        generate_password_hash(PASSWORD),
        port,
        external_lab,
        [target.port for target in memory_targets],
        access_logs=request.node.get_closest_marker("access_logs") is not None,
    )
    process, stream = start_runtime(root, port, ARTIFACTS)
    context = browser.new_context(viewport={"width": request.param[0], "height": request.param[1]})
    context.tracing.start(screenshots=True, snapshots=True, sources=True)
    page = context.new_page()
    errors = []
    expected_errors = []
    http_errors = []
    http_console = []
    failed = False
    allowed = {
        (mark.args[0], int(mark.args[1]))
        for mark in request.node.iter_markers("expected_http_error")
    }

    def console_message(message):
        if message.type != "error":
            return
        status = re.search(
            r"(?:server responded with a status of|Response Status Error Code) (\d{3})",
            message.text,
        )
        if status:
            http_console.append((int(status.group(1)), message.text))
        else:
            errors.append(message.text)

    page.on("console", console_message)
    page.on(
        "response",
        lambda response: (
            http_errors.append((urlsplit(response.url).path, response.status))
            if response.status >= 400
            else None
        ),
    )
    page.on("pageerror", lambda error: errors.append(str(error)))
    base = f"http://127.0.0.1:{port}"
    try:
        page.goto(base + "/admin/login")
        page.locator("input[name='username']").fill("admin")
        page.locator("input[name='password']").fill(PASSWORD)
        page.locator("button.login-btn").click()
        page.wait_for_url("**/admin/")
        yield page, portal, shop
        # Chromium sometimes leaves HTTP console messages without a source URL.
        # Attribute them using passive response events, never by granting a
        # status-wide exemption. Every failing response still needs an exact
        # endpoint/status marker and a visible error assertion in its scenario.
        expected_errors.extend(http_error for http_error in http_errors if http_error in allowed)
        errors.extend(
            f"Unexpected HTTP {status}: {path}"
            for path, status in http_errors
            if (path, status) not in allowed
        )
        observed_statuses = {status for _, status in http_errors}
        errors.extend(
            message for status, message in http_console if status not in observed_statuses
        )
        assert not errors, errors
    except Exception:
        failed = True
        raise
    finally:
        report = getattr(request.node, "report_call", None)
        failed = failed or bool(report and report.failed)
        capture_errors = []
        try:
            if failed:
                try:
                    page.screenshot(path=str(ARTIFACTS / f"failure-{port}.png"), full_page=True)
                    (ARTIFACTS / f"failure-{port}.txt").write_text(
                        page.locator("body").inner_text(), encoding="utf-8"
                    )
                except Exception as error:
                    capture_errors.append(str(error))
                context.tracing.stop(path=str(ARTIFACTS / f"failure-{port}.zip"))
            else:
                context.tracing.stop()
        finally:
            (ARTIFACTS / f"diagnostics-{port}.json").write_text(
                json.dumps(
                    {
                        "test": request.node.nodeid,
                        "errors": errors,
                        "expected_http_errors": expected_errors,
                        "failed": failed,
                        "capture_errors": capture_errors,
                    },
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )
            try:
                context.close()
            finally:
                stop_runtime(process, stream)


@pytest.fixture
def external_lab():
    with ExternalLab() as lab:
        yield lab


@pytest.fixture
def memory_targets(tmp_path):
    portal = tmp_path / "instance" / "sites" / "portal"
    shop = tmp_path / "instance" / "sites" / "shop"
    portal.mkdir(parents=True, exist_ok=True)
    shop.mkdir(parents=True, exist_ok=True)
    try:
        with MemoryTarget(portal) as portal_target, MemoryTarget(shop) as shop_target:
            yield portal_target, shop_target
    finally:
        owned_root = (tmp_path / "instance").resolve()
        assert owned_root.parent == tmp_path.resolve() and owned_root.name == "instance"
        shutil.rmtree(owned_root)
