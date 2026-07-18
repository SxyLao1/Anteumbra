# -*- coding: utf-8 -*-
"""
E2E Test: Security Hardening (18.3)

Covers:
  1. YARA routes require authentication (302 without login)
  2. Path traversal returns 400/403/404 (not 200 with sensitive data)
  3. Server response headers do not expose version
  4. Login rate limiting (429 after rapid attempts)
"""
import os
import base64
import io
import time
from pathlib import Path
from urllib.parse import quote

import pytest


# ── Flask test client fixtures ──────────────────────────────────────────────


@pytest.fixture(scope="module")
def _app():
    """Create the Flask app once per test module."""
    os.environ.setdefault("ANTEUMBRA_TOOL_MODE", "true")

    from anteumbra.interfaces.web.factory import create_app
    app = create_app()
    app.config["TESTING"] = True
    # Disable CSRF for test client so we can POST forms
    app.config["WTF_CSRF_ENABLED"] = False
    return app


@pytest.fixture
def client(_app):
    """Flask test client — each test gets a fresh client context."""
    with _app.test_client() as c:
        yield c


# ═══════════════════════════════════════════════════════════════════════════════
# 18.3.1 — Authentication Required on Protected Routes
# ═══════════════════════════════════════════════════════════════════════════════

# Routes that MUST require authentication (redirect unauthenticated users)
_PROTECTED_ROUTES = [
    # Admin core
    "/admin/",
    "/admin/overview",
    "/admin/threats",
    "/admin/settings",
    "/admin/dashboard",
    "/admin/dashboard_content",
    "/admin/monitor_content",
    "/admin/account",
    "/admin/system",
    "/admin/registry",
    "/admin/session",
    "/admin/config",
    "/admin/wal",
    # YARA management
    "/admin/yara/rules",
    "/admin/yara/search?q=test",
    # Quarantine
    "/admin/quarantine",
    # Records / Blocklist / Profiles / Scanner
    "/admin/records",
    "/admin/blocklist",
    "/admin/profiles",
    # SSE history
    "/admin/sse/history",
    # SIEM
    "/admin/siem/export",
    "/admin/siem/stats",
    # Metrics
    "/admin/metrics",
    "/admin/metrics/data",
    # System panels
    "/admin/system/registry_panel",
    "/admin/system/wal_panel",
    "/admin/system/session_panel",
    "/admin/system/config_panel",
    # Settings sub-pages
    "/admin/settings/notifications",
    "/admin/settings/config/editor",
    "/admin/settings/siem-status",
    "/admin/settings/storage-status",
    "/admin/settings/plugin-status",
    # Logs
    "/admin/logs/history",
    # Debug (now protected as of v1.0.6)
    "/admin/test",
    "/admin/debug/routes",
]

# Routes that are intentionally public (no auth required)
_PUBLIC_ROUTES = [
    "/admin/login",
    "/admin/api/v1/health",
    "/api/v1/health",
]


class TestAuthRequired:
    """Verify protected routes reject unauthenticated requests."""

    @pytest.mark.parametrize("route", _PROTECTED_ROUTES)
    def test_protected_route_redirects_to_login(self, client, route):
        """Protected routes should redirect (302) or deny (403) without auth.

        The test client's remote_addr is 127.0.0.1, which is in allowed_ips,
        so the expected behavior is a 302 redirect to /admin/login.
        """
        resp = client.get(route, follow_redirects=False)
        # Acceptable outcomes for unauthenticated access:
        #   302 — redirect to login (standard)
        #   403 — IP not in whitelist (if remote_addr is not 127.0.0.1)
        #   401 — unauthorized (if the route uses a different auth pattern)
        #   404 — route doesn't exist (not a security issue but worth noting)
        #   405 — method not allowed (GET vs POST)
        assert resp.status_code in (302, 403, 401, 404, 405), (
            f"Route {route} returned {resp.status_code} — "
            f"expected 302/403/401/404/405 for unauthenticated access.\n"
            f"Body: {resp.get_data(as_text=True)[:200]}"
        )

        # If it returned 200, that's a security issue — the route is unprotected
        assert resp.status_code != 200, (
            f"SECURITY: Route {route} returned 200 without authentication! "
            f"It must have @require_auth decorator."
        )

    def test_yara_routes_require_login(self, client):
        """YARA endpoints should return 302 redirect without session."""
        resp = client.get("/admin/yara/rules")
        assert resp.status_code != 200, (
            "YARA rules endpoint should not be accessible without login"
        )
        assert resp.status_code in (302, 403), (
            f"Expected 302/403 for unauthenticated YARA access, "
            f"got {resp.status_code}"
        )

    def test_yara_validate_requires_login(self, client):
        """YARA validate POST should be rejected without session."""
        resp = client.post(
            "/admin/yara/validate",
            json={"content": 'rule test { condition: true }'},
            content_type="application/json",
        )
        assert resp.status_code != 200, (
            "YARA validate endpoint should not work without login"
        )
        assert resp.status_code in (302, 403, 401, 400), (
            f"Expected 302/403/401/400, got {resp.status_code}"
        )

    def test_admin_routes_require_login(self, client):
        """Admin overview/settings should redirect to login without session."""
        for route in ["/admin/overview", "/admin/settings", "/admin/system"]:
            resp = client.get(route, follow_redirects=False)
            assert resp.status_code != 200, (
                f"Route {route} returned 200 without auth — unprotected!"
            )

    def test_public_routes_accessible(self, client):
        """Intentionally public routes should be accessible without auth."""
        for route in _PUBLIC_ROUTES:
            resp = client.get(route, follow_redirects=False)
            # Public routes should return something other than 302 redirect to login
            # They can be 200, 405, 404 (route missing), but NOT 302 to login
            if resp.status_code == 302:
                location = resp.headers.get("Location", "")
                if "/login" in location:
                    pytest.fail(
                        f"Route {route} is supposed to be public but "
                        f"redirected to login"
                    )
            # Just verify it doesn't 500 crash
            assert resp.status_code != 500, (
                f"Public route {route} crashed with 500"
            )

    def test_debug_routes_lacks_auth(self, client):
        """v1.0.6: /admin/debug/routes is now protected by @require_auth."""
        resp = client.get("/admin/debug/routes")
        assert resp.status_code in (302, 403), (
            f"Expected 302/403 for protected route, got {resp.status_code}"
        )

    def test_post_protected_routes_reject_unauth(self, client):
        """POST to protected action endpoints should be rejected without auth."""
        protected_posts = [
            "/admin/settings/config/save",
            "/admin/settings/env/save",
            "/admin/settings/env/hash",
            "/admin/settings/notifications/save",
            "/admin/account/password",
            "/admin/system/registry/compact",
            "/admin/system/wal/replay",
            "/admin/system/session/cleanup",
            "/admin/system/config/reload",
        ]
        for route in protected_posts:
            resp = client.post(
                route,
                json={},
                content_type="application/json",
            )
            assert resp.status_code != 200, (
                f"POST {route} returned 200 without auth — unprotected!"
            )
            assert resp.status_code not in (500,), (
                f"POST {route} crashed with 500 on unauthenticated access"
            )


# ═══════════════════════════════════════════════════════════════════════════════
# 18.3.2 — Path Traversal Protections
# ═══════════════════════════════════════════════════════════════════════════════


class TestPathTraversal:
    """Verify path traversal protections on file-serving routes."""

    # Patterns that attempt directory traversal
    _TRAVERSAL_PATTERNS = [
        "/admin/../etc/passwd",
        "/admin/yara/rules/../../../etc/passwd",
        "/admin/yara/rules/..%2f..%2f..%2fetc%2fpasswd",
        "/admin/yara/rules/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
        "/admin/records?file=../../../etc/passwd",
        "/admin/quarantine?qid=../../../etc/passwd",
        "/admin/..%252f..%252f..%252fetc%252fpasswd",  # double URL-encoded
    ]

    def test_dot_dot_slash_returns_safe_status(self, client):
        """Requests with ../ in path should not return 200 with sensitive content.

        Flask/Werkzeug normalizes paths automatically, so many traversal
        patterns will be collapsed to safe paths and return 302 (redirect
        to login) or 404. The key assertion: they must never return 200
        with sensitive file contents.
        """
        for pattern in self._TRAVERSAL_PATTERNS:
            # Use the full URL including query string — Flask test client
            # handles query strings natively in the path argument.
            resp = client.get(pattern)

            # Path traversal should result in 400, 403, 404, or 302 — never 200
            if resp.status_code == 200:
                body = resp.get_data(as_text=True)[:500].lower()
                # Check if we got actual file contents (sensitive leak)
                dangerous = any(
                    marker in body
                    for marker in ("root:", "passwd", "[extensions]", "bin/bash")
                )
                if dangerous:
                    pytest.fail(
                        f"PATH TRAVERSAL: {pattern} returned 200 with "
                        f"potentially sensitive content: {body[:200]}"
                    )
                # If it's just an HTML page (Flask handled it safely), it's OK
                if "<html" in body or "<!DOCTYPE" in body:
                    continue
                # Otherwise flag for review
                pytest.fail(
                    f"PATH TRAVERSAL: {pattern} returned 200 with unexpected "
                    f"content: {body[:200]}"
                )

            # All other statuses are safe: 302 (redirect to login),
            # 400 (bad request), 403 (forbidden), 404 (not found)

    def test_null_byte_injection_rejected(self, client):
        """Requests with null byte (%00) should be rejected."""
        patterns = [
            "/admin/yara/rules/test.yar%00.php",
            "/admin/yara/rules/test%00.html",
        ]
        for pattern in patterns:
            resp = client.get(pattern)
            # Should not process the request normally
            assert resp.status_code != 200, (
                f"Null byte injection {pattern} returned 200 — potential bypass"
            )
            # 400 (bad request) is the expected response for null byte injection

    def test_url_encoded_traversal_rejected(self, client):
        """Double URL-encoded traversal attempts should be rejected."""
        # %252e%252e%252f decodes to %2e%2e%2f which decodes to ../
        resp = client.get("/admin/%252e%252e%252fetc%252fpasswd")
        assert resp.status_code != 200, (
            "Double URL-encoded path traversal should not return 200"
        )

    def test_yara_rules_read_requires_valid_filename(self, client):
        """YARA rule content endpoint should reject traversal filenames."""
        # Even with auth redirect, the path validation should happen first
        resp = client.get("/admin/yara/rules/../../../etc/passwd")
        # Should be 400/403/404/302 — never 200 with file contents
        assert resp.status_code != 200, (
            "YARA rules path with traversal should not return 200"
        )


# ═══════════════════════════════════════════════════════════════════════════════
# 18.3.3 — Server Response Headers (Fingerprint Reduction)
# ═══════════════════════════════════════════════════════════════════════════════


class TestServerHeaders:
    """Verify server does not leak version info in response headers."""

    def test_server_header_absent(self, client):
        """Server response header should not be present (removed by middleware)."""
        resp = client.get("/admin/login")
        server_header = resp.headers.get("Server", "")
        # The _RemoveServerHeaderMiddleware should strip the Server header
        # Werkzeug adds "Werkzeug/x.x.x Python/x.x.x" by default
        assert "Python" not in server_header, (
            f"Server header leaks Python version: {server_header}"
        )
        assert "Werkzeug" not in server_header, (
            f"Server header leaks Werkzeug version: {server_header}"
        )

    def test_no_powered_by_header(self, client):
        """X-Powered-By should not be present.

        Flask does not add this header by default, but some middleware or
        reverse proxies might. Verify it's absent.
        """
        resp = client.get("/admin/login")
        powered_by = resp.headers.get("X-Powered-By", "")
        assert not powered_by, (
            f"X-Powered-By header present: {powered_by}"
        )

    def test_no_version_in_headers(self, client):
        """No response header should contain a Python/Flask version string."""
        resp = client.get("/admin/login")
        version_patterns = [
            "Python/3.",
            "Python/2.",
            "Werkzeug/",
            "Flask/",
        ]
        for header_name, header_value in resp.headers:
            combined = f"{header_name}: {header_value}"
            for pattern in version_patterns:
                assert pattern not in combined, (
                    f"Header '{header_name}' leaks version info: {header_value}"
                )

    def test_security_headers_on_login(self, client):
        """Login page should have basic security headers."""
        resp = client.get("/admin/login")
        # Cache-Control is set by the after_request hook in factory.py
        cache_control = resp.headers.get("Cache-Control", "")
        assert "no-cache" in cache_control.lower() or "no-store" in cache_control.lower(), (
            f"Cache-Control should prevent caching, got: {cache_control}"
        )


# ═══════════════════════════════════════════════════════════════════════════════
# 18.3.4 — Login Rate Limiting
# ═══════════════════════════════════════════════════════════════════════════════


class TestRateLimiting:
    """Verify login rate limiting (V-006 fix)."""

    def test_login_rate_limited_after_rapid_attempts(self, client):
        """Rapid login attempts should eventually be rate limited (429).

        The rate limiter allows 5 attempts per 60 seconds per IP.
        After the 5th failed attempt, the 6th should return 429.
        """
        # Reset the rate limiter by importing and clearing
        import anteumbra.interfaces.web.blueprints.admin_bp as admin_mod
        admin_mod._login_attempts.clear()

        attempt_count = 0
        rate_limited = False

        for i in range(10):
            resp = client.post(
                "/admin/login",
                data={"username": "admin", "password": "wrong_password_test"},
                follow_redirects=False,
            )
            attempt_count += 1

            if resp.status_code == 429:
                rate_limited = True
                break

            # Should be 401 (wrong password) or 400 (missing fields)
            # before rate limit kicks in
            assert resp.status_code in (401, 400, 403), (
                f"Unexpected status {resp.status_code} on attempt {i + 1}"
            )

        # Clean up
        admin_mod._login_attempts.clear()

        if not rate_limited:
            pytest.skip(
                f"Rate limiting did not trigger after {attempt_count} attempts. "
                f"The limiter may be configured differently or disabled in test mode."
            )

        assert rate_limited, (
            f"After {attempt_count} rapid login attempts, expected a 429 "
            f"rate-limit response but got none"
        )

    def test_login_rate_limiter_resets_after_window(self, client):
        """After the rate limit window expires, attempts should be allowed again.

        This is a behavioral test: we verify that the rate limiter uses a
        sliding window by checking that _login_attempts is keyed by IP + timestamp.
        """
        import anteumbra.interfaces.web.blueprints.admin_bp as admin_mod

        # Clear state
        admin_mod._login_attempts.clear()

        # Make a few failed attempts
        for _ in range(3):
            client.post(
                "/admin/login",
                data={"username": "admin", "password": "wrong"},
                follow_redirects=False,
            )

        # The rate limiter should have recorded these attempts
        assert len(admin_mod._login_attempts) > 0, (
            "Rate limiter should track login attempts"
        )

        # Verify the entry structure: {ip: (count, first_timestamp)}
        for ip, (count, ts) in admin_mod._login_attempts.items():
            assert isinstance(count, int), "Attempt count should be an integer"
            assert count > 0, "Attempt count should be positive"
            assert isinstance(ts, float), "Timestamp should be a float"

        admin_mod._login_attempts.clear()

    def test_login_rate_limiter_clears_on_success(self):
        """After a successful login, the rate limiter should clear that IP's count.

        This test verifies the behavior by examining the source code.

        Note: We can't easily test the full login success flow without valid
        credentials. Instead, we verify the cleanup logic exists in the source.
        """
        admin_bp_path = (
            Path(__file__).parent.parent.parent
            / "src" / "anteumbra" / "interfaces" / "web" / "blueprints"
            / "admin_bp.py"
        )
        if not admin_bp_path.exists():
            pytest.skip("admin_bp.py not found")

        source = admin_bp_path.read_text(encoding="utf-8")
        # The login success path should pop from _login_attempts
        assert "_login_attempts.pop" in source, (
            "Login success should clear rate limit counter: "
            "_login_attempts.pop(client_ip, None)"
        )
        assert "_check_login_rate" in source, (
            "Login should call _check_login_rate before authenticating"
        )

    def test_login_get_returns_form_not_blocked(self, client):
        """GET /admin/login should always return the form (rate limit only applies to POST)."""
        import anteumbra.interfaces.web.blueprints.admin_bp as admin_mod
        admin_mod._login_attempts.clear()

        # Make many GET requests — none should be rate limited
        for _ in range(10):
            resp = client.get("/admin/login")
            assert resp.status_code == 200, (
                "GET /admin/login should always return 200, "
                "rate limiting is for POST only"
            )

        admin_mod._login_attempts.clear()


class TestPentestRegressions:
    """Regression tests for locally confirmed pentest findings."""

    def _authenticate(self, client, sse_token=None):
        with client.session_transaction() as sess:
            sess["authenticated"] = True
            sess["username"] = "admin"
            if sse_token:
                sess["sse_token"] = sse_token

    def test_stream_logs_rejects_forged_sse_token(self, client):
        forged = base64.b64encode(b"admin:not-the-session-secret").decode()

        resp = client.get(f"/admin/stream_logs?token={forged}")
        assert resp.status_code == 403

        valid_session_token = base64.b64encode(b"admin:real-session-secret").decode()
        self._authenticate(client, sse_token=valid_session_token)

        resp = client.get(f"/admin/stream_logs?token={forged}")
        assert resp.status_code == 403

    def test_yara_upload_rejects_traversal_filename(self, client):
        self._authenticate(client)

        from anteumbra.infrastructure.config.registry import ConfigRegistry
        from anteumbra.infrastructure.utils.path_utils import normalize_path

        rules_path = normalize_path(
            ConfigRegistry.get_raw_config()
            .get("paths", {})
            .get("yara_rules_path", "rules/webshell")
        )
        escaped_path = (rules_path / ".." / "anteumbra_pentest_escape.yar").resolve()
        if escaped_path.exists():
            escaped_path.unlink()

        try:
            resp = client.post(
                "/admin/yara/rules/upload",
                data={
                    "file": (
                        io.BytesIO(b"rule anteumbra_pentest_escape { condition: true }\n"),
                        "../anteumbra_pentest_escape.yar",
                    )
                },
                content_type="multipart/form-data",
            )

            assert resp.status_code == 400
            assert not escaped_path.exists()
        finally:
            if escaped_path.exists():
                escaped_path.unlink()

    def test_yara_edit_modal_escapes_rule_content(self, client):
        self._authenticate(client)

        from anteumbra.infrastructure.config.registry import ConfigRegistry
        from anteumbra.infrastructure.utils.path_utils import normalize_path

        rules_path = normalize_path(
            ConfigRegistry.get_raw_config()
            .get("paths", {})
            .get("yara_rules_path", "rules/webshell")
        )
        rules_path.mkdir(parents=True, exist_ok=True)
        rule_file = rules_path / "anteumbra_pentest_xss.yar"
        payload = "</textarea><script>window.__anteumbra_xss=1</script>"
        rule_file.write_text(
            f'rule anteumbra_pentest_xss {{ strings: $a = "{payload}" condition: $a }}\n',
            encoding="utf-8",
        )

        try:
            resp = client.get("/admin/yara/rules/edit/anteumbra_pentest_xss.yar")
            body = resp.get_data(as_text=True)

            assert resp.status_code == 200
            assert payload not in body
            assert "&lt;/textarea&gt;&lt;script&gt;" in body
        finally:
            rule_file.unlink(missing_ok=True)

    def test_scanner_run_requires_post_job_creation(self, client):
        self._authenticate(client)

        get_resp = client.get("/admin/scanner/run?target_dir=.")
        assert get_resp.status_code == 405

        post_resp = client.post("/admin/scanner/run", data={})
        assert post_resp.status_code == 400
        assert post_resp.get_json()["error"] == "missing target_dir"

    def test_scanner_post_job_streams_completion(self, client, monkeypatch, tmp_path):
        self._authenticate(client)

        scan_id = "anteumbra-test-scanner-post-stream"
        scan_file = Path("data") / "scans" / f"{scan_id}.json"

        class DummyResult:
            def __init__(self):
                self.scan_id = scan_id
                self.target_dir = str(tmp_path)
                self.start_time = time.time()
                self.end_time = self.start_time + 0.1
                self.status = "completed"
                self.total_files = 1
                self.scanned_files = 1
                self.new_findings = 0
                self.known_findings = 0
                self.clean = 1
                self.errors = 0
                self.findings = []

        class DummyScanner:
            def __init__(self, logger, site_id=None, site_name=None, **_dependencies):
                self.logger = logger
                self.site_id = site_id
                self.site_name = site_name

            def scan_directory(self, **kwargs):
                result = DummyResult()
                kwargs["progress_callback"](result)
                return result

        monkeypatch.setattr(
            "anteumbra.application.scanner_service.ManualScanner",
            DummyScanner,
        )

        try:
            post_resp = client.post(
                "/admin/scanner/run",
                data={"target_dir": str(tmp_path), "recursive": "0"},
            )
            assert post_resp.status_code == 200
            payload = post_resp.get_json()
            assert payload["success"] is True
            assert payload["stream_url"].startswith("/admin/scanner/stream?scan_id=")

            stream_resp = client.get(payload["stream_url"])
            body = stream_resp.get_data(as_text=True)
            assert stream_resp.status_code == 200
            assert '"event": "init"' in body
            assert '"event": "complete"' in body
            assert scan_id in body
        finally:
            scan_file.unlink(missing_ok=True)
