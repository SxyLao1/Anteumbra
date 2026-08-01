import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def read_source(*parts: str) -> str:
    return (ROOT.joinpath(*parts)).read_text(encoding="utf-8")


def test_live_log_sse_control_messages_are_not_emitted_or_rendered():
    monitor_bp = read_source(
        "src",
        "anteumbra",
        "interfaces",
        "web",
        "blueprints",
        "monitor_bp.py",
    )
    sse_manager = read_source(
        "src",
        "anteumbra",
        "interfaces",
        "web",
        "static",
        "js",
        "sse-manager.js",
    )

    assert "[SSE] Connected to log stream" not in monitor_bp
    assert "[SSE] Monitoring logs" not in monitor_bp
    assert "if (rawData.indexOf('[SSE]') === 0) {" in sse_manager


def test_sse_responses_do_not_set_wsgi_hop_by_hop_connection_headers():
    monitor_bp = read_source(
        "src",
        "anteumbra",
        "interfaces",
        "web",
        "blueprints",
        "monitor_bp.py",
    )
    scanner_bp = read_source(
        "src",
        "anteumbra",
        "interfaces",
        "web",
        "blueprints",
        "scanner_bp.py",
    )

    assert "'Connection': 'keep-alive'" not in monitor_bp
    assert "'Connection': 'keep-alive'" not in scanner_bp


def test_log_stream_uses_runtime_owned_site_paths_without_name_fallbacks():
    monitor_bp = read_source(
        "src",
        "anteumbra",
        "interfaces",
        "web",
        "blueprints",
        "monitor_bp.py",
    )
    admin_bp = read_source(
        "src",
        "anteumbra",
        "interfaces",
        "web",
        "blueprints",
        "admin_bp.py",
    )

    assert "get_enabled_websites()" in monitor_bp
    assert "anteumbra.infrastructure.config.registry" not in monitor_bp
    assert "runtime.logging.get_site_log_path" in monitor_bp
    assert "collect_log_history" in monitor_bp
    assert "logs/{website.name}/monitor.log" not in monitor_bp
    assert "logs/Default Website/monitor.log" not in monitor_bp
    assert "logs/Website-PhpStudy/monitor.log" not in monitor_bp
    assert "collect_log_history" in admin_bp
    assert "sse_log_buffer.json" not in admin_bp


def test_notifier_internal_logs_use_runtime_logger():
    notifier_handler = read_source(
        "src",
        "anteumbra",
        "plugins",
        "notifier_handler.py",
    )

    assert "log: logging.Logger" in notifier_handler
    assert "self._logger = log" in notifier_handler
    assert "RotatingFileHandler" not in notifier_handler
    assert "plugins.log" not in notifier_handler


def test_notifier_log_masking_hides_secrets():
    notifier_path = ROOT / "src" / "anteumbra" / "infrastructure" / "monitoring" / "notifier.py"
    spec = importlib.util.spec_from_file_location("anteumbra_source_notifier", notifier_path)
    notifier = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(notifier)

    masked_url = notifier._mask_url_secret("https://sctapi.ftqq.com/SCT1234567890abcdef.send")
    sanitized_error = notifier._sanitize_log_text(
        "400 Client Error for url: https://sctapi.ftqq.com/SCT1234567890abcdef.send"
    )
    masked_email = notifier._mask_email("exampleuser@example.com")

    assert "SCT1234567890abcdef" not in masked_url
    assert "SCT1234567890abcdef" not in sanitized_error
    assert "exampleuser" not in masked_email
    assert masked_url.endswith(".send")
    assert masked_email.endswith("@example.com")


def test_access_log_analysis_is_available_from_log_analyzer():
    monitor_bp = read_source(
        "src",
        "anteumbra",
        "interfaces",
        "web",
        "blueprints",
        "monitor_bp.py",
    )
    dashboard_js = read_source("src", "anteumbra", "interfaces", "web", "static", "js", "dashboard.js")
    overview = read_source("src", "anteumbra", "interfaces", "web", "templates", "admin", "overview.html")

    assert "@monitor_bp.route('/logs/access-analysis')" in monitor_bp
    assert "runtime.log_analysis.analyze" in monitor_bp
    assert "function loadAccessLogAnalysis()" in dashboard_js
    assert "/admin/logs/access-analysis" in dashboard_js
    assert "Access Analysis" in overview
