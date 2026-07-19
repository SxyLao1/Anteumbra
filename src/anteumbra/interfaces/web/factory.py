# -*- coding: utf-8 -*-
"""
@Time: 1/11/2026 9:49 PM
@Auth: SxyLao1
@File: factory.py
@IDE: PyCharm
@Motto: HACK THE REAL
Flask应用工厂：v1.7.3分离access.log与monitor.log
"""
import logging
import os
import secrets
import time
from datetime import timedelta
from pathlib import Path

from flask import Flask, request, session, jsonify
from flask_session import Session
from flask_wtf.csrf import CSRFProtect
from anteumbra.application.runtime_container import RuntimeContainer
from anteumbra.domain.logging import bind_symbols
from anteumbra.application.path_service import normalize_path
from flask_wtf.csrf import generate_csrf

logger = logging.getLogger(__name__)


def _silence_werkzeug() -> None:
    """Suppress Flask's development banner before attaching access logging."""
    import flask.cli

    flask.cli.show_server_banner = lambda *_args, **_kwargs: None
    werkzeug_logger = logging.getLogger("werkzeug")
    werkzeug_logger.handlers.clear()
    werkzeug_logger.propagate = True
    werkzeug_logger.setLevel(logging.INFO)


def _session_cookie_secure(web_admin_config: dict) -> bool:
    """Use secure sessions automatically when an HTTPS proxy is configured."""
    value = web_admin_config.get("session_cookie_secure", "auto")
    if isinstance(value, str) and value.strip().lower() == "auto":
        return bool(web_admin_config.get("trusted_proxy_ips", []))
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return bool(value)


def _trusted_proxy_hops(web_admin_config: dict) -> int:
    try:
        return max(1, min(10, int(web_admin_config.get("trusted_proxy_hops", 1))))
    except (TypeError, ValueError):
        return 1


def _initialize_credentials(runtime: RuntimeContainer) -> None:
    """Persist and display credentials generated for a first-run runtime."""
    generated_password = runtime.passwords.ensure_initial_secrets()
    if generated_password:
        print(f"\n{'=' * 60}")
        print("  Anteumbra first-run credentials")
        print("  Admin username: admin")
        print(f"  Admin password: {generated_password}")
        print(f"  Stored in: {runtime.passwords.env_path}")
        print(f"{'=' * 60}\n")


def create_app(
    config_path: str | None = None,
    *,
    runtime: RuntimeContainer | None = None,
    plugin_manager=None,
) -> Flask:
    """创建Flask应用实例

    Args:
        config_path: config.toml 路径。None 时自动探测（CWD > 源码树 > 父目录）。
    """
    if runtime is None:
        from anteumbra.application.launcher import build_runtime_container

        runtime = build_runtime_container(
            config_path,
            plugin_manager=plugin_manager,
        )
    else:
        if config_path is not None and Path(config_path).resolve() != runtime.config.path:
            raise ValueError("config_path conflicts with the supplied RuntimeContainer")
        if plugin_manager is not None:
            if runtime.plugin_manager not in (None, plugin_manager):
                raise ValueError("plugin_manager conflicts with the supplied RuntimeContainer")
            runtime.plugin_manager = plugin_manager

    _initialize_credentials(runtime)
    resolved_config = runtime.config.get()

    # 先静默werkzeug横幅
    _silence_werkzeug()

    # 创建主应用
    app = Flask(__name__)
    app.extensions["anteumbra.runtime"] = runtime
    app.extensions["anteumbra.plugin_manager"] = runtime.plugin_manager
    web_admin_config = resolved_config.get("web_admin", {})
    from anteumbra.interfaces.web.proxy import TrustedProxyFix

    app.wsgi_app = TrustedProxyFix(
        app.wsgi_app,
        web_admin_config.get("trusted_proxy_ips", []),
        _trusted_proxy_hops(web_admin_config),
    )

    # v2.0: Flask-Babel i18n (language from ?lang= or cookie or Accept-Language)
    app.config['BABEL_DEFAULT_LOCALE'] = 'en'
    # v1.0.9: 包内翻译路径 — translations/ 已移入 src/anteumbra/translations/
    import anteumbra as _anteumbra_pkg
    _translations_dir = os.path.join(os.path.dirname(_anteumbra_pkg.__file__), "translations")
    app.config['BABEL_TRANSLATION_DIRECTORIES'] = _translations_dir
    try:
        def _select_locale():
            """v2.0 fix: Auto-detect locale from query param → cookie → Accept-Language header."""
            lang = request.args.get('lang')
            if lang and lang in ('en', 'zh'):
                return lang
            lang = request.cookies.get('lang')
            if lang and lang in ('en', 'zh'):
                return lang
            best = request.accept_languages.best_match(['zh', 'en'])
            return best or 'en'

        from flask_babel import Babel
        babel = Babel(app, locale_selector=_select_locale)

        # v2.0: After-request hook to set lang cookie based on detected locale
        @app.after_request
        def _set_lang_cookie(response):
            # Only set if not already present and user hasn't explicitly set ?lang=
            if not request.cookies.get('lang') and not request.args.get('lang'):
                best = request.accept_languages.best_match(['zh', 'en'])
                if best:
                    response.set_cookie('lang', best, max_age=365*24*3600, samesite='Lax')
            elif request.args.get('lang'):
                # User explicitly chose a language — persist it
                lang = request.args.get('lang')
                if lang in ('en', 'zh'):
                    response.set_cookie('lang', lang, max_age=365*24*3600, samesite='Lax')
            return response
    except ImportError:
        pass  # Graceful: works without flask-babel installed

    # v2.0: 注入版本号到所有模板（重命名 trident_ → anteumbra_ 保持模板兼容）
    from anteumbra.application.config_service import get_version, get_release_date
    @app.context_processor
    def inject_version():
        return {
            'anteumbra_version': get_version(),
            'anteumbra_release_date': get_release_date(),
        }
    security_config = resolved_config.get("security", {})
    configured_secret = str(security_config.get("secret_key", "")).strip()
    if not configured_secret:
        configured_secret = os.environ.get("ANTEUMBRA_SECRET_KEY", "").strip()
    if not configured_secret:
        configured_secret = secrets.token_urlsafe(48)
        logger.warning("No persistent session secret was configured; using an ephemeral key")
    app.config['SECRET_KEY'] = configured_secret
    app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0
    app.config['TEMPLATES_AUTO_RELOAD'] = True

    # === 新增Session配置 ===
    session_type = web_admin_config.get("session_type", "filesystem")
    session_dir = normalize_path(
        web_admin_config.get("session_dir", "data/sessions")
    )
    if session_type == "filesystem":
        from cachelib.file import FileSystemCache

        app.config['SESSION_TYPE'] = 'cachelib'
        app.config['SESSION_CACHELIB'] = FileSystemCache(
            cache_dir=str(session_dir),
            threshold=int(web_admin_config.get("session_file_threshold", 500)),
            mode=0o600,
        )
    else:
        app.config['SESSION_TYPE'] = session_type
    app.config['SESSION_PERMANENT'] = web_admin_config.get("session_permanent", False)
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(
        seconds=web_admin_config.get("session_lifetime", 3600)
    )
    app.config['SESSION_COOKIE_SECURE'] = _session_cookie_secure(web_admin_config)
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

    # 初始化Session
    Session(app)

    # v1.7.3关键修复：获取access logger并挂载到werkzeug
    access_logger = runtime.logging.get_access_logger()
    flask_runtime_logger = runtime.logging.get_application_logger()

    # 配置werkzeug logger将访问日志写入access.log
    werkzeug_logger = logging.getLogger('werkzeug')
    werkzeug_logger.handlers = access_logger.handlers
    werkzeug_logger.setLevel(logging.INFO)
    werkzeug_logger.propagate = False

    # v1.7.3修复：Flask应用日志（app.logger）写入flask_runtime.log，不污染monitor.log
    app.logger.handlers = flask_runtime_logger.handlers
    app.logger.setLevel(logging.DEBUG)
    app.logger.propagate = False
    bind_symbols(app.logger, resolved_config)

    # CSRF保护
    _csrf = CSRFProtect()
    _csrf.init_app(app)

    # v2.0 fix: Return JSON for CSRF errors so frontend JS can handle them
    @app.errorhandler(400)
    def _csrf_error_json(e):
        if request.path.startswith('/admin/'):
            # Check if it's actually a CSRF error
            desc = str(e)
            if 'csrf' in desc.lower() or 'token' in desc.lower():
                return jsonify({"error": "CSRF token expired. Please refresh the page.", "code": "csrf_expired"}), 400
        return jsonify({"error": str(e), "code": "bad_request"}), 400

    # v1.7.9: V-005修复 — WSGI中间件级隐藏服务器指纹
    # Werkzeug开发服务器在Flask after_request之后才加Server头，必须在WSGI层拦截
    class _RemoveServerHeaderMiddleware:
        def __init__(self, wsgi_app):
            self.wsgi_app = wsgi_app
        def __call__(self, environ, start_response):
            def _start_response(status, headers, exc_info=None):
                headers = [(k, v) for k, v in headers if k.lower() != 'server']
                return start_response(status, headers, exc_info)
            return self.wsgi_app(environ, _start_response)
    app.wsgi_app = _RemoveServerHeaderMiddleware(app.wsgi_app)

    @app.after_request
    def add_no_cache_headers(response):
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
        return response

    # 注册Blueprint
    from anteumbra.interfaces.web.blueprints import register_blueprints
    register_blueprints(app)

    # CSRF token for all templates (belt-and-suspenders: CSRFProtect also provides this)
    @app.context_processor
    def inject_csrf():
        return dict(csrf_token=generate_csrf)

    return app


class WaitressRuntimeServer:
    """Small lifecycle adapter around Waitress' production WSGI server."""

    def __init__(
        self,
        app: Flask,
        host: str,
        port: int,
        threads: int,
        *,
        sse_manager=None,
    ) -> None:
        try:
            from waitress import create_server
        except ImportError as exc:
            raise RuntimeError(
                "waitress is required to run Anteumbra. Reinstall the package "
                "or install the source dependencies."
            ) from exc
        self._server = create_server(
            app,
            host=host,
            port=port,
            threads=threads,
            ident="Anteumbra",
        )
        self._sse = sse_manager
        self._closed = False

    def serve_forever(self) -> None:
        self._server.run()

    def shutdown(self) -> None:
        if self._closed:
            return
        try:
            if self._sse is not None and self._sse.cleanup_connections():
                # Give active generators a bounded chance to consume their
                # sentinel before Waitress closes the underlying trigger.
                time.sleep(0.15)
        except Exception:
            logger.debug("SSE client cleanup failed during server shutdown", exc_info=True)
        self._server.close()
        self._closed = True

    def server_close(self) -> None:
        """Compatibility alias for stdlib WSGI server lifecycle callers."""
        self.shutdown()


def create_runtime_server(app: Flask, host: str, port: int, threaded: bool = True):
    """Bind Waitress synchronously so startup failures are visible."""
    runtime = app.extensions.get("anteumbra.runtime")
    return WaitressRuntimeServer(
        app,
        host,
        port,
        threads=8 if threaded else 1,
        sse_manager=getattr(runtime, "sse", None),
    )


def run_app(host: str = "127.0.0.1", port: int = 8080, threaded: bool = True):
    """Run the web application in the foreground."""
    server = create_runtime_server(create_app(), host, port, threaded=threaded)
    server.serve_forever()
