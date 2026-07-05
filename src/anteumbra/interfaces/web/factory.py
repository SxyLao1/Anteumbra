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
from datetime import timedelta

from flask import Flask, request, session, jsonify
from typing import Optional
from flask_session import Session
from flask_wtf.csrf import CSRFProtect
from anteumbra.infrastructure.config.registry import ConfigRegistry
from anteumbra.infrastructure.utils.path_utils import normalize_path
from flask_wtf.csrf import generate_csrf

logger = logging.getLogger(__name__)

# 全局应用实例
_app_instance: Optional[Flask] = None


def _ensure_password_configured():
    """首次运行：如果密码未配置，自动生成随机密码并写入 .env 文件。

    优先级：环境变量 > .env 文件 > 自动生成
    """
    from pathlib import Path as _Path
    import string as _string

    # 获取已加载的配置路径（ConfigRegistry 初始化后已设置）
    cfg_path = _Path(ConfigRegistry._config_path) if ConfigRegistry._config_path else None
    if cfg_path is None or not cfg_path.exists():
        logger.debug("Config path unknown, skipping password auto-setup")
        return
    root = cfg_path.parent

    # 检查 ANTEUMBRA_PASSWORD_HASH 是否已设置（环境变量或已加载的配置）
    cfg = ConfigRegistry.get_raw_config()
    pw_hash = cfg.get("web_admin", {}).get("password_hash", "")

    # 如果已配置有效 hash（非空且非占位符），跳过
    if pw_hash and not pw_hash.startswith("${"):
        return

    # 检查 .env 文件是否已有 ANTEUMBRA_PASSWORD_HASH
    env_file = root / ".env"
    env_has_pw = False
    if env_file.exists():
        env_has_pw = "ANTEUMBRA_PASSWORD_HASH" in env_file.read_text(encoding="utf-8")

    if env_has_pw:
        # .env 已存在但 initialize 没读到——重新加载
        try:
            from dotenv import load_dotenv
            load_dotenv(str(env_file), override=True)
            ConfigRegistry.initialize(str(cfg_path), force=True)
            return
        except Exception:
            logger.debug("Failed to reload .env for password setup", exc_info=True)
            return

    # 生成随机密码
    import secrets as _secrets
    pwd = ''.join(_secrets.choice(_string.ascii_letters + _string.digits) for _ in range(12))
    from werkzeug.security import generate_password_hash
    h = generate_password_hash(pwd)

    # 写入 .env 文件
    env_file.write_text(
        f"# Anteumbra auto-generated admin password hash\n"
        f"# Regenerate: python -c \"from werkzeug.security import generate_password_hash; print(generate_password_hash('your_password'))\"\n"
        f"ANTEUMBRA_PASSWORD_HASH={h}\n",
        encoding="utf-8"
    )

    # 设置环境变量，重新初始化让配置生效
    os.environ["ANTEUMBRA_PASSWORD_HASH"] = h
    ConfigRegistry.initialize(str(cfg_path), force=True)

    # 打印凭据
    print(f"\n{'='*60}")
    print(f"  Anteumbra — 首次运行")
    print(f"  管理员账号: admin")
    print(f"  管理员密码: {pwd}")
    print(f"  (已写入 {env_file})")
    print(f"{'='*60}\n")


def create_app(config_path: str = None) -> Flask:
    """创建Flask应用实例

    Args:
        config_path: config.toml 路径。None 时自动探测（CWD > 源码树 > 父目录）。
    """
    global _app_instance

    if _app_instance is not None:
        return _app_instance

    # v1.0.9 fix: 确保配置已初始化（run.py 会先调，但 CLI 直接调 create_app 时不会）
    # 优先使用 CWD 的 config.toml（部署环境），其次源码树内（开发环境）
    if config_path:
        ConfigRegistry.initialize(config_path)
    else:
        from pathlib import Path as _Path
        cwd_config = _Path.cwd() / "config.toml"
        if cwd_config.exists():
            ConfigRegistry.initialize(str(cwd_config))
        else:
            ConfigRegistry.initialize()

    # v1.0.9: 首次运行 — 密码为空则自动生成随机密码写入 .env
    _ensure_password_configured()

    # 先静默werkzeug横幅
    from anteumbra.application.logging_service import silence_werkzeug
    silence_werkzeug()

    # 创建主应用
    app = Flask(__name__)

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
    app.config['SECRET_KEY'] = secrets.token_urlsafe(32)  # 改为随机生成
    app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0
    app.config['TEMPLATES_AUTO_RELOAD'] = True

    # === 新增Session配置 ===
    app.config['SESSION_TYPE'] = ConfigRegistry.get_raw_config().get("web_admin", {}).get("session_type", "filesystem")
    app.config['SESSION_FILE_DIR'] = normalize_path(
        ConfigRegistry.get_raw_config().get("web_admin", {}).get("session_dir", "data/sessions")
    )
    app.config['SESSION_PERMANENT'] = ConfigRegistry.get_raw_config().get("web_admin", {}).get("session_permanent",
                                                                                               False)
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(
        seconds=ConfigRegistry.get_raw_config().get("web_admin", {}).get("session_lifetime", 3600)
    )
    # v1.9.6: 开发环境 HTTP 下不使用 Secure cookie，否则浏览器不发送 cookie
    app.config['SESSION_COOKIE_SECURE'] = ConfigRegistry.get_raw_config().get("web_admin", {}).get("session_cookie_secure", False)
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

    # 初始化Session
    Session(app)

    # v1.7.3关键修复：获取access logger并挂载到werkzeug
    from anteumbra.application.logging_service import get_access_logger, get_flask_runtime_logger
    access_logger = get_access_logger()
    flask_runtime_logger = get_flask_runtime_logger()

    # 配置werkzeug logger将访问日志写入access.log
    werkzeug_logger = logging.getLogger('werkzeug')
    werkzeug_logger.handlers = access_logger.handlers
    werkzeug_logger.setLevel(logging.INFO)
    werkzeug_logger.propagate = False

    # v1.7.3修复：Flask应用日志（app.logger）写入flask_runtime.log，不污染monitor.log
    app.logger.handlers = flask_runtime_logger.handlers
    app.logger.setLevel(logging.DEBUG)
    app.logger.propagate = False

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

    _app_instance = app
    return app


def get_app() -> Flask:
    """获取已创建的应用实例"""
    global _app_instance
    if _app_instance is None:
        raise RuntimeError("Flask app not initialized. Call create_app() first.")
    return _app_instance


def run_app(host: str = "127.0.0.1", port: int = 8080, threaded: bool = True):
    """统一启动Flask应用"""
    app = create_app()
    # v1.7.9: V-005修复 — 禁掉Werkzeug开发服务器的版本信息输出
    # Werkzeug在底层BaseHTTPRequestHandler里硬编码了server_version和sys_version，
    # 不关掉的话每个响应都会带 Server: Werkzeug/x.x.x Python/x.x.x
    try:
        from werkzeug.serving import WSGIRequestHandler
        WSGIRequestHandler.server_version = ""    # 清掉 Werkzeug 版本
        WSGIRequestHandler.sys_version = ""       # 清掉 Python 版本
    except Exception:
        logger.debug("Failed to suppress Werkzeug server version headers", exc_info=True)
    app.run(host=host, port=port, threaded=threaded, debug=False)
