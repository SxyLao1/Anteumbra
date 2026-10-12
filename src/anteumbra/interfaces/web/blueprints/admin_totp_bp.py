"""Single-administrator TOTP enrollment and login challenge routes."""

from __future__ import annotations

import logging
import time

from flask import Blueprint, current_app, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash

from anteumbra.application.totp_service import TotpService
from anteumbra.domain.logging import log_with_symbol
from anteumbra.interfaces.web.auth import get_admin_credentials, require_auth
from anteumbra.interfaces.web.blueprints._shared import generate_secure_sse_token
from anteumbra.interfaces.web.pages import render_page
from anteumbra.interfaces.web.runtime import get_runtime

logger = logging.getLogger(__name__)

admin_totp_bp = Blueprint("admin_totp", __name__, url_prefix="/admin")


@admin_totp_bp.route("/login/totp", methods=["GET", "POST"])
def login_totp():
    """Complete the one-administrator password + TOTP login challenge."""
    username = session.get("totp_pending_username")
    started_at = float(session.get("totp_pending_at") or 0)
    if not username or time.time() - started_at > TotpService.LOGIN_TTL_SECONDS:
        session.pop("totp_pending_username", None)
        session.pop("totp_pending_at", None)
        return redirect(url_for("admin.login"))

    if request.method == "GET":
        return render_template("admin/login.html", totp_challenge=True, username=username)

    client_ip = request.remote_addr or "unknown"
    limiter = get_runtime().login_rate_limiter
    decision = limiter.check_and_record(client_ip)
    if not decision.allowed:
        error = f"登录尝试过于频繁，请 {decision.retry_after_seconds} 秒后重试"
        return (
            render_template("admin/login.html", totp_challenge=True, username=username, error=error),
            429,
            {"Retry-After": str(decision.retry_after_seconds)},
        )

    code = request.form.get("totp_code", "")
    totp = getattr(get_runtime(), "totp", None)
    accepted = bool(totp and totp.verify(code))
    recovery_used = False
    if not accepted and totp is not None:
        recovery_used = totp.consume_recovery_code(code)
        accepted = recovery_used
    if not accepted:
        log_with_symbol(
            "critical_permission",
            "critical",
            f"TOTP 二次认证失败: {username}",
            current_app.logger,
        )
        return (
            render_template(
                "admin/login.html",
                totp_challenge=True,
                username=username,
                error="验证码或恢复码错误 / Invalid authenticator or recovery code",
            ),
            401,
        )

    limiter.reset(client_ip)
    session.pop("totp_pending_username", None)
    session.pop("totp_pending_at", None)
    session["authenticated"] = True
    session["username"] = username
    session.permanent = current_app.config.get("SESSION_PERMANENT", False)
    session["sse_token"] = generate_secure_sse_token(username)
    if recovery_used:
        log_with_symbol(
            "critical_permission",
            "warning",
            f"用户 {username} 使用一次性 TOTP 恢复码登录",
            current_app.logger,
        )
    log_with_symbol("success", "info", f"用户 {username} TOTP 登录成功", current_app.logger)
    return redirect(url_for("admin.dashboard_index"))


@admin_totp_bp.route("/account", methods=["GET"])
@require_auth
def account_page():
    """Render the one administrator account settings page."""
    notices = {
        "enabled": "TOTP enabled. Store the recovery codes from setup safely.",
        "disabled": "TOTP disabled. New logins no longer require a code.",
    }
    return _render_account(success=notices.get(request.args.get("totp", "")))


def _render_account(*, error: str | None = None, success: str | None = None, status: int = 200):
    runtime = get_runtime()
    totp = getattr(runtime, "totp", None)
    enrollment = None
    secret = session.get("totp_enrollment_secret")
    recovery_codes = session.get("totp_enrollment_recovery_codes")
    started_at = float(session.get("totp_enrollment_at") or 0)
    if secret and time.time() - started_at <= TotpService.PENDING_TTL_SECONDS:
        enrollment = {
            "secret": secret,
            "recovery_codes": recovery_codes or [],
            "otpauth_uri": TotpService.otpauth_uri(
                secret,
                "Anteumbra",
                session.get("username", "admin"),
            ),
        }
    elif secret:
        _clear_totp_enrollment()
    response = render_page(
        "admin/account.html",
        username=session.get("username"),
        totp_enabled=bool(totp and totp.enabled),
        totp_enrollment=enrollment,
        error=error,
        success=success,
    )
    if status != 200:
        return response, status
    return response


def _clear_totp_enrollment() -> None:
    session.pop("totp_enrollment_secret", None)
    session.pop("totp_enrollment_recovery_codes", None)
    session.pop("totp_enrollment_at", None)


def _current_password_is_valid(password: str) -> bool:
    _, stored_hash, _ = get_admin_credentials()
    return bool(password and stored_hash and check_password_hash(stored_hash, password))


@admin_totp_bp.route("/account/totp/setup", methods=["POST"])
@require_auth
def setup_totp():
    runtime = get_runtime()
    totp = getattr(runtime, "totp", None)
    if totp is None:
        return _render_account(error="TOTP service is unavailable", status=503)
    if totp.enabled:
        return _render_account(error="TOTP is already enabled")
    if not _current_password_is_valid(request.form.get("current_password", "")):
        return _render_account(error="当前密码错误 / Current password is incorrect", status=401)
    secret = totp.generate_secret()
    session["totp_enrollment_secret"] = secret
    session["totp_enrollment_recovery_codes"] = totp.generate_recovery_codes()
    session["totp_enrollment_at"] = time.time()
    log_with_symbol(
        "notice",
        "info",
        f"用户 {session.get('username', 'admin')} 开始 TOTP 配置",
        current_app.logger,
    )
    return redirect(url_for("admin_totp.account_page"))


@admin_totp_bp.route("/account/totp/enable", methods=["POST"])
@require_auth
def enable_totp():
    runtime = get_runtime()
    totp = getattr(runtime, "totp", None)
    secret = session.get("totp_enrollment_secret")
    recovery_codes = session.get("totp_enrollment_recovery_codes") or []
    started_at = float(session.get("totp_enrollment_at") or 0)
    if totp is None or not secret or time.time() - started_at > TotpService.PENDING_TTL_SECONDS:
        _clear_totp_enrollment()
        return _render_account(error="TOTP enrollment expired; start again")
    if not totp.verify_code(secret, request.form.get("totp_code", "")):
        return _render_account(error="验证码错误 / Invalid authenticator code", status=401)
    try:
        totp.enable(secret, recovery_codes)
    except (OSError, RuntimeError, ValueError) as exc:
        logger.error("TOTP enable failed: %s", exc, exc_info=True)
        return _render_account(error="TOTP could not be enabled", status=500)
    _clear_totp_enrollment()
    log_with_symbol(
        "success",
        "info",
        f"用户 {session.get('username', 'admin')} 启用 TOTP 二次认证",
        current_app.logger,
    )
    return redirect(url_for("admin_totp.account_page", totp="enabled"))


@admin_totp_bp.route("/account/totp/disable", methods=["POST"])
@require_auth
def disable_totp():
    runtime = get_runtime()
    totp = getattr(runtime, "totp", None)
    if totp is None or not totp.enabled:
        return _render_account(error="TOTP is already disabled")
    if not _current_password_is_valid(request.form.get("current_password", "")):
        return _render_account(error="当前密码错误 / Current password is incorrect", status=401)
    code = request.form.get("totp_code", "")
    accepted = totp.verify(code)
    recovery_used = False
    if not accepted:
        recovery_used = totp.consume_recovery_code(code)
        accepted = recovery_used
    if not accepted:
        return _render_account(error="验证码或恢复码错误 / Invalid authenticator or recovery code", status=401)
    try:
        totp.disable()
    except (OSError, RuntimeError, ValueError) as exc:
        logger.error("TOTP disable failed: %s", exc, exc_info=True)
        return _render_account(error="TOTP could not be disabled", status=500)
    log_with_symbol(
        "warning" if recovery_used else "success",
        "warning" if recovery_used else "info",
        f"用户 {session.get('username', 'admin')} 停用 TOTP 二次认证"
        + ("（使用恢复码）" if recovery_used else ""),
        current_app.logger,
    )
    return redirect(url_for("admin_totp.account_page", totp="disabled"))

