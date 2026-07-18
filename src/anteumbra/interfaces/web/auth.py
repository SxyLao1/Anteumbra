# -*- coding: utf-8 -*-
"""Shared web authentication helpers for admin blueprints."""
from functools import wraps
from ipaddress import ip_address, ip_network
from flask import request, session, redirect, url_for, make_response
from anteumbra.interfaces.web.runtime import get_runtime


def get_admin_credentials():
    """从配置读取管理员凭证"""
    cfg = get_runtime().config.get().get("web_admin", {})
    username = cfg.get("username", "admin")
    password_hash = cfg.get("password_hash", "")
    allowed_ips = cfg.get("allowed_ips", ["127.0.0.1"])
    return username, password_hash, allowed_ips


def is_ip_allowed(client_ip: str, allowed_ips) -> bool:
    """Match a client address against exact IPs or CIDR ranges."""
    try:
        address = ip_address(str(client_ip or "").strip())
    except ValueError:
        return False
    if isinstance(allowed_ips, str):
        allowed_ips = [allowed_ips]
    for value in allowed_ips or []:
        try:
            if address in ip_network(str(value).strip(), strict=False):
                return True
        except ValueError:
            continue
    return False


def require_auth(f):
    """认证装饰器：检查 IP 白名单 + Session 登录状态"""
    @wraps(f)
    def decorated(*args, **kwargs):
        client_ip = request.remote_addr
        _, _, allowed_ips = get_admin_credentials()
        if not is_ip_allowed(client_ip, allowed_ips):
            response = make_response(f'IP {client_ip} 被拒绝访问', 403)
            return response
        if not session.get('authenticated'):
            return redirect(url_for('admin.login'))
        return f(*args, **kwargs)
    return decorated
