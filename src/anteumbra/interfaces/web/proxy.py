"""Trusted reverse-proxy handling for the admin WSGI application."""

from __future__ import annotations

from ipaddress import ip_address, ip_network
from typing import Iterable

from werkzeug.middleware.proxy_fix import ProxyFix


def _networks(values: Iterable[str]):
    for value in values:
        try:
            yield ip_network(str(value).strip(), strict=False)
        except ValueError:
            continue


def is_trusted_proxy(remote_addr: str | None, trusted_proxy_ips: Iterable[str]) -> bool:
    try:
        remote = ip_address(str(remote_addr or "").strip())
    except ValueError:
        return False
    return any(remote in network for network in _networks(trusted_proxy_ips))


class TrustedProxyFix:
    """Apply forwarded headers only when the TCP peer is explicitly trusted."""

    def __init__(self, app, trusted_proxy_ips: Iterable[str], hops: int = 1):
        self._app = app
        self._trusted_proxy_ips = tuple(str(value) for value in trusted_proxy_ips)
        self._proxy_fix = ProxyFix(
            app,
            x_for=max(1, int(hops)),
            x_proto=max(1, int(hops)),
            x_host=max(1, int(hops)),
            x_port=max(1, int(hops)),
            x_prefix=max(1, int(hops)),
        )

    def __call__(self, environ, start_response):
        if is_trusted_proxy(environ.get("REMOTE_ADDR"), self._trusted_proxy_ips):
            return self._proxy_fix(environ, start_response)
        return self._app(environ, start_response)
