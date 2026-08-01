from werkzeug.test import create_environ

from anteumbra.interfaces.web.auth import is_ip_allowed
from anteumbra.interfaces.web.factory import _session_cookie_secure
from anteumbra.interfaces.web.proxy import TrustedProxyFix


def _capture_app(observed):
    def app(environ, start_response):
        observed["remote_addr"] = environ["REMOTE_ADDR"]
        observed["scheme"] = environ["wsgi.url_scheme"]
        start_response("200 OK", [])
        return [b""]

    return app


def test_forwarded_headers_apply_only_from_a_trusted_proxy():
    observed = {}
    app = TrustedProxyFix(_capture_app(observed), ["127.0.0.1"], hops=1)
    environ = create_environ(
        headers={
            "X-Forwarded-For": "203.0.113.5",
            "X-Forwarded-Proto": "https",
        },
    )
    environ["REMOTE_ADDR"] = "127.0.0.1"

    list(app(environ, lambda *_args: None))

    assert observed == {"remote_addr": "203.0.113.5", "scheme": "https"}


def test_untrusted_peer_cannot_spoof_forwarded_client_address():
    observed = {}
    app = TrustedProxyFix(_capture_app(observed), ["127.0.0.1"], hops=1)
    environ = create_environ(headers={"X-Forwarded-For": "203.0.113.5"})
    environ["REMOTE_ADDR"] = "10.0.0.99"

    list(app(environ, lambda *_args: None))

    assert observed["remote_addr"] == "10.0.0.99"


def test_admin_allowlist_supports_ip_and_cidr_without_invalid_entries():
    allowed = ["127.0.0.1", "192.168.10.0/24", "not-an-address"]

    assert is_ip_allowed("127.0.0.1", allowed)
    assert is_ip_allowed("192.168.10.42", allowed)
    assert not is_ip_allowed("192.168.11.42", allowed)


def test_secure_cookie_auto_mode_tracks_trusted_proxy_configuration():
    assert _session_cookie_secure({"session_cookie_secure": "auto"}) is False
    assert (
        _session_cookie_secure(
            {
                "session_cookie_secure": "auto",
                "trusted_proxy_ips": ["127.0.0.1"],
            }
        )
        is True
    )
    assert _session_cookie_secure({"session_cookie_secure": False}) is False
    assert _session_cookie_secure({"session_cookie_secure": True}) is True
