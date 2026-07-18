import sys
import socket
import threading
import time
import urllib.request
from types import SimpleNamespace

import pytest
from flask import Flask


def test_runtime_server_uses_waitress_and_exposes_launcher_lifecycle(monkeypatch):
    from anteumbra.interfaces.web.factory import create_runtime_server

    calls = {}

    class FakeServer:
        def run(self):
            calls["run"] = True

        def close(self):
            calls["close"] = calls.get("close", 0) + 1

    def create_server(app, **kwargs):
        calls["app"] = app
        calls.update(kwargs)
        return FakeServer()

    monkeypatch.setitem(
        sys.modules,
        "waitress",
        SimpleNamespace(create_server=create_server),
    )
    app = Flask("test-runtime-server")

    server = create_runtime_server(app, "127.0.0.1", 18080, threaded=True)
    server.serve_forever()
    server.shutdown()
    server.server_close()

    assert calls["app"] is app
    assert calls["host"] == "127.0.0.1"
    assert calls["port"] == 18080
    assert calls["threads"] == 8
    assert calls["run"] is True
    assert calls["close"] == 1


def test_waitress_runtime_server_serves_and_stops_cleanly():
    pytest.importorskip("waitress")
    from anteumbra.interfaces.web.factory import create_runtime_server

    app = Flask("waitress-smoke")

    @app.get("/health")
    def health():
        return {"status": "ok"}

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]

    server = create_runtime_server(app, "127.0.0.1", port)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        body = None
        for _ in range(30):
            try:
                with urllib.request.urlopen(
                    f"http://127.0.0.1:{port}/health",
                    timeout=0.5,
                ) as response:
                    body = response.read()
                break
            except OSError:
                time.sleep(0.05)
        assert body == b'{"status":"ok"}\n'
    finally:
        server.shutdown()
        thread.join(timeout=3.0)

    assert not thread.is_alive()
