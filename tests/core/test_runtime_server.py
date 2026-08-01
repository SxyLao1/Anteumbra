import http.client
import socket
import sys
import threading
import time
import urllib.request
from types import SimpleNamespace

import pytest
from flask import Flask


def test_runtime_server_uses_waitress_and_exposes_launcher_lifecycle(monkeypatch):
    from anteumbra.interfaces.web.factory import create_runtime_server

    calls = {}

    class FakeChannel:
        def close(self):
            calls["channel_close"] = calls.get("channel_close", 0) + 1

    class FakeDispatcher:
        def shutdown(self, **kwargs):
            calls["dispatcher_shutdown"] = kwargs

    class FakeServer:
        active_channels = {"client": FakeChannel()}
        task_dispatcher = FakeDispatcher()

        def run(self):
            calls["run"] = True

        def pull_trigger(self):
            calls["pull_trigger"] = True

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
    assert calls["ident"] == ""
    assert calls["run"] is True
    assert calls["pull_trigger"] is True
    assert calls["channel_close"] == 1
    assert calls["dispatcher_shutdown"] == {
        "cancel_pending": True,
        "timeout": 2.0,
    }
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
        server_header = None
        for _ in range(30):
            try:
                with urllib.request.urlopen(
                    f"http://127.0.0.1:{port}/health",
                    timeout=0.5,
                ) as response:
                    body = response.read()
                    server_header = response.headers.get("Server")
                break
            except OSError:
                time.sleep(0.05)
        assert body == b'{"status":"ok"}\n'
        assert server_header is None
    finally:
        server.shutdown()
        thread.join(timeout=3.0)

    assert not thread.is_alive()


def test_waitress_runtime_server_closes_keep_alive_connections():
    pytest.importorskip("waitress")
    from anteumbra.interfaces.web.factory import create_runtime_server

    app = Flask("waitress-keep-alive")

    @app.get("/health")
    def health():
        return {"status": "ok"}

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]

    server = create_runtime_server(app, "127.0.0.1", port)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=2.0)
    try:
        for _ in range(30):
            try:
                connection.request("GET", "/health")
                response = connection.getresponse()
                assert response.read() == b'{"status":"ok"}\n'
                break
            except OSError:
                time.sleep(0.05)
        else:
            pytest.fail("Waitress server did not accept a keep-alive connection")

        started = time.monotonic()
        server.shutdown()
        thread.join(timeout=2.0)
        elapsed = time.monotonic() - started
    finally:
        connection.close()
        server.shutdown()

    assert not thread.is_alive()
    assert elapsed < 2.0
