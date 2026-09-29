"""Loopback external devices, controlled and observed through their HTML UI.

Only counterpart devices are simulated; Anteumbra makes real HTTP requests and
UDP sends. Tests never invoke these handlers or inspect the private receipts.
"""
import json
import socket
import threading
from datetime import datetime, timezone

from flask import Flask, jsonify, redirect, render_template_string, request
from werkzeug.serving import make_server


class ExternalLab:
    def __init__(self):
        self._lock = threading.Lock()
        self._receipts = []
        self._events = []
        self._failure = False
        self._stop = threading.Event()
        self._udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._udp.bind(("127.0.0.1", 0))
        self._udp.settimeout(0.2)
        self.syslog_port = self._udp.getsockname()[1]
        app = Flask(__name__)

        @app.get("/")
        def index():
            with self._lock:
                rows, count = list(self._receipts), len(self._events)
            return render_template_string('''<!doctype html><html lang="en"><meta charset="utf-8">
            <title>Anteumbra external test lab</title><h1>External integrations lab</h1>
            <p>Loopback devices. Receipts below are actual requests from Anteumbra.</p>
            <form method="post" action="/scenario"><button>Generate Portal WAF events</button></form>
            <form method="post" action="/failure"><button>{{ 'Recover device' if failure else 'Fail device B' }}</button></form>
            <a href="/">Refresh receipts</a><p id="event-count">{{ count }} WAF events</p>
            <table><thead><tr><th>Channel</th><th>Payload</th></tr></thead><tbody>
            {% for row in rows %}<tr><td>{{ row[0] }}</td><td><pre>{{ row[1] }}</pre></td></tr>{% endfor %}
            </tbody></table></html>''', rows=rows, count=count, failure=self._failure)

        @app.post("/scenario")
        def scenario():
            now = datetime.now(timezone.utc).isoformat()
            with self._lock:
                for number in range(12):
                    self._events.append({
                        "event_id": f"browser-waf-{len(self._events)}", "timestamp": now,
                        "src_ip": "198.51.100.24", "http_method": "POST",
                        "url": f"/uploads/marker{number}.php", "user_agent": "sqlmap/1.8",
                        "waf_rule_id": "BrowserWAF", "waf_score": 0.95,
                        "attack_type": "webshell", "site_id": "portal", "site_name": "Portal test site",
                    })
            return redirect("/")

        @app.post("/failure")
        def failure():
            self._failure = not self._failure
            return redirect("/")

        @app.get("/status")
        def status():
            return jsonify(ready=True)

        @app.get("/api/open/events")
        def events():
            with self._lock:
                return jsonify(list(self._events))

        @app.get("/<device>/ping")
        def ping(device):
            return "ready"

        @app.post("/<device>/<operation>")
        def device_action(device, operation):
            payload = request.get_json(silent=True)
            self._record(f"{device}/{operation}", json.dumps(payload, ensure_ascii=False))
            if device == "device-b" and self._failure:
                return "Simulated device B rejection", 503
            return jsonify(success=True)

        @app.post("/webhook")
        def webhook():
            self._record("webhook", request.get_data(as_text=True))
            return jsonify(success=True)

        self._server = make_server("127.0.0.1", 0, app, threaded=True)
        self.url = f"http://127.0.0.1:{self._server.server_port}"
        self._web_thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._udp_thread = threading.Thread(target=self._collect, daemon=True)

    def _record(self, channel, payload):
        with self._lock:
            self._receipts.append((channel, payload))

    def _collect(self):
        while not self._stop.is_set():
            try:
                data, _ = self._udp.recvfrom(65535)
                self._record("syslog", data.decode("utf-8", errors="replace"))
            except socket.timeout:
                continue
            except OSError:
                break

    def __enter__(self):
        self._web_thread.start()
        self._udp_thread.start()
        return self

    def __exit__(self, *_):
        self._stop.set()
        self._server.shutdown()
        self._server.server_close()
        self._udp.close()
        self._web_thread.join(2)
        self._udp_thread.join(2)
