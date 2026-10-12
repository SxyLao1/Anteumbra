"""Loopback servlet-container protocol simulator for real browser acceptance.

This is deliberately outside Anteumbra: the product writes a temporary JSP,
performs its ordinary HTTP request and validates the response marker.  The
simulator verifies that the requested JSP was actually deployed below the
test-owned web root before it returns the constrained protocol envelope.

It models the HTTP/protocol boundary only.  It does not claim to execute JSP,
enumerate a JVM, or perform Tomcat reflection.
"""

from __future__ import annotations

import base64
import hashlib
import html
import json
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

PROBE_MARKER = "ANTEUMBRA-MEMORY-SHELL-PROBE"
COMPONENT_KIND = "filter"
COMPONENT_NAME = "E2EInjectedFilter"
COMPONENT_CLASS = "lab.memory.E2EInjectedFilter"


class MemoryTarget:
    """A loopback target that exposes a safe, visible probe protocol lab.

    ``root`` is the same temporary website root configured into Anteumbra.  A
    request succeeds only while Anteumbra's short-lived probe file exists there
    and contains both the product marker and its request token.
    """

    def __init__(self, root: Path) -> None:
        self.root = Path(root).resolve()
        self.port = 0
        self.url = ""
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self._component_present = True
        self._next_failure = ""
        self._events: list[dict[str, str]] = []

    def __enter__(self) -> "MemoryTarget":
        return self.start()

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def start(self) -> "MemoryTarget":
        if self._server is not None:
            return self
        if not self.root.is_dir():
            raise RuntimeError(f"memory target root does not exist: {self.root}")

        target = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802 - stdlib handler contract
                target._handle(self)

            def do_POST(self) -> None:  # noqa: N802 - stdlib handler contract
                target._handle(self)

            def log_message(self, _format: str, *_args: object) -> None:
                # Requests are already shown on the public lab page; avoid
                # duplicating test output with an HTTP access log.
                return None

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = int(self._server.server_address[1])
        self.url = f"http://127.0.0.1:{self.port}"
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            name=f"MemoryTarget-{self.port}",
            daemon=True,
        )
        self._thread.start()
        return self

    def close(self) -> None:
        server, self._server = self._server, None
        if server is not None:
            server.shutdown()
            server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=3)
        self._thread = None

    def _handle(self, handler: BaseHTTPRequestHandler) -> None:
        parsed = urlparse(handler.path)
        if parsed.path == "/":
            self._send_html(handler, self._status_page())
            return
        if parsed.path == "/control" and handler.command == "POST":
            length = int(handler.headers.get("Content-Length") or 0)
            form = parse_qs(handler.rfile.read(length).decode("utf-8", "replace"))
            mode = str(form.get("mode", [""])[0])
            if mode not in {"", "probe_error", "dump_error", "kill_error"}:
                self._send_html(handler, "<h1>Unknown lab mode</h1>", HTTPStatus.BAD_REQUEST)
                return
            with self._lock:
                self._next_failure = mode
                self._record("control", mode or "normal")
            handler.send_response(HTTPStatus.SEE_OTHER)
            handler.send_header("Location", "/")
            handler.end_headers()
            return
        self._handle_probe(handler, parsed)

    def _handle_probe(self, handler: BaseHTTPRequestHandler, parsed: Any) -> None:
        params = {key: values[0] for key, values in parse_qs(parsed.query).items()}
        action = params.get("action", "probe")
        try:
            source = self._probe_source(parsed.path, params.get("t", ""))
        except ValueError as exc:
            self._record(action, f"rejected: {exc}")
            self._send_json(handler, {"error": str(exc)}, HTTPStatus.NOT_FOUND)
            return

        with self._lock:
            failure = self._next_failure
            if failure == f"{action}_error":
                self._next_failure = ""
                self._record(action, "configured HTTP 502")
                self._send_json(
                    handler, {"error": "lab configured failure"}, HTTPStatus.BAD_GATEWAY
                )
                return
            self._record(action, self._request_detail(parsed.path, params, len(source)))
            if action == "probe":
                response = self._probe_envelope(action)
            elif action == "dump":
                response = self._dump_envelope(params)
            elif action == "kill":
                response = self._kill_envelope(params)
            else:
                self._send_json(handler, {"error": "unsupported action"}, HTTPStatus.BAD_REQUEST)
                return
        self._send_json(handler, response)

    def _probe_source(self, request_path: str, token: str) -> str:
        relative = Path(unquote(request_path).lstrip("/"))
        if not token or relative.suffix.lower() != ".jsp" or not relative.parts:
            raise ValueError("probe route or token is invalid")
        candidate = (self.root / relative).resolve()
        try:
            candidate.relative_to(self.root)
        except ValueError as exc:
            raise ValueError("probe route escaped the test root") from exc
        if not candidate.is_file() or not candidate.parts[-2].startswith("mb-"):
            raise ValueError("no deployed Anteumbra probe at this route")
        content = candidate.read_text(encoding="utf-8", errors="replace")
        if PROBE_MARKER not in content or token not in content:
            raise ValueError("deployed probe marker or token did not match")
        return content

    def _probe_envelope(self, action: str) -> dict[str, object]:
        entries = [self._entry()] if self._component_present else []
        return self._envelope(action, entries)

    def _dump_envelope(self, params: dict[str, str]) -> dict[str, object]:
        kind, name = params.get("kind", ""), params.get("name", "")
        if (kind, name) != (COMPONENT_KIND, COMPONENT_NAME) or not self._component_present:
            return {**self._envelope("dump", []), "refused": True, "reason": "component_not_found"}
        heap_path = params.get("heap_path", "")
        heap: dict[str, object] | None = None
        if heap_path:
            destination = Path(heap_path)
            # Anteumbra creates this directory before asking the target JVM to
            # write into it.  Keep the lab honest by refusing unexpected paths.
            if not destination.parent.is_dir() or destination.name != "heap.hprof":
                return {
                    **self._envelope("dump", []),
                    "refused": True,
                    "reason": "invalid_heap_path",
                }
            heap_bytes = b"E2E heap evidence is simulated, not a JVM dump.\n"
            destination.write_bytes(heap_bytes)
            heap = {
                "heap_requested": True,
                "heap_path": str(destination),
                "heap_bytes": len(heap_bytes),
                "heap_sha256": hashlib.sha256(heap_bytes).hexdigest(),
                "heap_live": params.get("heap_live") == "1",
                "heap_error": None,
            }
        class_bytes = b"\xca\xfe\xba\xbe\x00\x00\x00\x34E2E-PROTOCOL-ONLY"
        manifest = {
            "kind": COMPONENT_KIND,
            "name": COMPONENT_NAME,
            "urls": ["/*"],
            "class_name": COMPONENT_CLASS,
            "class_loader": "org.apache.catalina.loader.WebappClassLoaderBase",
            "class_loader_identity": "WebappClassLoaderBase@e2e",
            "code_source": None,
            "resource": None,
            "on_disk": False,
            "on_disk_path": None,
            "methods": ["doFilter(ServletRequest,ServletResponse,FilterChain)->void"],
            "fields": ["labMarker:java.lang.String"],
            "protection_domain": "ProtectionDomain (protocol simulator)",
            "container": ["context_class:org.apache.catalina.core.StandardContext"],
            "context_path": "/",
            "probe_url": self.url,
            "jvm_input_arguments": ["protocol-simulator; JVM not executed"],
            "attach_self": "not-applicable",
            "captured_at": int(time.time() * 1000),
        }
        return {
            **self._envelope("dump", [self._entry()]),
            "removed": False,
            "refused": False,
            "reason": None,
            "kind": COMPONENT_KIND,
            "name": COMPONENT_NAME,
            "class_name": COMPONENT_CLASS,
            "manifest": manifest,
            "class_bytes_b64": base64.b64encode(class_bytes).decode("ascii"),
            "class_bytes_len": len(class_bytes),
            "class_bytes_sha256": hashlib.sha256(class_bytes).hexdigest(),
            "class_bytes_source": "protocol_simulator",
            "class_bytes_unavailable_reason": "",
            "heap": heap,
            "heap_error": "",
        }

    def _kill_envelope(self, params: dict[str, str]) -> dict[str, object]:
        kind, name, expected = (
            params.get("kind", ""),
            params.get("name", ""),
            params.get("expect_class", ""),
        )
        if not self._component_present or (kind, name, expected) != (
            COMPONENT_KIND,
            COMPONENT_NAME,
            COMPONENT_CLASS,
        ):
            return {
                **self._envelope("kill", self._entries()),
                "removed": False,
                "refused": True,
                "reason": "component_changed",
            }
        before = {"kind": kind, "name": name, "class_name": expected, "urls": ["/*"]}
        self._component_present = False
        return {
            **self._envelope("kill", []),
            "removed": True,
            "refused": False,
            "reason": None,
            "kind": kind,
            "name": name,
            "expect_class": expected,
            "force": params.get("force") == "1",
            "removal_error": None,
            "still_present": False,
            "before_component": before,
            "after_component": None,
        }

    def _entries(self) -> list[dict[str, object]]:
        return [self._entry()] if self._component_present else []

    def _entry(self) -> dict[str, object]:
        return {
            "type": COMPONENT_KIND,
            "name": COMPONENT_NAME,
            "urls": ["/*"],
            "class": COMPONENT_CLASS,
            "class_loader": "org.apache.catalina.loader.WebappClassLoaderBase",
            "resource": None,
            "code_source": None,
            "suspect": True,
            "reasons": ["class_not_on_disk"],
        }

    def _envelope(self, action: str, entries: list[dict[str, object]]) -> dict[str, object]:
        return {
            "probe": PROBE_MARKER,
            "version": "1.1.0",
            "action": action,
            "context_path": "/",
            "container": ["Anteumbra protocol simulator (no JVM)"],
            "error": None,
            "entry_count": len(entries),
            "duration_ms": 1,
            "entries": entries,
        }

    def _record(self, action: str, detail: str) -> None:
        self._events.insert(
            0,
            {"at": time.strftime("%H:%M:%S", time.localtime()), "action": action, "detail": detail},
        )
        del self._events[20:]

    @staticmethod
    def _request_detail(request_path: str, params: dict[str, str], source_bytes: int) -> str:
        """Expose the component identity on the lab page for browser diagnosis."""
        component = (
            ":".join(value for value in (params.get("kind", ""), params.get("name", "")) if value)
            or "site probe"
        )
        expected = params.get("expect_class", "")
        suffix = f"; expect={expected}" if expected else ""
        return f"{Path(request_path).name}; {component}{suffix}; {source_bytes} bytes"

    def _status_page(self) -> str:
        with self._lock:
            rows = (
                "".join(
                    f"<tr><td>{html.escape(event['at'])}</td><td>{html.escape(event['action'])}</td><td>{html.escape(event['detail'])}</td></tr>"
                    for event in self._events
                )
                or "<tr><td colspan='3'>No product request received.</td></tr>"
            )
            pending = self._next_failure or "normal"
        return f"""<!doctype html><html><head><title>Memory target protocol lab</title></head><body>
<h1>Memory target protocol lab</h1>
<p>Protocol-only servlet target simulator. It does not execute JSP or a JVM.</p>
<p>Next response mode: <strong>{html.escape(pending)}</strong></p>
<form method='post' action='/control'>
  <button name='mode' value=''>Normal responses</button>
  <button name='mode' value='probe_error'>Fail next probe</button>
  <button name='mode' value='dump_error'>Fail next forensics</button>
  <button name='mode' value='kill_error'>Fail next remediation</button>
</form>
<h2>Product request replay</h2><table border='1'><thead><tr><th>Time</th><th>Action</th><th>Detail</th></tr></thead><tbody>{rows}</tbody></table>
</body></html>"""

    @staticmethod
    def _send_json(
        handler: BaseHTTPRequestHandler,
        payload: dict[str, object],
        status: HTTPStatus = HTTPStatus.OK,
    ) -> None:
        data = json.dumps(payload).encode("utf-8")
        handler.send_response(status)
        handler.send_header("Content-Type", "application/json; charset=utf-8")
        handler.send_header("Content-Length", str(len(data)))
        handler.end_headers()
        handler.wfile.write(data)

    @staticmethod
    def _send_html(
        handler: BaseHTTPRequestHandler, body: str, status: HTTPStatus = HTTPStatus.OK
    ) -> None:
        data = body.encode("utf-8")
        handler.send_response(status)
        handler.send_header("Content-Type", "text/html; charset=utf-8")
        handler.send_header("Content-Length", str(len(data)))
        handler.end_headers()
        handler.wfile.write(data)
