"""Launch a disposable console and protocol lab for manual browser review.

Run this file from the repository with the same interpreter as the UI suite.
All integrations stay on loopback. Creating the printed stop file shuts down
the child runtime and removes the owned temporary deployment.
"""

from __future__ import annotations

import argparse
import json
import secrets
import tempfile
import time
from contextlib import ExitStack
from pathlib import Path

from memory_target import MemoryTarget
from receivers import ExternalLab
from support import free_port, start_runtime, stop_runtime, write_instance
from werkzeug.security import generate_password_hash


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--hours", type=float, default=4)
    args = parser.parse_args()
    artifacts = args.artifacts.resolve()
    artifacts.mkdir(parents=True, exist_ok=True)
    stop_file = artifacts / "stop-preview"
    if stop_file.exists():
        parser.error(f"Choose a fresh artifact directory; stop file exists: {stop_file}")
    with tempfile.TemporaryDirectory(prefix="anteumbra-review-") as temporary, ExitStack() as stack:
        root = Path(temporary)
        portal, shop = root / "sites" / "portal", root / "sites" / "shop"
        portal.mkdir(parents=True)
        shop.mkdir(parents=True)
        lab = stack.enter_context(ExternalLab())
        targets = [stack.enter_context(MemoryTarget(path)) for path in (portal, shop)]
        port = args.port or free_port()
        password = secrets.token_urlsafe(18)
        write_instance(root, generate_password_hash(password), port, lab, [t.port for t in targets])
        process, stream = start_runtime(root, port, artifacts)
        stack.callback(stop_runtime, process, stream)
        details = {
            "console": f"http://127.0.0.1:{port}/admin/",
            "username": "admin",
            "password": password,
            "external_lab": lab.url,
            "memory_targets": [target.url for target in targets],
            "website_roots": [str(portal), str(shop)],
            "stop_file": str(stop_file),
            "expires_after_hours": args.hours,
        }
        (artifacts / "preview.json").write_text(json.dumps(details, indent=2), encoding="utf-8")
        print(json.dumps(details, indent=2), flush=True)
        deadline = time.monotonic() + args.hours * 3600
        try:
            while process.poll() is None and not stop_file.exists() and time.monotonic() < deadline:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
    print("Preview stopped; disposable deployment removed.", flush=True)


if __name__ == "__main__":
    main()
