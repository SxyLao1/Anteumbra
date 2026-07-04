# Anteumbra Gunicorn Production Configuration
# Usage: gunicorn -c gunicorn.conf.py "web.factory:create_app()"
#
# Workers: 2-4 x $(nproc) is a good default.
# For CPU-bound YARA scanning, use fewer workers with threads.

import multiprocessing
import os

# ── Server Socket ───────────────────────────────────────

bind = os.environ.get("ANTEUMBRA_BIND", "127.0.0.1:8080")
backlog = 2048

# ── Worker Processes ────────────────────────────────────

workers = int(os.environ.get("ANTEUMBRA_WORKERS", min(4, multiprocessing.cpu_count() * 2)))
threads = int(os.environ.get("ANTEUMBRA_THREADS", 2))
worker_class = "sync"  # sync workers + threads for I/O-bound YARA scans
worker_connections = 1000
timeout = 120  # YARA scanning can take a while
graceful_timeout = 30
keepalive = 5

# ── Process Naming ──────────────────────────────────────

proc_name = "anteumbra"
default_proc_name = "anteumbra"

# ── Logging ─────────────────────────────────────────────

accesslog = os.environ.get("ANTEUMBRA_ACCESS_LOG", "logs/Anteumbra/gunicorn_access.log")
errorlog = os.environ.get("ANTEUMBRA_ERROR_LOG", "logs/Anteumbra/gunicorn_error.log")
loglevel = os.environ.get("ANTEUMBRA_LOG_LEVEL", "info")
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(L)s'

# ── Server Mechanics ────────────────────────────────────

daemon = False
pidfile = None
umask = 0o022
user = None
group = None
tmp_upload_dir = None

# ── Hooks ───────────────────────────────────────────────

def on_starting(server):
    """Initialize Anteumbra subsystems before workers fork."""
    import sys
    sys.path.insert(0, os.path.dirname(__file__))
    from config.registry import ConfigRegistry
    ConfigRegistry.initialize()

def when_ready(server):
    server.log.info("Anteumbra: Gunicorn ready — %d workers, %d threads", workers, threads)

def on_exit(server):
    server.log.info("Anteumbra: Gunicorn shutting down")
