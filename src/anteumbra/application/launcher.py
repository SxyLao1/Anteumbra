# -*- coding: utf-8 -*-
"""
Anteumbra 全系统启动器 — 从 run.py 抽入包内，使 CLI 和 run.py 共享同一启动逻辑。

v1.0.10: 从 cli/main.py:run() 和 run.py:main() 的重复代码中提取。
"""

import json
import os
import sys
import time
import threading
from pathlib import Path


def start_all(host: str = "127.0.0.1", port: int = 8080) -> None:
    """
    启动全部 Anteumbra 子系统（阻塞，Ctrl+C 停止）。

    子系统启动顺序:
    1. Flask web server (后台线程)
    2. File monitor (watchdog)
    3. Log monitor
    4. WAF poller
    5. ThreatGraph profile engine
    6. Plugin system
    7. SSE worker
    8. Metrics / SIEM
    """
    from anteumbra.infrastructure.config.registry import ConfigRegistry
    from anteumbra.infrastructure.utils.path_utils import normalize_path
    from anteumbra.infrastructure.config.version import get_version

    # ── PID 文件 ──────────────────────────────────────
    pid_dir = Path("data")
    pid_dir.mkdir(parents=True, exist_ok=True)
    (pid_dir / "anteumbra.pid").write_text(str(os.getpid()))

    # ── 配置 ──────────────────────────────────────────
    ConfigRegistry.initialize()
    websites = ConfigRegistry.get_enabled_websites()
    if not websites:
        print("[FATAL] No enabled websites in config.toml")
        return
    website = websites[0]
    website.path = normalize_path(website.path)

    api_cfg = ConfigRegistry.get_raw_config().get("api", {})
    host = api_cfg.get("health_check_host", host)
    port = api_cfg.get("health_check_port", port)

    print(f"Anteumbra v{get_version()} — Web Perimeter Security")
    print(f"  Website: {website.name}")
    print(f"  Watch:   {website.path}")
    print(f"  Admin:   http://{host}:{port}/admin")
    print(f"  Health:  http://{host}:{port}/api/v1/health")
    print("-" * 50)

    # ── Flask ──────────────────────────────────────────
    from anteumbra.interfaces.web.factory import create_app, run_app
    app = create_app()
    app.config.setdefault('SESSION_COOKIE_SECURE', False)
    app.config.setdefault('SESSION_COOKIE_HTTPONLY', True)
    app.config.setdefault('SESSION_COOKIE_SAMESITE', 'Lax')
    threading.Thread(target=run_app, kwargs={"host": host, "port": port},
                     daemon=True, name="FlaskServer").start()
    print("[OK] Flask started")

    # ── File Monitor ───────────────────────────────────
    from anteumbra.infrastructure.monitoring.monitor import WebsiteMonitor
    from anteumbra.infrastructure.detection.scanner import quick_scan_yara
    from anteumbra.infrastructure.utils.logger_factory import get_logger
    monitor_logger = get_logger(website.name)
    scan_callback = quick_scan_yara
    monitor = WebsiteMonitor(website, scan_callback, monitor_logger)
    monitor.start()
    print(f"[OK] File monitor watching: {website.path}")

    # ── Log Monitor ────────────────────────────────────
    try:
        from anteumbra.infrastructure.monitoring.log_monitor import LogMonitor
        from anteumbra.infrastructure.monitoring.log_analyzer import get_analyzer
        analyzer = get_analyzer(website, monitor_logger)
        log_monitor = LogMonitor(monitor_logger, analyzer)
        log_monitor.start()
        print("[OK] Log monitor started")
    except Exception as e:
        print(f"[WARN] Log monitor: {e}")

    # ── WAF Poller ─────────────────────────────────────
    try:
        from anteumbra.infrastructure.waf_client import get_waf_poller
        waf_poller = get_waf_poller()
        if waf_poller:
            waf_poller.start()
            print(f"[OK] WAF poller: {waf_poller.source.get_name()}")
    except Exception as e:
        print(f"[WARN] WAF poller: {e}")

    # ── Profile Engine ─────────────────────────────────
    from anteumbra.infrastructure.threat_graph import get_threat_graph
    threat_graph = get_threat_graph()
    print("[OK] ThreatGraph initialized")

    def _profile_consumer():
        cache_path = normalize_path("data/waf_events.jsonl")
        last_pos = 0
        while True:
            try:
                if cache_path.exists():
                    with open(str(cache_path), 'r', encoding='utf-8') as f:
                        f.seek(last_pos)
                        for line in f:
                            if line.strip():
                                evt = json.loads(line)
                                threat_graph.ingest_waf_event(evt)
                        last_pos = f.tell()
            except Exception:
                pass
            time.sleep(5)

    threading.Thread(target=_profile_consumer, daemon=True, name="ProfileConsumer").start()
    print("[OK] Profile consumer started")

    def _profile_persist():
        while True:
            time.sleep(300)
            try:
                threat_graph.merge_overlapping_profiles(min_overlap=3)
                threat_graph.decay_profiles()
                threat_graph.persist()
            except Exception:
                pass
    threading.Thread(target=_profile_persist, daemon=True, name="ProfilePersist").start()

    # ── Plugin System ──────────────────────────────────
    try:
        from anteumbra.application.plugin_manager import init_plugins
        pm = init_plugins(ConfigRegistry.get_raw_config())
        if pm.is_enabled:
            plugins = pm.list_all()
            print(f"[OK] Plugins: {len(plugins)} loaded ({', '.join(p['name'] for p in plugins)})")
    except Exception as e:
        print(f"[WARN] Plugins: {e}")

    # ── SSE Worker ─────────────────────────────────────
    try:
        from anteumbra.infrastructure.utils.sse_manager import start_sse_worker
        start_sse_worker()
    except Exception as e:
        print(f"[WARN] SSE: {e}")

    # ── Metrics ────────────────────────────────────────
    try:
        from anteumbra.infrastructure.monitoring.metrics import get_metrics, preload_metrics
        preload_metrics()
        get_metrics().load_persisted()
    except Exception as e:
        print(f"[WARN] Metrics: {e}")

    # ── SIEM ───────────────────────────────────────────
    try:
        from anteumbra.infrastructure.monitoring.siem_exporter import get_siem_exporter
        siem = get_siem_exporter()
        if siem.enabled:
            print(f"[OK] SIEM export: {siem._format} -> {siem._export_path}")
    except Exception as e:
        print(f"[WARN] SIEM: {e}")

    print("=" * 50)
    print("  ALL SYSTEMS OPERATIONAL")
    print(f"  Dashboard: http://{host}:{port}/admin")
    print(f"  Health:    http://{host}:{port}/api/v1/health")
    print("=" * 50)

    # 持有的引用，供 stop() 使用
    _launcher_state["monitor"] = monitor
    _launcher_state["log_monitor"] = log_monitor

    # 保持主线程存活
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nShutting down...")
        stop_all()


# 模块级状态
_launcher_state: dict = {}


def stop_all() -> None:
    """优雅关闭所有子系统。"""
    monitor = _launcher_state.get("monitor")
    log_monitor = _launcher_state.get("log_monitor")

    if monitor:
        try:
            monitor.stop()
        except Exception:
            pass
    if log_monitor:
        try:
            log_monitor.stop()
        except Exception:
            pass

    print("Anteumbra stopped.")
    sys.exit(0)
