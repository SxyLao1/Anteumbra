# -*- coding: utf-8 -*-
"""
@Time: 1/16/2026 5:43 PM
@Auth: SxyLao1
@File: sse_manager.py
@IDE: PyCharm
@Motto: HACK THE REAL
v1.7.5: 独立SSE推送管理器（解决循环导入和命名空间隔离）
"""
import logging
import queue
import threading
import time
import json
from pathlib import Path
from collections import deque
from typing import List
from anteumbra.infrastructure.config.registry import ConfigRegistry

# 模块级全局变量
_registry_update_queue = queue.Queue(maxsize=0)
_sse_clients: List[queue.Queue] = []
_sse_lock = threading.Lock()
_worker_thread = None
_worker_lock = threading.Lock()
_worker_stop_event = threading.Event()
_worker_stop_signal = object()

def get_sse_limits():
    """从config.toml动态读取SSE连接限制（支持热加载）"""
    try:
        config = ConfigRegistry.get_raw_config()
        web_admin_cfg = config.get("web_admin", {})
        return {
            'per_ip': web_admin_cfg.get("sse_max_clients_per_ip", 5),
            'total': web_admin_cfg.get("sse_max_total_clients", 20)
        }
    except Exception as e:
        logging.getLogger("monitor.sse_worker").warning(
            f"[SSE] 读取配置失败，使用默认值: {e}"
        )
        return {'per_ip': 5, 'total': 20}  # 安全默认值

def start_sse_worker():
    """启动SSE推送工作线程（全局单例）"""
    global _worker_thread

    def _worker():
        logger = logging.getLogger("monitor.sse_worker")
        logger.info("[SSE][WORKER] Registry推送工作线程已启动")

        while not _worker_stop_event.is_set():
            try:
                signal = _registry_update_queue.get(timeout=0.5)
                if signal is _worker_stop_signal:
                    break
                if signal == "registry_update":
                    # 动态读取限制（支持配置热更新）
                    limits = get_sse_limits()
                    with _sse_lock:
                        clients_snapshot = list(_sse_clients)
                    logger.debug(
                        f"[SSE] 广播Registry更新给 {len(clients_snapshot)}/{limits['total']} 个客户端"
                    )

                    dead_clients = []
                    for client_queue in clients_snapshot:
                        try:
                            client_queue.put_nowait("registry_update")
                        except queue.Full:
                            dead_clients.append(client_queue)
                        except Exception:
                            dead_clients.append(client_queue)

                    if dead_clients:
                        with _sse_lock:
                            for dead in dead_clients:
                                if dead in _sse_clients:
                                    _sse_clients.remove(dead)

            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"[SSE][WORKER] 错误: {e}", exc_info=True)

    with _worker_lock:
        if _worker_thread is not None and _worker_thread.is_alive():
            return
        _worker_stop_event.clear()
        _worker_thread = threading.Thread(
            target=_worker,
            daemon=True,
            name="RegistrySSEWorker",
        )
        _worker_thread.start()


def stop_sse_worker(timeout: float = 2.0) -> bool:
    """Stop the SSE worker and disconnect registered clients."""
    global _worker_thread

    with _worker_lock:
        thread = _worker_thread
        if thread is None:
            cleanup_sse_connections()
            return True
        _worker_stop_event.set()
        _registry_update_queue.put_nowait(_worker_stop_signal)

    if thread is not threading.current_thread():
        thread.join(timeout=timeout)
    stopped = not thread.is_alive()
    cleanup_sse_connections()

    with _worker_lock:
        if _worker_thread is thread and stopped:
            _worker_thread = None
    return stopped


def is_sse_worker_running() -> bool:
    """Return whether the singleton worker thread is alive."""
    with _worker_lock:
        return bool(_worker_thread and _worker_thread.is_alive())


def register_sse_client() -> queue.Queue:
    """注册新的SSE客户端，返回专属队列"""
    client_queue = queue.Queue(maxsize=100)
    with _sse_lock:
        _sse_clients.append(client_queue)
        current_total = len(_sse_clients)

    limits = get_sse_limits()
    logger = logging.getLogger("monitor.sse_worker")
    logger.info(
        f"[SSE] 新客户端注册，当前总数: {current_total}/{limits['total']}"
    )

    return client_queue


def unregister_sse_client(client_queue: queue.Queue):
    """注销SSE客户端"""
    with _sse_lock:
        if client_queue in _sse_clients:
            _sse_clients.remove(client_queue)
    # 清理队列内容（无需锁 — 队列已经不在全局列表中了）
    try:
        while True:
            client_queue.get_nowait()
    except queue.Empty:
        pass

def cleanup_sse_connections(client_ip: str = None):
    """强制清理指定IP的所有SSE连接（确保计数同步）"""
    cleaned = 0

    # 创建副本避免遍历时修改（锁快照）
    with _sse_lock:
        clients_snapshot = list(_sse_clients)

    for client_queue in clients_snapshot:
        if client_ip is None or getattr(client_queue, '_client_ip', None) == client_ip:
            try:
                # 强制关闭队列
                client_queue.put_nowait(None)  # 发送退出信号
                unregister_sse_client(client_queue)
                cleaned += 1
            except Exception as e:
                logging.getLogger("monitor.sse_worker").debug(f"清理连接失败: {e}")

    logging.getLogger("monitor.sse_worker").info(
        f"[SSE] 强制清理了 {cleaned} 个连接 (IP: {client_ip or 'ALL'})"
    )

def trigger_registry_update():
    """触发Registry更新"""
    try:
        _registry_update_queue.put_nowait("registry_update")
    except queue.Full:
        pass


def get_connected_client_count() -> int:
    """获取当前连接的SSE客户端数量（线程安全）"""
    limits = get_sse_limits()
    with _sse_lock:
        current = len(_sse_clients)
    logger = logging.getLogger("monitor.sse_worker")
    logger.debug(f"[SSE] 当前连接: {current}/{limits['total']}")
    return current


def get_ip_client_count(client_ip: str) -> int:
    """获取指定IP的SSE客户端数量（线程安全）"""
    with _sse_lock:
        return sum(1 for q in _sse_clients if getattr(q, '_client_ip', None) == client_ip)


def get_ip_clients(client_ip: str) -> list:
    """获取指定IP的所有SSE客户端队列（线程安全，返回副本）"""
    with _sse_lock:
        return [q for q in _sse_clients if getattr(q, '_client_ip', None) == client_ip]


def remove_dead_clients(dead_queues: list) -> int:
    """批量移除已断开的SSE客户端（线程安全）"""
    with _sse_lock:
        removed = 0
        for q in dead_queues:
            if q in _sse_clients:
                _sse_clients.remove(q)
                removed += 1
    return removed

class LogBuffer:
    def __init__(self, max_size=100, buffer_path="data/sse_log_buffer.json"):
        self.max_size = max_size
        self.buffer_path = Path(buffer_path)
        self.buffer_path.parent.mkdir(parents=True, exist_ok=True)
        self._queue = deque(maxlen=max_size)
        self._lock = threading.Lock()
        self._load()

    def _load(self):
        """从磁盘加载缓冲"""
        if self.buffer_path.exists():
            try:
                data = json.loads(self.buffer_path.read_text(encoding='utf-8'))
                with self._lock:
                    self._queue.extend(data)
            except Exception:
                logger = logging.getLogger("monitor.sse_worker")
                logger.warning("LogBuffer load failed, starting empty")
                with self._lock:
                    self._queue.clear()

    def _save(self):
        """保存到磁盘"""
        try:
            with self._lock:
                data = list(self._queue)
            self.buffer_path.write_text(
                json.dumps(data, indent=2),
                encoding='utf-8'
            )
        except Exception:
            logger = logging.getLogger("monitor.sse_worker")
            logger.warning("LogBuffer save failed")

    def push(self, log_line):
        """
        添加日志到缓冲区，避免重复写入

        Args:
            log_line: 日志内容字符串

        Returns:
            bool: 是否成功添加（False表示已存在，跳过写入）
        """
        with self._lock:
            if log_line in self._queue:
                return False
            self._queue.append(log_line)
        self._save()
        return True

    def get_all(self):
        """获取所有缓冲的日志（线程安全）"""
        with self._lock:
            return list(self._queue)

# 全局实例
_log_buffer = LogBuffer(max_size=100)

def persist_log_line(log_line):
    """供admin_bp.py调用，持久化日志"""
    return _log_buffer.push(log_line)  # 返回bool，便于调用方知道是否写入成功

def get_log_buffer():
    """获取缓冲的日志"""
    return _log_buffer.get_all()
