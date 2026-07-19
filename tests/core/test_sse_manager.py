"""Unit tests for the runtime-owned SSE manager."""

from __future__ import annotations

import pytest

from anteumbra.infrastructure.utils.sse_manager import SSECapacityError, SSEManager


class ConfigStub:
    def __init__(self, *, per_ip=5, total=20):
        self.web_admin = {
            "sse_max_clients_per_ip": per_ip,
            "sse_max_total_clients": total,
        }

    def get(self):
        return {"web_admin": dict(self.web_admin)}


@pytest.fixture
def manager(tmp_path):
    return SSEManager(ConfigStub(), tmp_path / "sse_history.json")


def test_start_is_idempotent_and_stop_disconnects_clients(manager):
    manager.start()
    first_worker = manager.worker
    manager.start()
    client = manager.register_client("127.0.0.1")

    assert manager.is_running is True
    assert manager.worker is first_worker
    assert manager.connected_client_count() == 1
    assert manager.stop() is True
    assert manager.is_running is False
    assert manager.connected_client_count() == 0
    assert client.get_nowait() is None


def test_registry_update_reaches_registered_client(manager):
    client = manager.register_client("127.0.0.1")
    manager.start()
    try:
        assert manager.trigger_registry_update() is True
        assert client.get(timeout=1.0) == "registry_update"
    finally:
        manager.stop()


def test_update_queue_coalesces_bursts_before_worker_starts(manager):
    assert manager.trigger_registry_update() is True
    assert manager.trigger_registry_update() is False


def test_cleanup_leaves_disconnect_sentinel(manager):
    first = manager.register_client("10.0.0.1")
    second = manager.register_client("10.0.0.2")

    assert manager.cleanup_connections("10.0.0.1") == 1
    assert first.get_nowait() is None
    assert manager.connected_client_count() == 1
    assert second.empty()


def test_two_instances_never_share_clients_or_history(tmp_path):
    config = ConfigStub()
    first = SSEManager(config, tmp_path / "first.json")
    second = SSEManager(config, tmp_path / "second.json")

    first.register_client("127.0.0.1")
    first.persist_log_line("first runtime")

    assert first.connected_client_count() == 1
    assert second.connected_client_count() == 0
    assert first.get_log_buffer() == ["first runtime"]
    assert second.get_log_buffer() == []


def test_limits_are_hot_reloaded_and_enforced(tmp_path):
    config = ConfigStub(per_ip=1, total=2)
    manager = SSEManager(config, tmp_path / "history.json")
    manager.register_client("10.0.0.1")

    with pytest.raises(SSECapacityError, match="IP 10.0.0.1"):
        manager.register_client("10.0.0.1")

    config.web_admin["sse_max_clients_per_ip"] = 2
    manager.register_client("10.0.0.1")
    with pytest.raises(SSECapacityError, match="total client"):
        manager.register_client("10.0.0.2")


def test_persisted_history_survives_new_manager_instance(tmp_path):
    path = tmp_path / "history.json"
    first = SSEManager(ConfigStub(), path)
    assert first.persist_log_line("line one") is True
    assert first.persist_log_line("line one") is False
    assert first.persist_log_line("line two") is True

    second = SSEManager(ConfigStub(), path)

    assert second.get_log_buffer() == ["line one", "line two"]


def test_corrupt_history_is_preserved_and_does_not_break_startup(tmp_path):
    path = tmp_path / "history.json"
    path.write_text("not-json", encoding="utf-8")

    manager = SSEManager(ConfigStub(), path)

    assert manager.get_log_buffer() == []
    assert path.with_name("history.json.corrupt").read_text(encoding="utf-8") == "not-json"


def test_stalled_client_is_removed_from_fanout(manager):
    client = manager.register_client("127.0.0.1")
    for _ in range(client.maxsize):
        client.put_nowait("occupied")
    manager.start()
    try:
        manager.trigger_registry_update()
        for _ in range(20):
            if manager.connected_client_count() == 0:
                break
            __import__("time").sleep(0.01)
        assert manager.connected_client_count() == 0
    finally:
        manager.stop()
