"""Lifecycle, validation, and retry tests for the runtime-owned IP blocker."""

import json
import time

import pytest

from anteumbra.domain.blocking import BlockDecision, BlockResult
from anteumbra.domain.site import SiteIdentity
from anteumbra.infrastructure.ip_blocker import (
    BlockDevice,
    IPBlocker,
    IPBlockerDisabledError,
    MockDevice,
)


class CountingDevice(BlockDevice):
    def __init__(self, name, *, failures=0):
        self._name = name
        self.failures = failures
        self.block_calls = 0
        self.unblock_calls = 0

    @property
    def name(self):
        return self._name

    def block(self, decision: BlockDecision):
        self.block_calls += 1
        success = self.block_calls > self.failures
        return BlockResult(self.name, success, "ok" if success else "offline", decision.ip)

    def unblock(self, ip):
        self.unblock_calls += 1
        return BlockResult(self.name, True, "ok", ip)

    def is_available(self):
        return True


@pytest.fixture
def site():
    return SiteIdentity("alpha", "Alpha")


def test_disabled_blocker_rejects_operations(tmp_path, site):
    blocker = IPBlocker(enabled=False, retry_path=tmp_path / "retry.json")

    with pytest.raises(IPBlockerDisabledError, match="disabled"):
        blocker.block(["10.0.0.1"], reason="test", site=site)


def test_block_and_unblock_validate_and_deduplicate_ips(tmp_path, site):
    device = MockDevice("waf")
    blocker = IPBlocker([device], retry_path=tmp_path / "retry.json")

    results = blocker.block(
        ["10.0.0.1", "10.0.0.1"],
        reason="test",
        site=site,
    )

    assert len(results) == 1
    assert device.is_blocked("10.0.0.1")
    assert blocker.unblock(["10.0.0.1"])[0].success
    assert not device.is_blocked("10.0.0.1")


def test_invalid_ip_has_no_device_side_effect(tmp_path, site):
    device = CountingDevice("waf")
    blocker = IPBlocker([device], retry_path=tmp_path / "retry.json")

    with pytest.raises(ValueError, match="invalid IP"):
        blocker.block(["not-an-ip"], reason="test", site=site)

    assert device.block_calls == 0


def test_selected_devices_are_validated(tmp_path, site):
    blocker = IPBlocker([MockDevice("waf")], retry_path=tmp_path / "retry.json")

    with pytest.raises(ValueError, match="unknown blocking devices"):
        blocker.block(
            ["10.0.0.2"],
            reason="test",
            site=site,
            device_names=["missing"],
        )


def test_retry_targets_only_failed_devices_and_stops_cleanly(tmp_path, site):
    healthy = CountingDevice("healthy")
    transient = CountingDevice("transient", failures=1)
    blocker = IPBlocker(
        [healthy, transient],
        retry_path=tmp_path / "retry.json",
        retry_interval=0.02,
        max_retry_attempts=3,
    )

    blocker.block(["10.0.0.3"], reason="test", site=site)
    blocker.start()
    deadline = time.monotonic() + 2
    while blocker.get_retry_queue_status()["pending"] and time.monotonic() < deadline:
        time.sleep(0.02)
    blocker.stop()

    assert healthy.block_calls == 1
    assert transient.block_calls == 2
    assert blocker.get_retry_queue_status()["pending"] == 0
    assert not blocker.is_running


def test_retry_queue_round_trip_preserves_site_and_device(tmp_path, site):
    retry_path = tmp_path / "retry.json"
    failing = CountingDevice("waf", failures=99)
    first = IPBlocker(
        [failing],
        retry_path=retry_path,
        retry_interval=60,
    )
    first.block(["10.0.0.4"], reason="persist", site=site)
    first.stop()

    restored = IPBlocker(
        [CountingDevice("waf", failures=99)],
        retry_path=retry_path,
        retry_interval=60,
    )
    restored.start()
    status = restored.get_retry_queue_status()
    restored.stop()

    assert status["pending"] == 1
    assert status["items"][0]["site_id"] == "alpha"
    assert status["items"][0]["devices"] == ["waf"]


def test_retry_item_for_removed_device_is_not_a_poison_loop(tmp_path, site):
    retry_path = tmp_path / "retry.json"
    retry_path.write_text(
        json.dumps(
            [
                {
                    "ip": "10.0.0.5",
                    **site.as_dict(),
                    "reason": "stale device",
                    "pending_devices": ["removed-waf"],
                    "attempts": 1,
                    "max_attempts": 5,
                    "next_retry_at": 0,
                }
            ]
        ),
        encoding="utf-8",
    )
    blocker = IPBlocker(
        [CountingDevice("current-waf")],
        retry_path=retry_path,
        retry_interval=0.02,
    )

    blocker.start()
    deadline = time.monotonic() + 1
    while blocker.get_retry_queue_status()["pending"] and time.monotonic() < deadline:
        time.sleep(0.02)
    blocker.stop()

    assert blocker.get_retry_queue_status()["pending"] == 0
    assert json.loads(retry_path.read_text(encoding="utf-8")) == []


def test_from_config_builds_explicit_device_inventory(tmp_path):
    blocker = IPBlocker.from_config(
        {
            "enabled": True,
            "auto_block_enabled": True,
            "auto_block_min_score": 0.9,
            "devices": [{"name": "test-waf", "type": "mock"}],
        },
        retry_path=tmp_path / "retry.json",
    )

    assert blocker.enabled
    assert blocker.auto_block_enabled
    assert blocker.auto_block_min_score == 0.9
    assert blocker.device_names == ("test-waf",)
    assert blocker.device_status() == [{"name": "test-waf", "available": True}]
