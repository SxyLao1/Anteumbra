"""Runtime-owned WAF poller tests."""

from __future__ import annotations

import copy
from datetime import datetime, timezone

from anteumbra.domain import WAFEvent, WAFEventSource
from anteumbra.infrastructure.waf_client import WAFPoller, build_waf_poller


class Provider:
    def __init__(self, settings):
        self.settings = settings

    def get(self):
        return copy.deepcopy(self.settings)


class Source(WAFEventSource):
    def __init__(self, events=()):
        self.base_url = "http://old"
        self.events = list(events)
        self.windows = []

    def get_name(self):
        return "test"

    def is_available(self):
        return True

    def pull_events(self, start_time, end_time):
        self.windows.append((start_time, end_time))
        return list(self.events)


def _event(event_id="event-1"):
    return WAFEvent(
        event_id=event_id,
        src_ip="192.0.2.10",
        timestamp="2026-07-19T01:00:00+00:00",
        http_method="POST",
        url="/upload.php",
        user_agent="test",
        waf_rule_id="upload",
        waf_score=90,
        attack_type="webshell",
    )


def _provider(enabled=True):
    return Provider(
        {
            "waf_source": {
                "enabled": enabled,
                "type": "mock",
                "url": "http://new",
                "poll_interval": 0.05,
            }
        }
    )


def test_disabled_factory_returns_no_runtime_resource(tmp_path):
    assert build_waf_poller(_provider(enabled=False), tmp_path / "waf.jsonl") is None


def test_two_pollers_do_not_share_cache_or_lifecycle(tmp_path):
    first = WAFPoller(Source(), _provider(), tmp_path / "first.jsonl")
    second = WAFPoller(Source(), _provider(), tmp_path / "second.jsonl")

    first.start()
    first.stop()

    assert first.is_running is False
    assert second.is_running is False
    assert first._cache_path != second._cache_path


def test_poll_once_hot_reloads_url_and_deduplicates_events(tmp_path):
    source = Source([_event(), _event()])
    poller = WAFPoller(source, _provider(), tmp_path / "waf.jsonl")
    now = datetime(2026, 7, 19, 2, 0, tzinfo=timezone.utc)

    first_count = poller.poll_once(now)
    second_count = poller.poll_once(now)

    assert first_count == 1
    assert second_count == 0
    assert source.base_url == "http://new"
    assert poller.get_cached_events() == [
        {
            "event_id": "event-1",
            "src_ip": "192.0.2.10",
            "timestamp": "2026-07-19T01:00:00+00:00",
            "http_method": "POST",
            "url": "/upload.php",
            "user_agent": "test",
            "waf_rule_id": "upload",
            "waf_score": 90,
            "attack_type": "webshell",
        }
    ]
    assert source.windows[1][0] == now


def test_checkpoint_prevents_duplicates_after_reconstruction(tmp_path):
    cache_path = tmp_path / "waf.jsonl"
    first = WAFPoller(Source([_event()]), _provider(), cache_path)
    assert first.poll_once() == 1

    second = WAFPoller(Source([_event()]), _provider(), cache_path)
    second._load_checkpoint()

    assert second.poll_once() == 0
    assert len(second.get_cached_events()) == 1


def test_cached_event_reader_skips_malformed_lines(tmp_path):
    cache_path = tmp_path / "waf.jsonl"
    cache_path.write_text('{"event_id":"ok"}\n{broken\n', encoding="utf-8")
    poller = WAFPoller(Source(), _provider(), cache_path)

    assert poller.get_cached_events() == [{"event_id": "ok"}]


def test_stop_interrupts_long_poll_interval(tmp_path):
    provider = _provider()
    provider.settings["waf_source"]["poll_interval"] = 60
    poller = WAFPoller(Source(), provider, tmp_path / "waf.jsonl")

    poller.start()
    poller.stop(timeout=1)

    assert poller.is_running is False
