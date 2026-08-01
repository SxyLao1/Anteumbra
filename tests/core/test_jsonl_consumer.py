"""Reliable JSONL tailing regression tests."""

import json
import logging

from anteumbra.application.jsonl_consumer import JsonlEventTailer


def _tailer(tmp_path, handler):
    source = tmp_path / "events.jsonl"
    dead_letter = tmp_path / "events.deadletter.jsonl"
    return (
        source,
        dead_letter,
        JsonlEventTailer(
            source,
            handler,
            logger=logging.getLogger("test.jsonl"),
            dead_letter_path=dead_letter,
        ),
    )


def test_consumes_complete_events_exactly_once_per_process(tmp_path):
    seen = []
    source, _, tailer = _tailer(tmp_path, seen.append)
    source.write_text('{"id": 1}\n{"id": 2}\n', encoding="utf-8")

    assert tailer.poll() == 2
    assert tailer.poll() == 0
    assert seen == [{"id": 1}, {"id": 2}]


def test_poison_message_is_dead_lettered_and_cursor_advances(tmp_path):
    seen = []
    source, dead_letter, tailer = _tailer(tmp_path, seen.append)
    source.write_text('not-json\n{"id": 2}\n', encoding="utf-8")

    assert tailer.poll() == 2
    assert tailer.poll() == 0
    assert seen == [{"id": 2}]

    rejected = [json.loads(line) for line in dead_letter.read_text(encoding="utf-8").splitlines()]
    assert len(rejected) == 1
    assert rejected[0]["offset"] == 0
    assert rejected[0]["raw"] == "not-json"


def test_handler_failure_does_not_block_following_events(tmp_path):
    seen = []

    def handler(event):
        if event["id"] == 1:
            raise RuntimeError("rejected by graph")
        seen.append(event)

    source, dead_letter, tailer = _tailer(tmp_path, handler)
    source.write_text('{"id": 1}\n{"id": 2}\n', encoding="utf-8")

    assert tailer.poll() == 2
    assert seen == [{"id": 2}]
    assert "rejected by graph" in dead_letter.read_text(encoding="utf-8")


def test_incomplete_trailing_line_waits_for_next_poll(tmp_path):
    seen = []
    source, _, tailer = _tailer(tmp_path, seen.append)
    source.write_bytes(b'{"id": 1}')

    assert tailer.poll() == 0
    assert tailer.offset == 0
    assert seen == []

    with source.open("ab") as stream:
        stream.write(b"\n")

    assert tailer.poll() == 1
    assert seen == [{"id": 1}]


def test_file_truncation_restarts_consumption_at_zero(tmp_path):
    seen = []
    source, _, tailer = _tailer(tmp_path, seen.append)
    source.write_text('{"id": "long-first-event"}\n', encoding="utf-8")
    assert tailer.poll() == 1

    source.write_text('{"id": 2}\n', encoding="utf-8")

    assert tailer.poll() == 1
    assert seen == [{"id": "long-first-event"}, {"id": 2}]
