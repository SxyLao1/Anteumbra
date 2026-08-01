"""Reliable, incremental consumption of append-only JSONL event files."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Callable


class JsonlEventTailer:
    """Consume complete JSONL records once and dead-letter rejected records."""

    def __init__(
        self,
        path: Path,
        handler: Callable[[dict[str, Any]], None],
        *,
        logger: logging.Logger,
        dead_letter_path: Path | None = None,
    ) -> None:
        self.path = Path(path)
        self.handler = handler
        self.logger = logger
        self.dead_letter_path = dead_letter_path or self.path.with_suffix(".deadletter.jsonl")
        self.offset = 0
        self._file_identity: tuple[int, int] | None = None

    def poll(self) -> int:
        """Consume all complete records currently available.

        The returned count includes rejected records because they have been moved to
        the dead-letter file and acknowledged. An incomplete trailing line is left
        unacknowledged until a later poll completes it.
        """
        if not self.path.exists():
            return 0

        stat = self.path.stat()
        identity = (stat.st_dev, stat.st_ino)
        if (
            self._file_identity is not None and identity != self._file_identity
        ) or stat.st_size < self.offset:
            self.logger.warning(
                "Profile event file was replaced or truncated; restarting at offset 0: %s",
                self.path,
            )
            self.offset = 0
        self._file_identity = identity

        consumed = 0
        with self.path.open("rb") as stream:
            stream.seek(self.offset)
            while True:
                record_offset = stream.tell()
                raw_line = stream.readline()
                if not raw_line:
                    break
                if not raw_line.endswith(b"\n"):
                    stream.seek(record_offset)
                    break

                next_offset = stream.tell()
                if not raw_line.strip():
                    self.offset = next_offset
                    consumed += 1
                    continue

                try:
                    text = raw_line.decode("utf-8")
                    event = json.loads(text)
                    if not isinstance(event, dict):
                        raise ValueError("event must be a JSON object")
                    self.handler(event)
                except Exception as exc:
                    self._dead_letter(record_offset, raw_line, exc)
                    self.logger.error(
                        "Rejected profile event at byte %s in %s: %s",
                        record_offset,
                        self.path,
                        exc,
                        exc_info=True,
                    )

                self.offset = next_offset
                consumed += 1

        return consumed

    def _dead_letter(self, offset: int, raw_line: bytes, exc: Exception) -> None:
        record = {
            "source": str(self.path),
            "offset": offset,
            "error_type": type(exc).__name__,
            "error": str(exc),
            "raw": raw_line.decode("utf-8", errors="replace").rstrip("\r\n"),
        }
        try:
            self.dead_letter_path.parent.mkdir(parents=True, exist_ok=True)
            with self.dead_letter_path.open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(record, ensure_ascii=False) + "\n")
        except Exception:
            self.logger.critical(
                "Failed to write profile event dead letter: %s",
                self.dead_letter_path,
                exc_info=True,
            )
