"""Filesystem adapter for durable manual-scan history."""

from __future__ import annotations

import json
import logging
import os
import re
import secrets
from pathlib import Path
from typing import Any, Mapping


_SCAN_ID_PATTERN = re.compile(r"^[0-9a-f]{16,64}$", re.IGNORECASE)


class FileScanHistoryStore:
    """Persist scan records under the runtime-owned data directory.

    Manual scan IDs are opaque hexadecimal tokens. Validating them before they
    become filenames keeps query input inside this adapter's directory boundary.
    """

    def __init__(self, directory: Path, *, logger: logging.Logger | None = None) -> None:
        self._directory = directory
        self._logger = logger or logging.getLogger(__name__)

    @staticmethod
    def _normalize_scan_id(scan_id: str) -> str:
        normalized = str(scan_id).strip().lower()
        if not _SCAN_ID_PATTERN.fullmatch(normalized):
            raise ValueError("invalid scan_id")
        return normalized

    def _path_for(self, scan_id: str) -> Path:
        return self._directory / f"{self._normalize_scan_id(scan_id)}.json"

    def save(self, scan_id: str, record: Mapping[str, Any]) -> None:
        """Write a complete JSON record so readers never observe a partial file."""
        normalized_id = self._normalize_scan_id(scan_id)
        self._directory.mkdir(parents=True, exist_ok=True)
        target = self._path_for(normalized_id)
        temporary = self._directory / f".{normalized_id}.{secrets.token_hex(8)}.tmp"
        payload = dict(record)
        payload["scan_id"] = normalized_id

        try:
            with temporary.open("w", encoding="utf-8") as stream:
                json.dump(payload, stream, indent=2, ensure_ascii=False)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, target)
        finally:
            if temporary.exists():
                try:
                    temporary.unlink()
                except OSError:
                    self._logger.debug("Failed to remove scan history temp file", exc_info=True)

    def list_records(self, limit: int | None = None) -> list[dict[str, Any]]:
        """Load valid records newest-first while skipping corrupt historical files."""
        if not self._directory.exists():
            return []

        records: list[dict[str, Any]] = []
        for path in self._directory.glob("*.json"):
            try:
                self._normalize_scan_id(path.stem)
                record = self._read(path)
            except (OSError, ValueError, json.JSONDecodeError):
                self._logger.warning("Ignoring invalid scan history record %s", path.name)
                continue
            records.append(record)

        records.sort(
            key=lambda record: float(record.get("end_time") or record.get("start_time") or 0),
            reverse=True,
        )
        return records if limit is None else records[: max(0, limit)]

    def get(self, scan_id: str) -> dict[str, Any] | None:
        """Load one record after validating its opaque identifier."""
        path = self._path_for(scan_id)
        if not path.exists():
            return None
        try:
            return self._read(path)
        except (OSError, ValueError, json.JSONDecodeError):
            self._logger.warning("Ignoring invalid scan history record %s", path.name)
            return None

    @staticmethod
    def _read(path: Path) -> dict[str, Any]:
        loaded = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(loaded, dict):
            raise ValueError("scan history record must be an object")
        return loaded