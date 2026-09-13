"""Content fingerprinting for detected files.

A detection record outlives the file it describes.  Recording *what* was found
— not only *where* — is what lets a later "the same webshell is back" question
be answered after the original file was deleted by an operator, a script, or an
attacker cleaning up.
"""

from __future__ import annotations

from hashlib import sha256
from pathlib import Path

CHUNK_SIZE = 1024 * 1024
MAX_HASH_BYTES = 64 * 1024 * 1024


def file_content_hash(path: str | Path, *, max_bytes: int = MAX_HASH_BYTES) -> str:
    """Return the SHA-256 digest of a file's bytes, or ``""`` if unavailable.

    Fingerprinting is best-effort evidence.  A file that is already gone,
    locked by another process, or larger than ``max_bytes`` must never break the
    detection path, so every failure degrades to an empty digest and the
    detection is still recorded.
    """
    digest = sha256()
    total = 0
    try:
        with open(path, "rb") as handle:
            while True:
                chunk = handle.read(CHUNK_SIZE)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    return ""
                digest.update(chunk)
    except OSError:
        return ""
    return digest.hexdigest()


__all__ = ["MAX_HASH_BYTES", "file_content_hash"]
