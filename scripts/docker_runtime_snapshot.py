"""Back up or restore a stopped Docker runtime, preserving numeric ownership."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import tarfile
from pathlib import Path, PurePosixPath


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def manifest(root: Path) -> dict:
    result = {}
    for path in [root, *sorted(root.rglob("*"))]:
        info = path.lstat()
        if stat.S_ISREG(info.st_mode):
            kind = "file"
        elif stat.S_ISDIR(info.st_mode):
            kind = "directory"
        else:
            raise ValueError(f"Unsupported link or special file: {path.relative_to(root)}")
        item = {
            "type": kind,
            "mode": stat.S_IMODE(info.st_mode),
            "uid": info.st_uid,
            "gid": info.st_gid,
        }
        if kind == "file":
            item.update(bytes=info.st_size, sha256=sha256(path))
        result[path.relative_to(root).as_posix()] = item
    return result


def sidecars(archive: Path) -> tuple[Path, Path]:
    return Path(str(archive) + ".manifest.json"), Path(str(archive) + ".sha256")


def backup(root: Path, archive: Path) -> None:
    metadata, checksum = sidecars(archive)
    if any(path.exists() for path in (archive, metadata, checksum)):
        raise ValueError("Snapshot or sidecar already exists; choose a new snapshot name")
    before = manifest(root)
    with tarfile.open(archive, "x:gz") as bundle:
        for name in before:
            bundle.add(root / name, arcname=name, recursive=False)
    if manifest(root) != before:
        raise ValueError("Runtime changed during backup; stop all writers and use a new snapshot")
    metadata.write_text(json.dumps(before, indent=2) + "\n", encoding="utf-8")
    checksum.write_text(sha256(archive) + "\n", encoding="ascii")
    for path in (archive, metadata, checksum):
        path.chmod(0o600)
    print(f"Backup complete: {len(before)} entries; content, modes and numeric owners recorded")


def restore(root: Path, archive: Path) -> None:
    if any(root.iterdir()):
        raise ValueError("Restore requires an empty new runtime volume")
    metadata, checksum = sidecars(archive)
    expected_digest = checksum.read_text(encoding="ascii").strip()
    if sha256(archive) != expected_digest:
        raise ValueError("Snapshot SHA-256 does not match its sidecar")
    expected = json.loads(metadata.read_text(encoding="utf-8"))
    with tarfile.open(archive, "r:gz") as bundle:
        members = bundle.getmembers()
        names = []
        for member in members:
            path = PurePosixPath(member.name)
            if path.is_absolute() or ".." in path.parts or "\\" in member.name:
                raise ValueError("Unsafe path in snapshot")
            if not (member.isfile() or member.isdir()):
                raise ValueError("Links and special files are not supported in runtime snapshots")
            names.append(path.as_posix())
        if len(set(names)) != len(names) or set(names) != set(expected):
            raise ValueError("Snapshot entries differ from the recorded manifest")
        for member, name in zip(members, names):
            recorded = {
                "type": "file" if member.isfile() else "directory",
                "mode": member.mode,
                "uid": member.uid,
                "gid": member.gid,
            }
            if member.isfile():
                digest = hashlib.sha256()
                with bundle.extractfile(member) as stream:
                    for block in iter(lambda: stream.read(1024 * 1024), b""):
                        digest.update(block)
                recorded.update(bytes=member.size, sha256=digest.hexdigest())
            if recorded != expected[name]:
                raise ValueError(f"Snapshot content or metadata differs from manifest: {name}")
        # Every member is now a relative regular file/directory, and the target
        # is empty. The data filter discards ownership, so use the validated
        # members with numeric owners to keep the non-root runtime writable.
        bundle.extractall(root, members=members, numeric_owner=True, filter="fully_trusted")
    actual = manifest(root)
    if actual != expected:
        differences = sorted(name for name in actual.keys() | expected.keys()
                             if actual.get(name) != expected.get(name))
        raise ValueError(f"Restored content or metadata differs: {differences[:10]}")
    print(f"Restore verified: {len(actual)} entries; SHA-256, modes and numeric owners match")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("backup", "restore"))
    parser.add_argument("--runtime", type=Path, default=Path("/runtime"))
    parser.add_argument("--archive", type=Path, required=True)
    args = parser.parse_args()
    if os.name != "posix" or os.geteuid() != 0:
        parser.error("Run this helper as root inside the isolated Linux helper container")
    root = args.runtime.resolve(strict=True)
    archive = args.archive.resolve()
    if not root.is_dir() or root == Path("/") or archive.is_relative_to(root):
        parser.error("Use a dedicated runtime mount and a separate backup directory")
    archive.parent.mkdir(parents=True, exist_ok=True)
    try:
        (backup if args.action == "backup" else restore)(root, archive)
    except (OSError, ValueError, tarfile.TarError) as exc:
        parser.exit(1, f"{exc}\n")


if __name__ == "__main__":
    main()
