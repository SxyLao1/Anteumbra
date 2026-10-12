"""Regression coverage for the Docker runtime snapshot helper."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
import stat
import tarfile
import tempfile
import unittest
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
HELPER_PATH = REPOSITORY_ROOT / "scripts" / "docker_runtime_snapshot.py"
SPEC = importlib.util.spec_from_file_location("docker_runtime_snapshot", HELPER_PATH)
assert SPEC is not None and SPEC.loader is not None
snapshot = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(snapshot)


class DockerRuntimeSnapshotTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name)
        self.runtime = self.root / "runtime"
        self.backups = self.root / "backups"
        self.runtime.mkdir()
        self.backups.mkdir()
        (self.runtime / "config.toml").write_text("[website]\nname = 'fixture'\n", encoding="utf-8")
        data = self.runtime / "data"
        data.mkdir()
        self.state = data / "state.txt"
        self.state.write_text("synthetic fixture", encoding="utf-8")
        self.state.chmod(0o640)
        self.archive = self.backups / "runtime.tar.gz"

    def restore_target(self, name: str) -> Path:
        target = self.root / name
        target.mkdir()
        return target

    def assert_rejected_without_writes(self, archive: Path, name: str) -> None:
        target = self.restore_target(name)
        with self.assertRaises(ValueError):
            snapshot.restore(target, archive)
        self.assertEqual(list(target.iterdir()), [])

    def make_backup(self) -> dict:
        snapshot.backup(self.runtime, self.archive)
        return json.loads(snapshot.sidecars(self.archive)[0].read_text(encoding="utf-8"))

    def replace_manifest(self, records: dict) -> None:
        snapshot.sidecars(self.archive)[0].write_text(
            json.dumps(records), encoding="utf-8"
        )

    def test_backup_restore_preserves_root_and_file_metadata(self) -> None:
        expected = self.make_backup()
        restored = self.restore_target("restored")

        snapshot.restore(restored, self.archive)

        self.assertEqual(snapshot.manifest(restored), expected)
        self.assertEqual((restored / "data" / "state.txt").read_text(encoding="utf-8"), "synthetic fixture")

    @unittest.skipUnless(os.name == "posix", "numeric owners are POSIX-specific")
    def test_restore_preserves_numeric_owners_and_modes_on_posix(self) -> None:
        data = self.runtime / "data"
        if os.geteuid() == 0:
            for path, uid, gid in (
                (self.runtime, 1000, 1000),
                (data, 1001, 1001),
                (self.state, 1002, 1002),
            ):
                os.chown(path, uid, gid)
            self.runtime.chmod(0o750)
            data.chmod(0o750)
        self.make_backup()
        restored = self.restore_target("restored")

        snapshot.restore(restored, self.archive)

        for original, recovered in (
            (self.runtime, restored),
            (self.runtime / "data", restored / "data"),
            (self.state, restored / "data" / "state.txt"),
        ):
            source = original.stat()
            target = recovered.stat()
            self.assertEqual(
                (target.st_uid, target.st_gid, stat.S_IMODE(target.st_mode)),
                (source.st_uid, source.st_gid, stat.S_IMODE(source.st_mode)),
            )
        if os.geteuid() == 0:
            self.assertEqual(
                (restored.stat().st_uid, restored.stat().st_gid, stat.S_IMODE(restored.stat().st_mode)),
                (1000, 1000, 0o750),
            )
            restored_data = restored / "data"
            self.assertEqual(
                (
                    restored_data.stat().st_uid,
                    restored_data.stat().st_gid,
                    stat.S_IMODE(restored_data.stat().st_mode),
                ),
                (1001, 1001, 0o750),
            )
            restored_state = restored_data / "state.txt"
            self.assertEqual(
                (
                    restored_state.stat().st_uid,
                    restored_state.stat().st_gid,
                    stat.S_IMODE(restored_state.stat().st_mode),
                ),
                (1002, 1002, 0o640),
            )

    def test_backup_refuses_existing_snapshot_and_restore_refuses_nonempty_target(self) -> None:
        self.make_backup()
        with self.assertRaisesRegex(ValueError, "already exists"):
            snapshot.backup(self.runtime, self.archive)

        target = self.restore_target("nonempty")
        marker = target / "keep.txt"
        marker.write_text("unchanged", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "empty new runtime volume"):
            snapshot.restore(target, self.archive)
        self.assertEqual(marker.read_text(encoding="utf-8"), "unchanged")

    def test_restore_rejects_bad_archive_checksum_without_writing_target(self) -> None:
        self.make_backup()
        checksum = snapshot.sidecars(self.archive)[1]
        checksum.write_text("0" * 64 + "\n", encoding="ascii")

        self.assert_rejected_without_writes(self.archive, "bad-checksum")

    def test_restore_rejects_manifest_content_hash_and_metadata_without_writing_target(self) -> None:
        expected = self.make_backup()
        for name, field, value in (
            ("bad-content-hash", "sha256", "0" * 64),
            ("bad-owner", "uid", expected["data/state.txt"]["uid"] + 1),
            ("bad-mode", "mode", 0o600),
        ):
            with self.subTest(name=name):
                forged = copy.deepcopy(expected)
                forged["data/state.txt"][field] = value
                self.replace_manifest(forged)
                self.assert_rejected_without_writes(self.archive, name)
        self.replace_manifest(expected)

    def write_malformed_archive(
        self, name: str, member_type: bytes, member_names: list[str], records: dict
    ) -> Path:
        archive = self.backups / f"{name}.tar.gz"
        with tarfile.open(archive, "w:gz") as bundle:
            root = tarfile.TarInfo(".")
            root.type = tarfile.DIRTYPE
            bundle.addfile(root)
            for member_name in member_names:
                member = tarfile.TarInfo(member_name)
                member.type = member_type
                bundle.addfile(member)
        metadata, checksum = snapshot.sidecars(archive)
        metadata.write_text(json.dumps(records), encoding="utf-8")
        checksum.write_text(snapshot.sha256(archive) + "\n", encoding="ascii")
        return archive

    def test_restore_rejects_traversal_links_and_duplicate_members_without_writes(self) -> None:
        root_record = {"type": "directory", "mode": 0o755, "uid": 0, "gid": 0}
        file_record = {
            "type": "file",
            "mode": 0o644,
            "uid": 0,
            "gid": 0,
            "bytes": 0,
            "sha256": hashlib.sha256(b"").hexdigest(),
        }
        cases = (
            ("traversal", tarfile.REGTYPE, ["../outside"], {".": root_record, "../outside": file_record}),
            ("symlink", tarfile.SYMTYPE, ["linked"], {".": root_record, "linked": file_record}),
            ("hardlink", tarfile.LNKTYPE, ["linked"], {".": root_record, "linked": file_record}),
            ("duplicate", tarfile.REGTYPE, ["same", "same"], {".": root_record, "same": file_record}),
        )
        for name, member_type, member_names, records in cases:
            with self.subTest(name=name):
                archive = self.write_malformed_archive(name, member_type, member_names, records)
                self.assert_rejected_without_writes(archive, name)


if __name__ == "__main__":
    unittest.main()
