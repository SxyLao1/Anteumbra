"""Verify that a built Wheel contains current source modules only."""

from __future__ import annotations

import argparse
import sys
import zipfile
from pathlib import Path, PurePosixPath


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SOURCE_PACKAGE = PROJECT_ROOT / "src" / "anteumbra"


def resolve_wheel(path: Path) -> Path:
    """Resolve one Wheel from a file or a directory containing exactly one."""
    if path.is_file() and path.suffix == ".whl":
        return path
    if not path.is_dir():
        raise ValueError(f"Wheel path does not exist: {path}")
    wheels = sorted(path.glob("*.whl"))
    if len(wheels) != 1:
        raise ValueError(f"Expected exactly one Wheel in {path}, found {len(wheels)}")
    return wheels[0]


def compare_wheel_to_source(
    wheel_path: Path,
    source_package: Path,
) -> tuple[list[str], list[str], int, int]:
    """Return stale members, missing Python files, and comparison counts."""
    if not source_package.is_dir():
        raise ValueError(f"Source package does not exist: {source_package}")

    source_root = source_package.parent
    expected_python = {
        PurePosixPath("anteumbra")
        / PurePosixPath(path.relative_to(source_package).as_posix())
        for path in source_package.rglob("*.py")
    }
    with zipfile.ZipFile(wheel_path) as archive:
        package_members = {
            PurePosixPath(name)
            for name in archive.namelist()
            if name.startswith("anteumbra/") and not name.endswith("/")
        }

    stale = sorted(
        member.as_posix()
        for member in package_members
        if not (source_root / Path(*member.parts)).is_file()
    )
    wheel_python = {member for member in package_members if member.suffix == ".py"}
    missing_python = sorted(
        member.as_posix() for member in expected_python - wheel_python
    )
    return stale, missing_python, len(expected_python), len(package_members)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "wheel_or_directory",
        nargs="?",
        type=Path,
        default=PROJECT_ROOT / "dist",
    )
    parser.add_argument(
        "--source-package",
        type=Path,
        default=DEFAULT_SOURCE_PACKAGE,
    )
    args = parser.parse_args(argv)

    try:
        wheel_path = resolve_wheel(args.wheel_or_directory)
        stale, missing, python_count, package_file_count = compare_wheel_to_source(
            wheel_path,
            args.source_package,
        )
    except (OSError, ValueError, zipfile.BadZipFile) as exc:
        print(f"Wheel verification failed: {exc}", file=sys.stderr)
        return 1

    if stale or missing:
        if stale:
            print("Wheel contains files absent from src/anteumbra:", file=sys.stderr)
            for member in stale:
                print(f"  {member}", file=sys.stderr)
        if missing:
            print("Wheel is missing source Python files:", file=sys.stderr)
            for member in missing:
                print(f"  {member}", file=sys.stderr)
        return 1

    print(
        f"Wheel source parity OK: {wheel_path.name} "
        f"({python_count} Python files, {package_file_count} package files)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
