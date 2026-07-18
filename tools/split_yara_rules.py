"""Split a large YARA source file into independently compilable shards."""

from __future__ import annotations

import argparse
import re
import shutil
import tempfile
from pathlib import Path

import yara


RULE_START = re.compile(
    r"(?m)^(?:(?:private|global)\s+)?rule\s+(?P<identifier>[A-Za-z_]\w*)\b"
)


def compiled_identifiers(path: Path) -> list[str]:
    return [rule.identifier for rule in yara.compile(filepath=str(path))]


def active_rule_slices(source: str, active_ids: set[str]) -> tuple[str, list[str]]:
    """Return the header and source slices for compiler-visible rules."""
    starts = [
        match
        for match in RULE_START.finditer(source)
        if match.group("identifier") in active_ids
    ]
    if not starts:
        raise ValueError("no active YARA rules found")

    slices = []
    for index, match in enumerate(starts):
        end = starts[index + 1].start() if index + 1 < len(starts) else len(source)
        slices.append(source[match.start():end].rstrip() + "\n")
    return source[:starts[0].start()].rstrip() + "\n", slices


def shard_sources(
    source_path: Path,
    max_rules: int,
) -> tuple[list[str], list[tuple[str, str]]]:
    source = source_path.read_text(encoding="utf-8")
    source_ids = compiled_identifiers(source_path)
    header, rules = active_rule_slices(source, set(source_ids))
    if len(rules) != len(source_ids):
        raise ValueError(
            f"boundary mismatch: compiler={len(source_ids)}, parser={len(rules)}"
        )

    shards = []
    for offset in range(0, len(rules), max_rules):
        index = offset // max_rules + 1
        name = f"{source_path.stem}_{index:02d}{source_path.suffix}"
        notice = (
            f"\n/* Generated from {source_path.name}; shard {index}. "
            "Do not edit generated shards independently. */\n\n"
        )
        shards.append((name, header + notice + "\n".join(rules[offset:offset + max_rules])))
    return source_ids, shards


def verify_shards(directory: Path, names: list[str], expected_ids: list[str]) -> None:
    actual_ids = []
    for name in names:
        actual_ids.extend(compiled_identifiers(directory / name))
    if actual_ids != expected_ids:
        missing = sorted(set(expected_ids) - set(actual_ids))
        extra = sorted(set(actual_ids) - set(expected_ids))
        raise ValueError(
            f"shard verification failed: missing={missing}, extra={extra}"
        )


def split_file(source_path: Path, max_rules: int, write: bool) -> None:
    source_path = source_path.resolve()
    expected_ids, shards = shard_sources(source_path, max_rules)

    with tempfile.TemporaryDirectory(prefix="anteumbra-yara-") as temp_name:
        temp_dir = Path(temp_name)
        for name, content in shards:
            (temp_dir / name).write_text(content, encoding="utf-8", newline="\n")
        names = [name for name, _ in shards]
        verify_shards(temp_dir, names, expected_ids)

        sizes = [round((temp_dir / name).stat().st_size / 1024, 1) for name in names]
        print(
            f"verified {len(expected_ids)} rules in {len(names)} shards; "
            f"sizes_kb={sizes}"
        )
        if not write:
            print("dry run only; pass --write to replace the source file")
            return

        stale_pattern = f"{source_path.stem}_*{source_path.suffix}"
        for stale in source_path.parent.glob(stale_pattern):
            stale.unlink()
        for name in names:
            shutil.copyfile(temp_dir / name, source_path.parent / name)
        source_path.unlink()
        verify_shards(source_path.parent, names, expected_ids)
        print(f"replaced {source_path.name} with {len(names)} verified shards")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("--max-rules", type=int, default=75)
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    if args.max_rules < 1:
        parser.error("--max-rules must be positive")
    split_file(args.source, args.max_rules, args.write)


if __name__ == "__main__":
    main()
