"""Audit Anteumbra YARA coverage against a script corpus."""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from anteumbra.infrastructure.detection.yara_engine import YaraEngine  # noqa: E402


DEFAULT_EXTENSIONS = (".php", ".asp", ".aspx", ".jsp", ".jspx")


def audit_corpus(root: Path, rules: Path, extensions: set[str]) -> dict:
    logger = logging.getLogger("anteumbra.yara_corpus_audit")
    logger.addHandler(logging.NullHandler())
    logger.setLevel(logging.ERROR)
    engine = YaraEngine(rules, logger)
    if not engine.compiled_rules:
        raise RuntimeError(f"no valid YARA rules loaded from {rules}")

    files = sorted(
        (
            path for path in root.rglob("*")
            if path.is_file() and path.suffix.lower() in extensions
        ),
        key=lambda path: str(path).lower(),
    )
    by_extension = defaultdict(lambda: {"total": 0, "hit": 0, "miss": 0})
    rule_hits = Counter()
    hits = []
    misses = []
    errors = []
    started = time.perf_counter()

    for path in files:
        suffix = path.suffix.lower()
        by_extension[suffix]["total"] += 1
        try:
            matches = engine.scan_data(path.read_bytes(), str(path))
        except OSError as exc:
            errors.append({"path": str(path), "error": str(exc)})
            continue
        runtime_errors = dict(engine.compiled_rules.last_match_errors)
        if runtime_errors:
            errors.append({"path": str(path), "rule_errors": runtime_errors})

        relative = str(path.relative_to(root))
        if matches:
            names = [match.rule_name for match in matches]
            hits.append({"path": relative, "rules": names})
            by_extension[suffix]["hit"] += 1
            rule_hits.update(names)
        else:
            misses.append(relative)
            by_extension[suffix]["miss"] += 1

    elapsed = time.perf_counter() - started
    return {
        "root": str(root.resolve()),
        "rules": str(rules.resolve()),
        "loaded_rule_files": list(engine.loaded_rule_files),
        "load_errors": engine.load_errors,
        "total": len(files),
        "hit": len(hits),
        "miss": len(misses),
        "error": len(errors),
        "hit_rate": round(len(hits) / len(files), 4) if files else 0,
        "elapsed_seconds": round(elapsed, 3),
        "by_extension": dict(sorted(by_extension.items())),
        "top_rules": rule_hits.most_common(30),
        "hits": hits,
        "misses": misses,
        "errors": errors,
    }


def print_summary(result: dict) -> None:
    print(
        f"total={result['total']} hit={result['hit']} miss={result['miss']} "
        f"errors={result['error']} rate={result['hit_rate']:.2%} "
        f"seconds={result['elapsed_seconds']}"
    )
    for suffix, counts in result["by_extension"].items():
        print(
            f"  {suffix}: total={counts['total']} hit={counts['hit']} "
            f"miss={counts['miss']}"
        )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    parser.add_argument(
        "--rules",
        type=Path,
        default=SRC_ROOT / "anteumbra" / "rules" / "webshell",
    )
    parser.add_argument("--extensions", nargs="*", default=DEFAULT_EXTENSIONS)
    parser.add_argument("--json", type=Path)
    parser.add_argument("--show-misses", action="store_true")
    args = parser.parse_args()

    extensions = {
        value.lower() if value.startswith(".") else f".{value.lower()}"
        for value in args.extensions
    }
    result = audit_corpus(args.root.resolve(), args.rules.resolve(), extensions)
    print_summary(result)
    if args.show_misses:
        for path in result["misses"]:
            print(f"MISS {path}")
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(
            json.dumps(result, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        print(f"wrote {args.json.resolve()}")


if __name__ == "__main__":
    main()
