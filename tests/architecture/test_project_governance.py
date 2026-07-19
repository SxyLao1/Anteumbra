"""Documentation and CI governance regression tests."""

from __future__ import annotations

import re
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
LOCAL_LINK = re.compile(r"(?<!!)\[[^\]]+\]\(([^)]+)\)")

DOCUMENT_PAIRS = (
    ("README.md", "README_cn.md"),
    ("ROADMAP.md", "ROADMAP_cn.md"),
    ("CHANGELOG.md", "CHANGELOG_cn.md"),
    ("docs/ARCHITECTURE.md", "docs/ARCHITECTURE_cn.md"),
    ("docs/USER_MANUAL.md", "docs/USER_MANUAL_cn.md"),
    ("docs/RELEASE.md", "docs/RELEASE_cn.md"),
    ("tools/memory-shell/README.md", "tools/memory-shell/README_cn.md"),
)


def _documentation_files() -> list[Path]:
    files = list(PROJECT_ROOT.glob("*.md"))
    files.extend((PROJECT_ROOT / "docs").glob("*.md"))
    files.extend((PROJECT_ROOT / "tools" / "memory-shell").rglob("*.md"))
    return sorted(set(files))


def test_public_english_documents_have_cn_counterparts():
    missing = [
        chinese
        for english, chinese in DOCUMENT_PAIRS
        if not (PROJECT_ROOT / english).is_file()
        or not (PROJECT_ROOT / chinese).is_file()
    ]
    assert not missing, "missing English/Chinese document pairs: " + ", ".join(missing)


def test_active_document_names_no_longer_use_zh_suffix():
    stale = list(PROJECT_ROOT.glob("*_zh.md")) + list(
        (PROJECT_ROOT / "docs").glob("*_zh.md")
    )
    assert not stale, "rename Chinese documents to *_cn.md: " + ", ".join(
        str(path.relative_to(PROJECT_ROOT)) for path in stale
    )


def test_local_markdown_links_resolve():
    broken: list[str] = []
    for document in _documentation_files():
        source = document.read_text(encoding="utf-8")
        for raw_target in LOCAL_LINK.findall(source):
            target = raw_target.strip().strip("<>")
            if not target or target.startswith(("#", "http://", "https://", "mailto:")):
                continue
            local_path = target.split("#", 1)[0]
            if not (document.parent / local_path).resolve().exists():
                broken.append(
                    f"{document.relative_to(PROJECT_ROOT).as_posix()}: {raw_target}"
                )
    assert not broken, "broken local Markdown links:\n" + "\n".join(broken)


def test_ci_does_not_hide_release_smoke_failures():
    ci_source = (
        PROJECT_ROOT / ".github" / "workflows" / "ci.yml"
    ).read_text(encoding="utf-8")
    publish_source = (
        PROJECT_ROOT / ".github" / "workflows" / "publish.yml"
    ).read_text(encoding="utf-8")

    assert "python -m ruff check src tests" in ci_source
    assert "anteumbra --version 2>&1 || true" not in ci_source
    assert not re.search(r"curl[^\n]*api/v1/health[^\n]*\|\| true", ci_source)
    assert "curl --fail --silent --show-error" in ci_source
    assert 'echo "Anteumbra health endpoint did not become ready"' in ci_source
    wheel_check = "python scripts/verify_wheel_contents.py dist"
    assert wheel_check in ci_source
    assert wheel_check in publish_source
