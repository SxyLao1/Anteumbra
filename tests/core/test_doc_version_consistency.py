# -*- coding: utf-8 -*-
"""User-facing documents must state the version the package actually is.

1.0.40 shipped with the README badge, both README footers and both roadmap
headers still announcing 1.0.35: the release updated the manuals and changelogs
but nothing checked the readme, and a truncated grep hid it from review. This
guard fails the build instead.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]


def current_version() -> str:
    text = (REPO / "src" / "anteumbra" / "__init__.py").read_text(encoding="utf-8")
    match = re.search(r'__version__ = "([^"]+)"', text)
    assert match, "the package version could not be read"
    return match.group(1)


VERSION = current_version()

DOCUMENTS_WITH_BADGE = ("README.md", "README_cn.md")
MANUALS = ("docs/USER_MANUAL.md", "docs/USER_MANUAL_cn.md")
ROADMAPS = ("ROADMAP.md", "ROADMAP_cn.md")
CHANGELOGS = ("CHANGELOG.md", "CHANGELOG_cn.md")


@pytest.mark.parametrize("name", DOCUMENTS_WITH_BADGE)
def test_readme_badge_and_footer_show_the_current_version(name: str):
    text = (REPO / name).read_text(encoding="utf-8")
    assert f"version-{VERSION}-" in text, f"{name} badge does not carry {VERSION}"
    assert f"Anteumbra v{VERSION}" in text, f"{name} footer does not carry v{VERSION}"
    stale = re.findall(r"version-(\d+\.\d+\.\d+)-", text)
    assert stale == [VERSION], f"{name} badge versions: {stale}"


@pytest.mark.parametrize("name", MANUALS)
def test_manual_header_and_footer_show_the_current_version(name: str):
    text = (REPO / name).read_text(encoding="utf-8")
    assert f"v{VERSION}" in text.splitlines()[0], f"{name} title is not v{VERSION}"
    assert f"Anteumbra v{VERSION}" in text, f"{name} footer does not carry v{VERSION}"


@pytest.mark.parametrize("name", ROADMAPS)
def test_roadmap_announces_the_current_version(name: str):
    text = (REPO / name).read_text(encoding="utf-8")
    assert f"v{VERSION}" in text, f"{name} does not mention v{VERSION}"


@pytest.mark.parametrize("name", CHANGELOGS)
def test_changelog_has_a_section_for_the_current_version(name: str):
    text = (REPO / name).read_text(encoding="utf-8")
    assert f"## [{VERSION}]" in text, f"{name} has no section for {VERSION}"


def test_dockerfile_label_matches_the_package_version():
    text = (REPO / "Dockerfile").read_text(encoding="utf-8")
    assert f'image.version="{VERSION}"' in text, "Dockerfile label is stale"
