# -*- coding: utf-8 -*-
"""Watcher selection must not trade idle CPU for a self-inflicted event loop.

Windows inotify-equivalent (ReadDirectoryChangesW) reports a read as a change
when the notify mask carries FILE_NOTIFY_CHANGE_LAST_ACCESS, and this product
reads every file it scans.  Measured on a live site: 8.6 MODIFY events per
second on a tree nobody was touching, and the service never went idle.
"""

from __future__ import annotations

import platform

import pytest

from anteumbra.infrastructure.utils import platform_utils


@pytest.fixture
def winapi():
    """The watchdog Windows module, or a skip on a host that cannot load it."""
    return pytest.importorskip("watchdog.observers.winapi")


@pytest.fixture
def unmasked(winapi):
    """Start each test from a mask that still carries the access flags.

    Another test in the session may already have built an observer, which masks
    the module global, so the starting state has to be established explicitly.
    """
    original = winapi.WATCHDOG_FILE_NOTIFY_FLAGS
    for name in platform_utils.ACCESS_ONLY_NOTIFY_FLAGS:
        original |= getattr(winapi, name)
    winapi.WATCHDOG_FILE_NOTIFY_FLAGS = original
    yield original
    winapi.WATCHDOG_FILE_NOTIFY_FLAGS = original


def test_masking_removes_only_the_access_notifications(winapi, unmasked):
    assert platform_utils.watch_content_changes_only() is True

    after = winapi.WATCHDOG_FILE_NOTIFY_FLAGS
    assert not after & winapi.FILE_NOTIFY_CHANGE_LAST_ACCESS
    assert not after & winapi.FILE_NOTIFY_CHANGE_ATTRIBUTES
    # Content changes must still be reported, or nothing would ever be detected.
    for kept in (
        "FILE_NOTIFY_CHANGE_FILE_NAME",
        "FILE_NOTIFY_CHANGE_DIR_NAME",
        "FILE_NOTIFY_CHANGE_SIZE",
        "FILE_NOTIFY_CHANGE_LAST_WRITE",
        "FILE_NOTIFY_CHANGE_CREATION",
    ):
        assert after & getattr(winapi, kept), kept
    assert after != unmasked


def test_masking_is_idempotent(winapi, unmasked):
    assert platform_utils.watch_content_changes_only() is True
    once = winapi.WATCHDOG_FILE_NOTIFY_FLAGS

    assert platform_utils.watch_content_changes_only() is True

    assert winapi.WATCHDOG_FILE_NOTIFY_FLAGS == once


def test_missing_mask_reports_failure_instead_of_watching_nothing(monkeypatch, winapi):
    monkeypatch.delattr(winapi, "WATCHDOG_FILE_NOTIFY_FLAGS", raising=False)

    assert platform_utils.watch_content_changes_only() is False


def test_missing_flag_name_reports_failure(monkeypatch, winapi):
    monkeypatch.delattr(winapi, "FILE_NOTIFY_CHANGE_LAST_ACCESS", raising=False)

    assert platform_utils.watch_content_changes_only() is False


def test_windows_uses_native_events_when_masking_is_available(monkeypatch):
    monkeypatch.setattr(platform, "system", lambda: "Windows")
    monkeypatch.setattr(platform_utils, "watch_content_changes_only", lambda: True)

    observer = platform_utils.get_optimal_observer()

    assert observer.__class__.__name__ != "PollingObserver"


def test_windows_falls_back_to_polling_when_masking_is_unavailable(monkeypatch):
    monkeypatch.setattr(platform, "system", lambda: "Windows")
    monkeypatch.setattr(platform_utils, "watch_content_changes_only", lambda: False)

    observer = platform_utils.get_optimal_observer()
    assert observer.__class__.__name__ == "PollingObserver"
    assert observer.timeout == 0.2


@pytest.mark.skipif(platform.system() != "Linux", reason="inotify exists on Linux only")
def test_linux_still_uses_inotify(monkeypatch):
    monkeypatch.setattr(platform, "system", lambda: "Linux")

    observer = platform_utils.get_optimal_observer()
    try:
        assert observer.__class__.__name__ == "InotifyObserver"
    finally:
        observer.stop()
        observer.join(timeout=5)
