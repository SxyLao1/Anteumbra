# -*- coding: utf-8 -*-
"""The settings page's collapsible sections, in a real browser.

The Python tests can only assert the served HTML; this one proves the mechanism
those tests describe: the section header is an HTMX request, the server
re-renders the page for the requested ``?open=`` set, and the address bar keeps
the state so a refresh lands on the same expansion.
"""

from __future__ import annotations

SETTINGS_URL = "/admin/settings"


def go(page, url, **kw):
    """Navigate cleanly: unload first (killing SSE connections), then commit."""
    kw.setdefault("wait_until", "commit")
    kw.setdefault("timeout", 20000)
    page.goto("about:blank", wait_until="commit", timeout=10000)
    page.wait_for_timeout(200)
    return page.goto(url, **kw)


def _open_settings(page, server_url) -> None:
    go(page, f"{server_url}{SETTINGS_URL}")
    page.wait_for_selector('[data-settings-panel="environment"]', timeout=10000)


def test_secrets_are_the_first_open_section(page, server_url):
    _open_settings(page, server_url)

    panels = page.locator("[data-settings-panel]")
    assert panels.count() == 8
    assert panels.first.get_attribute("data-settings-panel") == "environment"
    assert page.locator("#settings-environment").is_visible()
    assert not page.locator('[data-settings-panel="plugins"] .card-body').is_visible(), (
        "only the secrets section may start expanded"
    )


def test_section_headers_expand_and_collapse_through_the_url(page, server_url):
    _open_settings(page, server_url)

    page.click('[data-settings-section="plugins"]')
    page.wait_for_url("**/admin/settings?open=environment,plugins", timeout=10000)
    page.wait_for_selector("#settings-plugins", state="visible", timeout=10000)
    # The whole page was re-rendered, so its panels were re-requested and the
    # plugin inventory is live rather than left over from the first render.
    page.wait_for_selector("#settings-plugins [data-plugin-panel]", timeout=10000)

    page.click('[data-settings-section="environment"]')
    page.wait_for_url("**/admin/settings?open=plugins", timeout=10000)
    page.wait_for_selector("#settings-environment", state="hidden", timeout=10000)
    assert page.locator("#settings-plugins").is_visible(), "plugins must stay open"

    page.reload()
    page.wait_for_selector("#settings-plugins", state="visible", timeout=10000)
    assert (
        page.locator('[data-settings-section="plugins"]').get_attribute("aria-expanded")
        == "true"
    ), "the query string must restore the same expansion after a reload"
    assert not page.locator("#settings-environment").is_visible()
