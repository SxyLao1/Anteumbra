"""Browser-only acceptance of the real memory-shell service and its UI.

The target is a loopback protocol simulator, not a JVM.  It is intentionally
visible in a browser so the test verifies Anteumbra's actual outbound requests
without reading target-process state directly.
"""
from __future__ import annotations

from pathlib import Path

from playwright.sync_api import expect

from .memory_target import COMPONENT_NAME


def _admin_url(admin_base: str, suffix: str) -> str:
    return admin_base + suffix


def test_memory_probe_forensics_download_and_component_remediation(real_instance, memory_targets):
    page, _portal, _shop = real_instance
    portal_target, shop_target = memory_targets
    admin_base = page.url.split("/admin/")[0]

    page.goto(_admin_url(admin_base, "/admin/memory-shell"))
    panel = page.locator("#memory-shell-panel")
    expect(panel).to_contain_text("Portal test site")
    portal_site = panel.locator("tr").filter(has_text="Portal test site")
    page.once("dialog", lambda dialog: dialog.accept())
    portal_site.get_by_role("button", name="Probe Memory Shell").click()
    expect(panel).to_contain_text(COMPONENT_NAME, timeout=15000)
    expect(panel).to_contain_text("Suspicious")
    expect(panel.locator("table").last.locator("tbody tr").first).to_contain_text("Suspicious")

    # The only target observation is its public browser-visible replay page.
    page.goto(portal_target.url)
    expect(page.get_by_role("heading", name="Memory target protocol lab")).to_be_visible()
    expect(page.get_by_text("probe", exact=True)).to_be_visible()

    page.goto(_admin_url(admin_base, "/admin/memory-shell"))
    panel = page.locator("#memory-shell-panel")
    finding = panel.locator("tr").filter(has_text=COMPONENT_NAME)
    finding.get_by_role("link", name="Forensics").click()
    page.wait_for_url("**/admin/memory-shell/forensics?**")
    forensics = page.locator("#memory-shell-forensics-panel")
    expect(forensics).to_contain_text(COMPONENT_NAME)
    forensics.get_by_role("button", name="Run forensics for this component").click()
    expect(forensics).to_contain_text("Forensics artifacts", timeout=15000)
    artifact_row = forensics.locator("tr").filter(has_text=COMPONENT_NAME)
    expect(artifact_row).to_contain_text("manifest.json")
    with page.expect_download() as download_info:
        artifact_row.get_by_role("link", name="manifest.json").click()
    download = download_info.value
    assert download.suggested_filename == "manifest.json"
    manifest = Path(download.path()).read_text(encoding="utf-8")
    assert COMPONENT_NAME in manifest
    assert "protocol simulator" in manifest

    page.goto(_admin_url(admin_base, "/admin/memory-shell/forensics?site=shop"))
    expect(page.locator("#memory-shell-forensics-panel")).not_to_contain_text(COMPONENT_NAME)

    page.goto(portal_target.url)
    expect(page.get_by_text("dump", exact=True)).to_be_visible()
    page.goto(_admin_url(admin_base, "/admin/memory-shell/forensics?site=portal"))
    forensics = page.locator("#memory-shell-forensics-panel")
    artifact_row = forensics.locator("tr").filter(has_text=COMPONENT_NAME)
    artifact_row.get_by_role("button", name="Remediate").click()
    dialog = page.get_by_role("dialog", name="Confirm remediation")
    expect(dialog).to_contain_text(COMPONENT_NAME)
    dialog.get_by_role("button", name="Confirm remediation").click()
    expect(page.get_by_role("dialog")).to_contain_text("Removed", timeout=10000)

    page.goto(portal_target.url)
    expect(page.get_by_text("kill", exact=True)).to_be_visible()
    page.goto(_admin_url(admin_base, "/admin/memory-shell?site=portal"))
    panel = page.locator("#memory-shell-panel")
    portal_site = panel.locator("tr").filter(has_text="Portal test site")
    page.once("dialog", lambda dialog: dialog.accept())
    portal_site.get_by_role("button", name="Probe Memory Shell").click()
    latest = panel.locator("table").last.locator("tbody tr").first
    expect(latest).to_contain_text("Clean", timeout=15000)
    expect(latest).not_to_contain_text(COMPONENT_NAME)
    expect(panel.get_by_role("link", name="Forensics", exact=True)).to_have_count(0)
    expect(panel).not_to_contain_text("Shop test site")
    expect(panel.locator("table").last.locator("tbody tr").nth(1)).to_contain_text("Suspicious")
    # The second site target remains untouched by this site's remediation.
    page.goto(shop_target.url)
    expect(page.get_by_text("No product request received.")).to_be_visible()


def test_memory_probe_failure_is_visible_after_target_control_ui(real_instance, memory_targets):
    page, _portal, _shop = real_instance
    _portal_target, shop_target = memory_targets
    admin_base = page.url.split("/admin/")[0]

    page.goto(shop_target.url)
    page.get_by_role("button", name="Fail next probe").click()
    expect(page.locator("body")).to_contain_text("probe_error")

    page.goto(_admin_url(admin_base, "/admin/memory-shell"))
    panel = page.locator("#memory-shell-panel")
    shop_site = panel.locator("tr").filter(has_text="Shop test site")
    page.once("dialog", lambda dialog: dialog.accept())
    shop_site.get_by_role("button", name="Probe Memory Shell").click()
    expect(panel).to_contain_text("Failed", timeout=15000)
    expect(panel).to_contain_text("probe HTTP 502", timeout=15000)

    page.goto(shop_target.url)
    expect(page.get_by_text("configured HTTP 502")).to_be_visible()
