"""Browser-visible investigation workflow against the isolated real runtime."""
from __future__ import annotations

import re
from urllib.parse import parse_qs, urlsplit

from playwright.sync_api import Page, expect

from .test_management_flows import download_text, open_page


def _wait_for_text(page: Page, selector: str, text: str, attempts: int = 15) -> None:
    """Refresh a user-facing page while its asynchronous intake catches up."""
    for _ in range(attempts):
        if text.lower() in page.locator(selector).inner_text().lower():
            return
        page.wait_for_timeout(1000)
        page.reload()
    expect(page.locator(selector)).to_contain_text(text, ignore_case=True)


def _generate_portal_waf_events(page: Page, external_lab) -> Page:
    lab_page = page.context.new_page()
    lab_page.goto(external_lab.url)
    lab_page.get_by_role("button", name="Generate Portal WAF events").click()
    expect(lab_page.locator("#event-count")).to_have_text("12 WAF events")
    return lab_page


def test_investigation_profile_block_and_cluster_quarantine(real_instance, external_lab):
    """Follow the operator workflow through visible pages and a real receiver."""
    page, portal, _ = real_instance
    lab_page = _generate_portal_waf_events(page, external_lab)
    try:
        # The profile is created by the running WAF source, then found using the
        # visible search and sort controls in the portal scope.
        open_page(page, "profiles?site=portal")
        _wait_for_text(page, "#main-content", "sqlmap")
        search = page.locator('input[name="q"]')
        search.fill("sqlmap")
        search.press("End")
        search.press("Space")
        search.press("Backspace")
        expect(page.locator("#profiles-list")).to_contain_text("sqlmap", ignore_case=True)
        page.get_by_role("button", name="Risk", exact=True).click()
        expect(page.locator("#profiles-list")).to_contain_text("sqlmap", ignore_case=True)

        card = page.locator(".profile-card").filter(has_text="sqlmap").first
        expect(card).to_be_visible()
        card.click()
        detail = page.locator(".profile-detail-view")
        expect(detail).to_have_attribute("data-site-id", "portal")
        profile_id = detail.locator(".profile-summary-grid code").first.inner_text()
        expect(detail).to_contain_text("sqlmap", ignore_case=True)

        # Report and copy are both browser actions; its report URL retains the
        # profile's site even when the shell's remembered scope changes later.
        with page.expect_popup() as report_pending:
            page.get_by_role("button", name="Generate Report", exact=True).click()
        report = report_pending.value
        report.wait_for_load_state()
        assert parse_qs(urlsplit(report.url).query).get("site") == ["portal"]
        expect(report.locator("body")).to_contain_text(profile_id)
        report.close()

        page.context.grant_permissions(["clipboard-read", "clipboard-write"], origin=urlsplit(page.url).scheme + "://" + urlsplit(page.url).netloc)
        page.get_by_role("button", name="Copy All", exact=True).click()
        expect(page.locator(".toast")).to_contain_text("Copied.")

        ip_checkbox = detail.locator(".ip-checkbox").first
        ip_checkbox.check()
        expect(page.locator("#ip-selected-count")).to_contain_text("1 selected")
        page.get_by_role("button", name="Block 1 IP(s)", exact=True).click()
        expect(page).to_have_url(re.compile(r".*/admin/blocklist\?.+"))
        query = parse_qs(urlsplit(page.url).query)
        assert query.get("site") == ["portal"]
        assert query.get("profile_id") == [profile_id]
        expect(page.locator("#bl-target-site")).to_have_value("portal")
        expect(page.locator("#bl-ip-input")).to_have_value("198.51.100.24")
        page.locator("#bl-ip-input").fill("")
        page.locator("#bl-ip-input").press("ControlOrMeta+V")
        expect(page.locator("#bl-ip-input")).to_have_value("198.51.100.24")

        page.get_by_role("button", name="Device A", exact=True).click()
        page.once("dialog", lambda dialog: dialog.accept())
        page.get_by_role("button", name="Block", exact=True).click()
        expect(page.locator("#bl-result")).to_contain_text("OK Device A", timeout=15000)
        ledger_row = page.locator("#ledger-tbody tr").filter(has_text="198.51.100.24")
        expect(ledger_row).to_contain_text("Portal test site")

        assert profile_id in download_text(page, page.get_by_role("button", name="Export JSON", exact=True))
        lab_page.get_by_role("link", name="Refresh receipts").click()
        expect(lab_page.locator("tbody")).to_contain_text("profile: " + profile_id[:8])
        expect(lab_page.locator("tbody")).to_contain_text('"site_id": "portal"')

        # Inject only harmless test markers. Detection, grouping, source/detail
        # and quarantine are then all entered through the product UI.
        marker = "<?php /* ANTEUMBRA_E2E_MARKER */ ?>\n"
        (portal / "cluster-marker-a.php").write_text(marker, encoding="utf-8")
        (portal / "cluster-marker-b.php").write_text(marker, encoding="utf-8")
        open_page(page, "threats?site=portal")
        _wait_for_text(page, "#main-content", "cluster-marker-a.php")

        open_page(page, "file-clusters?site=portal")
        _wait_for_text(page, "#main-content", "cluster-marker-a.php")
        page.locator("#clusters-search").fill("cluster-marker-a.php")
        expect(page.locator("#clusters-visible")).to_contain_text("1 /", timeout=10000)
        page.get_by_role("button", name="Expand all", exact=True).click()
        member = page.locator(".cluster-file").filter(has_text="cluster-marker-a.php")
        expect(member).to_have_attribute("data-site-id", "portal")
        member.get_by_role("button", name="Source", exact=True).click()
        expect(page.locator("#file-viewer-modal")).to_contain_text("ANTEUMBRA_E2E_MARKER")
        page.locator("#file-viewer-modal [data-action=\"records.file-close\"]").click()
        member.get_by_role("button", name="Detail", exact=True).click()
        expect(page.locator("#record-detail-modal")).to_contain_text("cluster-marker-a.php")
        expect(page.locator("#record-detail-modal")).to_contain_text("Portal test site")
        page.locator("#record-detail-modal [data-action=\"records.detail-close\"]").click()

        open_page(page, "threats?site=portal")
        _wait_for_text(page, "#main-content", "cluster-marker-a.php")
        record = page.locator(".record-item").filter(has_text="cluster-marker-a.php")
        expect(record).to_have_attribute("data-site-id", "portal")
        record.locator(".rec-checkbox").check()
        page.once("dialog", lambda dialog: dialog.accept())
        page.get_by_role("button", name="Quarantine", exact=True).click()
        expect(page.locator("#records-batch-results")).to_contain_text("Succeeded", timeout=15000)
        expect(page.locator("#records-batch-results")).to_contain_text("cluster-marker-a.php")

        open_page(page, "quarantine?site=portal")
        expect(page.locator(".quarantine-list")).to_contain_text("cluster-marker-a.php", timeout=15000)
        open_page(page, "quarantine?site=shop")
        expect(page.locator(".quarantine-list")).not_to_contain_text("cluster-marker-a.php")
    finally:
        lab_page.close()
