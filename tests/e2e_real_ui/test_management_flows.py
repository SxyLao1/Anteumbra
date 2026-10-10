"""Real business workflows driven by visible forms, buttons and downloads only."""
from urllib.parse import urlsplit

from playwright.sync_api import expect


def open_page(page, path):
    """A user bookmark navigation, never a business API request."""
    origin = urlsplit(page.url)
    page.goto(f"{origin.scheme}://{origin.netloc}/admin/{path}")
    expect(page.locator("#main-content")).to_be_visible()


def download_text(page, button):
    with page.expect_download() as pending:
        button.click()
    return pending.value.path().read_text(encoding="utf-8-sig")


def test_config_three_views_validation_save_backup_restore(real_instance):
    page, _, _ = real_instance
    open_page(page, "config?view=raw")
    raw = page.locator("textarea[name=raw_text]")
    baseline = raw.input_value()
    raw.fill(baseline + "\n[acceptance_note]\ntext = 'browser-saved'\n")
    page.get_by_role("button", name="Review raw changes", exact=True).click()
    result = page.locator("#ce-result")
    expect(result).to_contain_text("acceptance_note.text")
    result.get_by_role("button", name="Confirm save", exact=True).click()
    expect(result).to_contain_text("written")
    # A real browser reload must see the persisted document.
    page.reload()
    expect(raw).to_have_value(baseline + "\n[acceptance_note]\ntext = 'browser-saved'\n")
    page.get_by_role("button", name="Form", exact=True).click()
    page.get_by_placeholder("Search keys, values and comments...").fill("acceptance_note")
    row = page.locator('.ce-row[data-path="acceptance_note.text"]')
    expect(row).to_be_visible()
    row.locator("input.ce-value").fill('"second-value"')
    row.get_by_role("button", name="Review change", exact=True).click()
    expect(result).to_contain_text("second-value")
    result.get_by_role("button", name="Confirm save", exact=True).click()
    expect(result).to_contain_text("written")
    page.get_by_role("button", name="Tree", exact=True).click()
    expect(page.locator("#ce-list")).to_contain_text("acceptance_note")
    page.get_by_role("tab", name="History", exact=True).click()
    history = page.locator("#ce-history")
    revision = history.locator("tbody tr").filter(has=page.get_by_role("button", name="Restore", exact=True)).first
    revision.get_by_role("button", name="View diff", exact=True).click()
    expect(result).to_contain_text("acceptance_note")
    assert "acceptance_note" in download_text(page, revision.get_by_role("link", name="Download", exact=True))
    page.once("dialog", lambda dialog: dialog.accept())
    revision.get_by_role("button", name="Restore", exact=True).click()
    expect(result).to_contain_text("written")
    open_page(page, "config?view=raw")
    expect(raw).to_contain_text("browser-saved")


def test_rules_upload_edit_selection_and_delete(real_instance):
    page, _, _ = real_instance
    open_page(page, "yara/rules")
    page.get_by_role("button", name="[+] Upload", exact=True).click()
    page.locator("#yara-file-input").set_input_files({
        "name": "browser_acceptance.yar", "mimeType": "text/plain",
        "buffer": b'rule BrowserAcceptance { strings: $m = "BROWSER_RULE_ONLY" condition: $m }',
    })
    page.locator("#yara-upload-btn").click()
    row = page.locator('article[data-filename="browser_acceptance.yar"]')
    expect(row).to_be_visible()
    row.get_by_role("button", name="Edit", exact=True).click()
    modal = page.locator("#yara-edit-modal")
    expect(modal).to_contain_text("BrowserAcceptance")
    page.keyboard.press("Escape")
    row.locator("input.yara-checkbox").check()
    expect(page.locator("#yara-selected-count")).to_contain_text("1")
    page.locator("#yara-deselect-btn").click()
    expect(row.locator("input.yara-checkbox")).not_to_be_checked()
    row.locator("input.yara-checkbox").check()
    page.once("dialog", lambda dialog: dialog.accept())
    page.locator("#yara-batch-delete-btn").click()
    expect(row).to_have_count(0)
    page.reload()
    expect(row).to_have_count(0)


def test_scanner_real_completion_history_and_failed_path(real_instance):
    page, portal, _ = real_instance
    (portal / "scan-clean.txt").write_text("safe ordinary text", encoding="utf-8")
    open_page(page, "scanner?site=portal")
    page.locator("#scan-target-dir").fill(str(portal))
    page.locator("#scan-extensions").fill(".txt")
    page.locator("#scan-start-btn").click()
    expect(page.get_by_test_id("scan-status")).to_have_attribute("data-state", "completed", timeout=30000)
    expect(page.locator("#scan-progress-text")).to_contain_text("1 / 1")
    expect(page.locator("#scan-history-list")).to_contain_text(str(portal))
    page.locator("#scan-target-dir").fill(str(portal / "missing-directory"))
    page.locator("#scan-start-btn").click()
    expect(page.get_by_test_id("scan-status")).to_have_attribute("data-state", "failed", timeout=30000)
    expect(page.locator("#scan-progress-text")).to_contain_text("missing-directory")


def test_sites_settings_plugins_and_maintenance_are_real_pages(real_instance):
    page, portal, shop = real_instance
    open_page(page, "sites")
    expect(page.locator('[data-managed-site="portal"]')).to_contain_text(str(portal))
    expect(page.locator('[data-managed-site="shop"]')).to_contain_text(str(shop))
    page.locator('[data-managed-site="portal"]').get_by_role("link", name="Configuration", exact=True).click()
    expect(page.locator('[data-settings-panel="sites"] .card-body')).to_be_visible()
    open_page(page, "settings?open=plugins,notifications,storage,account")
    expect(page.locator("[data-plugin-panel]")).to_contain_text("stdout_logger")
    expect(page.locator("#settings-notify")).to_contain_text("Webhook")
    expect(page.locator('[data-settings-panel="account"] > .card-body')).to_be_visible()
    open_page(page, "system")
    for selector in ("#system-registry-panel", "#system-wal-panel", "#system-session-panel", "#system-config-panel"):
        expect(page.locator(selector)).not_to_contain_text("Loading...", timeout=10000)
    for action in ("Compact", "Replay", "Cleanup"):
        page.once("dialog", lambda dialog: dialog.accept())
        page.get_by_role("button", name=action, exact=True).click()
    page.reload()
    expect(page.locator("#system-registry-panel")).to_be_visible()


def test_site_manager_adds_and_edits_site_paths_and_access_logs(real_instance):
    """The site page must own the common add/edit path, without raw TOML work."""
    page, portal, _ = real_instance
    root = portal.parent
    blog = root / "blog"
    blog.mkdir()
    blog_log = root / "test-inputs" / "blog-access.log"
    blog_log.parent.mkdir(exist_ok=True)
    blog_log.touch()

    open_page(page, "sites")
    expect(page.get_by_test_id("site-management")).to_be_visible()
    page.get_by_test_id("add-site").click()
    expect(page.get_by_test_id("site-editor")).to_be_visible()
    page.get_by_test_id("site-name").fill("Blog test site")
    page.get_by_test_id("site-id").fill("blog")
    page.get_by_test_id("site-path").fill(str(blog))
    page.get_by_test_id("site-port").fill("18082")
    page.get_by_test_id("site-log-path").fill(str(blog_log))
    page.get_by_test_id("site-log-enabled").check()
    page.get_by_test_id("review-site-save").click()
    result = page.locator("#ce-result")
    expect(result).to_contain_text("website")
    result.get_by_role("button").click()
    expect(result).to_contain_text("written")

    page.goto(f"{page.url.split('/admin/')[0]}/admin/sites")
    blog_card = page.locator('[data-managed-site="blog"]')
    expect(blog_card).to_contain_text(str(blog))
    expect(blog_card).to_contain_text(str(blog_log))

    updated_root = root / "portal-updated"
    updated_root.mkdir()
    updated_log = root / "test-inputs" / "portal-updated-access.log"
    updated_log.touch()
    page.locator('[data-managed-site="portal"]').get_by_test_id("edit-site-portal").click()
    expect(page.get_by_test_id("site-editor")).to_be_visible()
    page.get_by_test_id("site-path").fill(str(updated_root))
    page.get_by_test_id("site-log-path").fill(str(updated_log))
    page.get_by_test_id("site-log-enabled").check()
    page.get_by_test_id("review-site-save").click()
    result.get_by_role("button").click()
    expect(result).to_contain_text("written")

    page.goto(f"{page.url.split('/admin/')[0]}/admin/sites")
    portal_card = page.locator('[data-managed-site="portal"]')
    expect(portal_card).to_contain_text(str(updated_root))
    expect(portal_card).to_contain_text(str(updated_log))
