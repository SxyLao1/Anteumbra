"""Browser regressions for YARA batch-operation failure semantics."""

from playwright.sync_api import expect


def test_yara_batch_delete_keeps_selection_when_a_delete_fails(page, runtime):
    filename = "anteumbra_batch_failure.yar"
    rule_file = runtime.yara_engine.rules_path / filename
    rule_file.parent.mkdir(parents=True, exist_ok=True)
    rule_file.write_text("rule anteumbra_batch_failure { condition: true }\n", encoding="utf-8")

    route_url = "**/admin/yara/rules/" + filename

    def fail_delete(route):
        if route.request.method == "DELETE":
            route.fulfill(
                status=500,
                content_type="application/json",
                body='{"error":"forced delete failure"}',
            )
            return
        route.continue_()

    try:
        page.click("a.nav-link[data-path='yara/rules']")
        checkbox = page.locator(f"input.yara-checkbox[data-filename='{filename}']")
        expect(checkbox).to_be_visible(timeout=10000)
        page.evaluate("window.confirm = () => true")
        page.route(route_url, fail_delete)
        checkbox.click()
        expect(page.locator("#yara-batch-delete-btn")).to_be_visible()
        page.locator("#yara-batch-delete-btn").click()

        expect(page.locator(".toast")).to_contain_text(
            "Rule deletion failed: forced delete failure", timeout=10000
        )
        assert page.evaluate("window.Anteumbra.module('yara').selectedRules().size") == 1
        expect(checkbox).to_be_checked()
    finally:
        page.unroute(route_url)
        rule_file.unlink(missing_ok=True)
