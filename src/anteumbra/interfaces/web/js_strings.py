# -*- coding: utf-8 -*-
"""Source strings the JS modules render, translated per request.

Frontend modules build table rows, buttons and status text themselves, so the
shell ships them a source->translation map.  Calling ``gettext`` at import time
would freeze the language of the first request, so the map is resolved inside
each request; ``_extraction_only`` exists purely so ``pybabel extract`` can see
the literals (extraction never executes the module).

``JS_SOURCES`` and ``_extraction_only`` must stay in sync; the test suite
compares them against each other and against the ``app.t('...')`` literals that
actually appear in ``static/js``.
"""

from __future__ import annotations

from flask_babel import gettext as _

# Strings referenced by static/js/**/*.js through app.t('...').
JS_SOURCES: tuple[str, ...] = (
    # scanner: result rows, history grid, statuses
    "Scan", "Started", "Target", "Coverage", "New", "Known", "Clean", "Errors", "Took",
    "View", "Report", "Source", "Detail", "Select All", "Clear", "Quarantine Selected",
    "Generate Report", "Loading results...", "Loading history...", "No scan history yet.",
    "Failed to load history.", "Completed", "Running", "Stopped", "Failed",
    "Please enter a target directory.", "Quarantine %(count)s selected files?",
    "Done: %(count)s quarantined",
    # log analyzer
    "Lines scanned", "Matched filters", "Errors + Critical", "Detection hits", "Level",
    "Module", "Keyword", "Rows", "All levels", "All modules", "Hits only", "Apply / Refresh",
    "Live tail", "Reset filters", "Access log analysis", "Export JSON", "Export CSV",
    "Time range", "Custom", "From", "To", "Ready", "Loading...", "Updated",
    "Live tail connected", "Live tail stopped", "Live tail reconnecting...", "SSE token missing",
    "No log lines match the current filters.", "No time-bucketed data.", "lines", "errors",
    "buckets", "per bucket", "%(count)s buckets", "%(count)s lines", "%(count)s errors",
    "%(lines)s lines · %(errors)s errors · peak %(peak)s per bucket",
    "showing the newest %(shown)s of %(total)s matches",
    "%(count)s undated lines hidden by the time filter",
    "Failed: %(message)s", "Exported %(count)s lines as %(format)s",
    # shared actions, states, toasts
    "Copy", "Close", "Wrap", "Unwrap", "Line copied", "Source copied.", "Mark FP", "Clear FP",
    "Marked as false positive.", "False positive cleared.", "Active", "Quarantined", "Deleted",
    "Delete", "Restore", "Quarantine", "Mark as FP", "%(count)s selected",
    "Selection metadata is invalid.", "IP selection metadata is invalid.",
    "%(action)s %(count)s records?", "%(action)s %(count)s quarantine records?",
    "Done: %(success)s success, %(skipped)s skipped, %(failed)s failed",
    "Done: %(success)s success, %(failed)s failed", "Batch failed: %(message)s",
    "Reload failed: %(message)s", "Review failed: %(message)s", "Filter failed: %(message)s",
    # profiles / IP reputation
    "Clipboard access is unavailable.", "Copied.", "Copy failed.", "Block Selected IPs",
    "Block %(count)s IPs?", "... and %(count)s more", "OK: ", "FAIL: ", "Blocked",
    "Block failed: %(message)s", "Block status unavailable: %(message)s",
    # yara rules
    "Only .yar files are allowed.", "Upload successful",
    "Delete %(count)s selected rule(s)?", "Rule deletion failed: %(message)s",
    # settings
    "Enter a password first.", "Reload config?", "export file",
    "Exported %(count)s events (CEF)", "Exported %(count)s events to %(file)s",
    "SIEM export failed: %(message)s", "%(total)s total / %(active)s active",
    # blocklist ledger
    "No block records found.", "Prev", "Next",
    "Page %(page)s / %(total_pages)s (%(total)s total)",
    # SSE indicator + block status bar
    "Connected", "Disconnected", "Auto: OFF", "Auto: ON (>%(score)s%%)", "Devices: %(count)s",
    "Queue: %(count)s", "Blocked: %(count)s",
    # clusters
    "Expand all", "Collapse all", "Filter by cluster id, file name or path...",
    "No cluster matches the filter",
    # source viewer
    "%(size)s | %(lines)s lines",
    # session expiry prompt
    "Session expired", "Your session has expired. Please sign in again.", "Sign in again",
    # shell
    "Chinese", "English", "Language",
)


def js_strings() -> dict[str, str]:
    """Resolve every JS-facing string in the request's active locale."""
    return {text: _(text) for text in JS_SOURCES}


def _extraction_only() -> tuple[str, ...]:
    """Unused at runtime: keeps the literals visible to ``pybabel extract``."""
    return (
        # scanner
        _("Scan"), _("Started"), _("Target"), _("Coverage"), _("New"), _("Known"),
        _("Clean"), _("Errors"), _("Took"), _("View"), _("Report"), _("Source"),
        _("Detail"), _("Select All"), _("Clear"), _("Quarantine Selected"),
        _("Generate Report"), _("Loading results..."), _("Loading history..."),
        _("No scan history yet."), _("Failed to load history."), _("Completed"),
        _("Running"), _("Stopped"), _("Failed"), _("Please enter a target directory."),
        _("Quarantine %(count)s selected files?"), _("Done: %(count)s quarantined"),
        # log analyzer
        _("Lines scanned"), _("Matched filters"), _("Errors + Critical"), _("Detection hits"),
        _("Level"), _("Module"), _("Keyword"), _("Rows"), _("All levels"), _("All modules"),
        _("Hits only"), _("Apply / Refresh"), _("Live tail"), _("Reset filters"),
        _("Access log analysis"), _("Export JSON"), _("Export CSV"), _("Time range"),
        _("Custom"), _("From"), _("To"), _("Ready"), _("Loading..."), _("Updated"),
        _("Live tail connected"), _("Live tail stopped"), _("Live tail reconnecting..."),
        _("SSE token missing"), _("No log lines match the current filters."),
        _("No time-bucketed data."), _("lines"), _("errors"), _("buckets"), _("per bucket"),
        _("%(count)s buckets"), _("%(count)s lines"), _("%(count)s errors"),
        _("%(lines)s lines · %(errors)s errors · peak %(peak)s per bucket"),
        _("showing the newest %(shown)s of %(total)s matches"),
        _("%(count)s undated lines hidden by the time filter"), _("Failed: %(message)s"),
        _("Exported %(count)s lines as %(format)s"),
        # shared actions, states, toasts
        _("Copy"), _("Close"), _("Wrap"), _("Unwrap"), _("Line copied"), _("Source copied."),
        _("Mark FP"), _("Clear FP"), _("Marked as false positive."),
        _("False positive cleared."), _("Active"), _("Quarantined"), _("Deleted"),
        _("Delete"), _("Restore"), _("Quarantine"), _("Mark as FP"), _("%(count)s selected"),
        _("Selection metadata is invalid."), _("IP selection metadata is invalid."),
        _("%(action)s %(count)s records?"), _("%(action)s %(count)s quarantine records?"),
        _("Done: %(success)s success, %(skipped)s skipped, %(failed)s failed"),
        _("Done: %(success)s success, %(failed)s failed"), _("Batch failed: %(message)s"),
        _("Reload failed: %(message)s"), _("Review failed: %(message)s"),
        _("Filter failed: %(message)s"),
        # profiles / IP reputation
        _("Clipboard access is unavailable."), _("Copied."), _("Copy failed."),
        _("Block Selected IPs"), _("Block %(count)s IPs?"), _("... and %(count)s more"),
        _("OK: "), _("FAIL: "), _("Blocked"), _("Block failed: %(message)s"),
        _("Block status unavailable: %(message)s"),
        # yara rules
        _("Only .yar files are allowed."), _("Upload successful"),
        _("Delete %(count)s selected rule(s)?"), _("Rule deletion failed: %(message)s"),
        # settings
        _("Enter a password first."), _("Reload config?"), _("export file"),
        _("Exported %(count)s events (CEF)"), _("Exported %(count)s events to %(file)s"),
        _("SIEM export failed: %(message)s"), _("%(total)s total / %(active)s active"),
        # blocklist ledger
        _("No block records found."), _("Prev"), _("Next"),
        _("Page %(page)s / %(total_pages)s (%(total)s total)"),
        # SSE indicator + block status bar
        _("Connected"), _("Disconnected"), _("Auto: OFF"), _("Auto: ON (>%(score)s%%)"),
        _("Devices: %(count)s"), _("Queue: %(count)s"), _("Blocked: %(count)s"),
        # clusters
        _("Expand all"), _("Collapse all"), _("Filter by cluster id, file name or path..."),
        _("No cluster matches the filter"),
        # source viewer
        _("%(size)s | %(lines)s lines"),
        # session expiry prompt
        _("Session expired"), _("Your session has expired. Please sign in again."),
        _("Sign in again"),
        # shell
        _("Chinese"), _("English"), _("Language"),
    )


__all__ = ["JS_SOURCES", "js_strings"]
