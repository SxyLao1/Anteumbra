# -*- coding: utf-8 -*-
"""The YARA toolbar must not move its buttons under the cursor.

Reported from real use: "select all" was clicked, and the second click in the
same place hit "delete selected" — because the toolbar swapped one button for
another in the same slot, and a few rounds of that deleted twenty rule files.
Controls now keep their positions and are disabled instead of hidden.
"""

from __future__ import annotations

import os
import re

import pytest

TOOLBAR_ORDER = (
    "yara-select-all-btn",
    "yara-batch-delete-btn",
    "yara-deselect-btn",
    "yara-selected-count",
    "yara-show-upload",
)


@pytest.fixture(scope="module")
def _app():
    os.environ.setdefault("ANTEUMBRA_TOOL_MODE", "true")

    from anteumbra.interfaces.web.factory import create_app

    app = create_app()
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False
    return app


@pytest.fixture
def toolbar(_app):
    with _app.test_client() as client:
        with client.session_transaction() as flask_session:
            flask_session["authenticated"] = True
            flask_session["username"] = "admin"
        body = client.get("/admin/yara/rules").get_data(as_text=True)
    section = body.split('class="batch-toolbar"', 1)[-1].split("</div>", 1)[0]
    return section


def _position(section: str, control_id: str) -> int:
    if control_id == "yara-show-upload":
        return section.find('data-action="yara.show-upload"')
    return section.find(f'id="{control_id}"')


def test_selection_controls_keep_their_order(toolbar):
    positions = [_position(toolbar, control) for control in TOOLBAR_ORDER]

    assert all(position >= 0 for position in positions), (toolbar, positions)
    assert positions == sorted(positions), (
        "the toolbar order changed; a control may have moved under the cursor"
    )


def test_destructive_controls_start_disabled_not_hidden(toolbar):
    for control in ("yara-batch-delete-btn", "yara-deselect-btn"):
        tag = toolbar.split(f'id="{control}"', 1)[-1].split(">", 1)[0]
        assert "disabled" in tag, f"{control} must start disabled: {tag}"
        assert "hidden" not in tag, f"{control} must not be hidden: {tag}"


def test_the_count_sits_beside_the_controls_it_describes(toolbar):
    count = re.search(r'id="yara-selected-count"[^>]*>([^<]*)<', toolbar)

    assert count, toolbar
    assert count.group(1).strip() == "0 selected", count.group(1)
    assert "hidden" not in count.group(0), "the count must always be visible"


def test_the_clear_button_says_what_it_clears(_app):
    with _app.test_request_context("/admin/yara/rules?lang=zh"):
        from flask_babel import gettext

        assert gettext("Clear selection") == "清除选中"
        assert gettext("%(count)s selected", count=3) == "3 项"
