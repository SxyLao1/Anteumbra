"""Keep the operator acceptance lane free of business API shortcuts."""

import ast
from pathlib import Path


def test_real_ui_scenarios_use_browser_actions_and_filesystem_stimuli_only():
    suite = Path(__file__).parents[1] / "e2e_real_ui"
    violations = []
    for path in suite.glob("test_*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                modules = (
                    [node.module or ""]
                    if isinstance(node, ast.ImportFrom)
                    else [item.name for item in node.names]
                )
                if any(
                    name.startswith(
                        ("anteumbra", "requests", "httpx", "urllib.request", "http.client")
                    )
                    for name in modules
                ):
                    violations.append(f"{path.name}:{node.lineno}: business/runtime client import")
            if isinstance(node, ast.Attribute) and node.attr in {
                "request",
                "evaluate",
                "evaluate_handle",
                "add_init_script",
                "route",
                "route_from_har",
                "add_cookies",
                "clear_cookies",
                "set_storage_state",
                "get_runtime",
            }:
                violations.append(
                    f"{path.name}:{node.lineno}: forbidden browser/runtime shortcut {node.attr}"
                )
    assert not violations, "\n".join(violations)
