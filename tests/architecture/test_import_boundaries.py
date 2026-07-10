"""Architecture boundary tests.

These tests intentionally use a ratchet model:
current migration debt is listed in allowlists, while new violations fail.
When a dependency is cleaned up, remove it from the relevant allowlist.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

PROJECT_ROOT = Path(__file__).resolve().parents[2]
PACKAGE_ROOT = PROJECT_ROOT / "src" / "anteumbra"


@dataclass(frozen=True)
class ImportEdge:
    source: str
    line: int
    imported: str

    @property
    def source_layer(self) -> str:
        return self.source.split("/", 1)[0]

    @property
    def imported_layer(self) -> str:
        parts = self.imported.split(".")
        if len(parts) < 2 or parts[0] != "anteumbra":
            return "external"
        return parts[1]

    @property
    def key(self) -> tuple[str, str]:
        return self.source, self.imported


def _import_edges() -> list[ImportEdge]:
    edges: list[ImportEdge] = []
    for path in _python_files():
        rel = path.relative_to(PACKAGE_ROOT).as_posix()
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))

        for node in ast.walk(tree):
            imported_modules: list[str] = []
            if isinstance(node, ast.Import):
                imported_modules = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported_modules = [node.module]

            for module in imported_modules:
                edges.append(ImportEdge(rel, node.lineno, module))
    return edges


def _python_files() -> Iterable[Path]:
    for path in PACKAGE_ROOT.rglob("*.py"):
        if "__pycache__" not in path.parts:
            yield path


def _internal_import_edges() -> list[ImportEdge]:
    return [edge for edge in _import_edges() if edge.imported.startswith("anteumbra")]


def _format_edges(edges: Iterable[ImportEdge]) -> str:
    return "\n".join(
        f"{edge.source}:{edge.line}: {edge.imported}" for edge in sorted(
            edges, key=lambda item: (item.source, item.line, item.imported)
        )
    )


# Known migration debt. The rule is no new direct web -> infrastructure imports.
# Prefer application services for config/path/storage/monitoring access.
KNOWN_INTERFACES_TO_INFRASTRUCTURE: set[tuple[str, str]] = {
    ("interfaces/web/auth.py", "anteumbra.infrastructure.config.registry"),
    ("interfaces/web/factory.py", "anteumbra.infrastructure.config.registry"),
    ("interfaces/web/factory.py", "anteumbra.infrastructure.utils.path_utils"),
    ("interfaces/web/blueprints/_shared.py", "anteumbra.infrastructure.config.registry"),
    ("interfaces/web/blueprints/_shared.py", "anteumbra.infrastructure.utils.path_utils"),
    ("interfaces/web/blueprints/admin_bp.py", "anteumbra.infrastructure.config.registry"),
    ("interfaces/web/blueprints/admin_bp.py", "anteumbra.infrastructure.utils.path_utils"),
    ("interfaces/web/blueprints/metrics.py", "anteumbra.infrastructure.config.registry"),
    ("interfaces/web/blueprints/metrics.py", "anteumbra.infrastructure.utils.path_utils"),
    ("interfaces/web/blueprints/monitor_bp.py", "anteumbra.infrastructure.config.registry"),
    ("interfaces/web/blueprints/monitor_bp.py", "anteumbra.infrastructure.utils.path_utils"),
    ("interfaces/web/blueprints/profiles_bp.py", "anteumbra.infrastructure.utils.path_utils"),
    ("interfaces/web/blueprints/quarantine_bp.py", "anteumbra.infrastructure.config.registry"),
    ("interfaces/web/blueprints/records_bp.py", "anteumbra.infrastructure.config.registry"),
    ("interfaces/web/blueprints/records_bp.py", "anteumbra.infrastructure.utils.path_utils"),
    ("interfaces/web/blueprints/scanner_bp.py", "anteumbra.infrastructure.config.registry"),
    ("interfaces/web/blueprints/scanner_bp.py", "anteumbra.infrastructure.utils.path_utils"),
    ("interfaces/web/blueprints/settings_bp.py", "anteumbra.infrastructure.config.registry"),
    ("interfaces/web/blueprints/system_bp.py", "anteumbra.infrastructure.config.registry"),
    ("interfaces/web/blueprints/yara_bp.py", "anteumbra.infrastructure.config.registry"),
    ("interfaces/web/blueprints/yara_bp.py", "anteumbra.infrastructure.utils.path_utils"),
}


# Known migration debt. Infrastructure should receive an event publisher port
# instead of importing the application PluginManager directly.
KNOWN_INFRASTRUCTURE_TO_PLUGIN_MANAGER: set[tuple[str, str]] = {
    ("infrastructure/block_ledger.py", "anteumbra.application.plugin_manager"),
    ("infrastructure/monitoring/monitor.py", "anteumbra.application.plugin_manager"),
    ("infrastructure/suspicious_registry.py", "anteumbra.application.plugin_manager"),
    ("infrastructure/wal_manager.py", "anteumbra.application.plugin_manager"),
}


# The launcher is the composition root and may start the web interface.
KNOWN_APPLICATION_TO_INTERFACES: set[tuple[str, str]] = {
    ("application/launcher.py", "anteumbra.interfaces.web.factory"),
}


def test_domain_layer_has_no_outward_dependencies():
    violations = [
        edge
        for edge in _internal_import_edges()
        if edge.source_layer == "domain"
        and edge.imported_layer
        in {"application", "infrastructure", "interfaces", "plugins", "cli"}
    ]
    assert not violations, "domain layer must not import outer layers:\n" + _format_edges(violations)


def test_packaged_code_does_not_import_top_level_tools():
    violations = [
        edge
        for edge in _import_edges()
        if edge.imported == "tools" or edge.imported.startswith("tools.")
    ]
    assert not violations, (
        "packaged runtime code must not import repository-local tools modules. "
        "Move reusable behavior into anteumbra.application or anteumbra.infrastructure:\n"
        + _format_edges(violations)
    )


def test_interfaces_do_not_add_new_direct_infrastructure_imports():
    violations = [
        edge
        for edge in _internal_import_edges()
        if edge.source_layer == "interfaces"
        and edge.imported_layer == "infrastructure"
        and edge.key not in KNOWN_INTERFACES_TO_INFRASTRUCTURE
    ]
    assert not violations, (
        "interfaces must depend on application/domain, not infrastructure. "
        "Route new access through an application service, or document existing debt "
        "in KNOWN_INTERFACES_TO_INFRASTRUCTURE:\n"
        + _format_edges(violations)
    )


def test_known_interfaces_to_infrastructure_debt_still_matches_reality():
    actual = {
        edge.key
        for edge in _internal_import_edges()
        if edge.source_layer == "interfaces" and edge.imported_layer == "infrastructure"
    }
    stale_allowlist = KNOWN_INTERFACES_TO_INFRASTRUCTURE - actual
    assert not stale_allowlist, (
        "remove cleaned-up web -> infrastructure imports from the allowlist:\n"
        + "\n".join(f"{source}: {imported}" for source, imported in sorted(stale_allowlist))
    )


def test_infrastructure_does_not_add_new_plugin_manager_imports():
    violations = [
        edge
        for edge in _internal_import_edges()
        if edge.source_layer == "infrastructure"
        and edge.imported == "anteumbra.application.plugin_manager"
        and edge.key not in KNOWN_INFRASTRUCTURE_TO_PLUGIN_MANAGER
    ]
    assert not violations, (
        "infrastructure should not import PluginManager directly. "
        "Use an EventPublisher port/facade instead, or document existing debt "
        "in KNOWN_INFRASTRUCTURE_TO_PLUGIN_MANAGER:\n"
        + _format_edges(violations)
    )


def test_known_infrastructure_plugin_manager_debt_still_matches_reality():
    actual = {
        edge.key
        for edge in _internal_import_edges()
        if edge.source_layer == "infrastructure"
        and edge.imported == "anteumbra.application.plugin_manager"
    }
    stale_allowlist = KNOWN_INFRASTRUCTURE_TO_PLUGIN_MANAGER - actual
    assert not stale_allowlist, (
        "remove cleaned-up infrastructure -> PluginManager imports from the allowlist:\n"
        + "\n".join(f"{source}: {imported}" for source, imported in sorted(stale_allowlist))
    )


def test_application_does_not_import_interfaces_except_composition_root():
    violations = [
        edge
        for edge in _internal_import_edges()
        if edge.source_layer == "application"
        and edge.imported_layer == "interfaces"
        and edge.key not in KNOWN_APPLICATION_TO_INTERFACES
    ]
    assert not violations, (
        "application services must not depend on interfaces. Keep interface startup "
        "inside the composition root:\n"
        + _format_edges(violations)
    )


def test_known_application_to_interfaces_debt_still_matches_reality():
    actual = {
        edge.key
        for edge in _internal_import_edges()
        if edge.source_layer == "application" and edge.imported_layer == "interfaces"
    }
    stale_allowlist = KNOWN_APPLICATION_TO_INTERFACES - actual
    assert not stale_allowlist, (
        "remove cleaned-up application -> interfaces imports from the allowlist:\n"
        + "\n".join(
            f"{source}: {imported}" for source, imported in sorted(stale_allowlist)
        )
    )
