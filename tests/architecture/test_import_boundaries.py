"""Architecture boundary tests for the modular-monolith dependency rules."""

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


def _packaged_text_files() -> Iterable[Path]:
    suffixes = {".css", ".html", ".js", ".py", ".toml"}
    for path in PACKAGE_ROOT.rglob("*"):
        if (
            path.is_file()
            and path.suffix in suffixes
            and "__pycache__" not in path.parts
            and "rules" not in path.parts
        ):
            yield path


def _internal_import_edges() -> list[ImportEdge]:
    return [edge for edge in _import_edges() if edge.imported.startswith("anteumbra")]


def _format_edges(edges: Iterable[ImportEdge]) -> str:
    return "\n".join(
        f"{edge.source}:{edge.line}: {edge.imported}" for edge in sorted(
            edges, key=lambda item: (item.source, item.line, item.imported)
        )
    )


# The launcher is the composition root and may start the web interface.
KNOWN_APPLICATION_TO_INTERFACES: set[tuple[str, str]] = {
    ("application/launcher.py", "anteumbra.interfaces.web.factory"),
}


KNOWN_LEGACY_BRANDING_LINES: set[tuple[str, str]] = {
    (
        "interfaces/web/factory.py",
        "重命名 trident_ → anteumbra_ 保持模板兼容",
    ),
    (
        "interfaces/web/static/js/sse-manager.js",
        "window.TridentSSEManager = window.AnteumbraSSEManager;",
    ),
    (
        "interfaces/web/static/js/utils.js",
        "window.TridentUtils = AnteumbraUtils;",
    ),
}


DEPRECATED_GLOBAL_SERVICE_MODULES = {
    PACKAGE_ROOT / "application" / "registry_service.py",
    PACKAGE_ROOT / "application" / "sse_service.py",
    PACKAGE_ROOT / "application" / "wal_service.py",
    PACKAGE_ROOT / "infrastructure" / "registry_adapter.py",
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


def test_deprecated_global_service_modules_are_removed():
    remaining = sorted(
        path.relative_to(PROJECT_ROOT).as_posix()
        for path in DEPRECATED_GLOBAL_SERVICE_MODULES
        if path.exists()
    )
    assert not remaining, (
        "runtime-owned services must not regain module-global compatibility facades:\n"
        + "\n".join(remaining)
    )


def test_persistence_instances_are_owned_by_the_composition_root():
    persistence_init = PACKAGE_ROOT / "infrastructure" / "persistence" / "__init__.py"
    source = persistence_init.read_text(encoding="utf-8")
    assert "_repo_cache" not in source
    assert "get_repository" not in source
    assert "get_shadow_repository" not in source


def test_notifier_has_no_process_global_factory():
    notifier = PACKAGE_ROOT / "infrastructure" / "monitoring" / "notifier.py"
    source = notifier.read_text(encoding="utf-8")
    assert "_notifier_instance" not in source
    assert "def get_notifier(" not in source


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


def test_interfaces_do_not_import_infrastructure():
    violations = [
        edge
        for edge in _internal_import_edges()
        if edge.source_layer == "interfaces"
        and edge.imported_layer == "infrastructure"
    ]
    assert not violations, (
        "interfaces must depend on application/domain, not infrastructure. "
        "Route access through an application service:\n"
        + _format_edges(violations)
    )


def test_infrastructure_does_not_import_plugin_manager():
    violations = [
        edge
        for edge in _internal_import_edges()
        if edge.source_layer == "infrastructure"
        and edge.imported == "anteumbra.application.plugin_manager"
    ]
    assert not violations, (
        "infrastructure should not import PluginManager directly. "
        "Use an EventPublisher port supplied by the composition root:\n"
        + _format_edges(violations)
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


def test_packaged_code_has_no_unscoped_legacy_branding():
    violations: list[str] = []
    for path in _packaged_text_files():
        rel = path.relative_to(PACKAGE_ROOT).as_posix()
        for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if "Trident" not in line and "trident_" not in line:
                continue
            if any(rel == allowed_path and allowed_text in line for allowed_path, allowed_text in KNOWN_LEGACY_BRANDING_LINES):
                continue
            violations.append(f"{rel}:{line_no}: {line.strip()}")

    assert not violations, (
        "legacy Trident naming must stay inside explicit compatibility shims:\n"
        + "\n".join(violations)
    )


def test_dashboard_initial_version_uses_package_version_context():
    dashboard = PACKAGE_ROOT / "interfaces" / "web" / "templates" / "admin" / "dashboard.html"
    source = dashboard.read_text(encoding="utf-8")
    assert 'class="brand-sub">v{{ anteumbra_version }}</span>' in source
    assert 'class="brand-sub">v1.' not in source


def test_pypi_publish_workflow_uses_trusted_publishing_environment():
    workflow = PROJECT_ROOT / ".github" / "workflows" / "publish.yml"
    source = workflow.read_text(encoding="utf-8")
    assert "id-token: write" in source
    assert "environment: pypi" in source
    assert "pypa/gh-action-pypi-publish@release/v1" in source
