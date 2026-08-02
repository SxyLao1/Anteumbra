"""Architecture boundary tests for the modular-monolith dependency rules."""

from __future__ import annotations

import ast
import re
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
        f"{edge.source}:{edge.line}: {edge.imported}"
        for edge in sorted(edges, key=lambda item: (item.source, item.line, item.imported))
    )


# The launcher is the composition root and may start the web interface.
KNOWN_APPLICATION_TO_INTERFACES: set[tuple[str, str]] = {
    ("application/runtime_builder.py", "anteumbra.interfaces.web.factory"),
}


KNOWN_LEGACY_BRANDING_LINES: set[tuple[str, str]] = {
    (
        "application/password_service.py",
        '"trident",  # Deprecated pre-rename default; remove after the 2.0 credential migration.',
    ),
    (
        "interfaces/web/static/js/sse-manager.js",
        "window.TridentSSEManager = window.AnteumbraSSEManager; // Deprecated: remove in 2.0 after legacy extensions migrate.",
    ),
    (
        "interfaces/web/static/js/utils.js",
        "window.TridentUtils = AnteumbraUtils; // Deprecated: remove in 2.0 after legacy extensions migrate.",
    ),
}


DEPRECATED_GLOBAL_SERVICE_MODULES = {
    PACKAGE_ROOT / "application" / "registry_service.py",
    PACKAGE_ROOT / "application" / "sse_service.py",
    PACKAGE_ROOT / "application" / "wal_service.py",
    PACKAGE_ROOT / "application" / "logging_service.py",
    PACKAGE_ROOT / "application" / "metrics_service.py",
    PACKAGE_ROOT / "infrastructure" / "config" / "registry.py",
    PACKAGE_ROOT / "infrastructure" / "utils" / "password_utils.py",
    PACKAGE_ROOT / "infrastructure" / "registry_adapter.py",
    PROJECT_ROOT / "tools" / "config_watcher_logger.py",
}


def test_domain_layer_has_no_outward_dependencies():
    violations = [
        edge
        for edge in _internal_import_edges()
        if edge.source_layer == "domain"
        and edge.imported_layer in {"application", "infrastructure", "interfaces", "plugins", "cli"}
    ]
    assert not violations, "domain layer must not import outer layers:\n" + _format_edges(
        violations
    )


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


def test_application_exports_are_importable():
    import importlib

    from anteumbra import application

    failures = []
    for module_name in application.__all__:
        try:
            importlib.import_module(f"anteumbra.application.{module_name}")
        except Exception as exc:
            failures.append(f"{module_name}: {type(exc).__name__}: {exc}")

    assert not failures, "public Application modules must import cleanly:\n" + "\n".join(failures)


def test_official_plugins_do_not_create_log_files_at_import_time():
    for filename in ("notifier_handler.py", "quarantine_handler.py"):
        source = (PACKAGE_ROOT / "plugins" / filename).read_text(encoding="utf-8")
        assert "RotatingFileHandler" not in source
        assert "plugins.log" not in source


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


def test_logging_is_owned_by_runtime_container():
    factory = PACKAGE_ROOT / "infrastructure" / "utils" / "logger_factory.py"
    source = factory.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(factory))
    module_functions = {node.name for node in tree.body if isinstance(node, ast.FunctionDef)}

    assert "ConfigRegistry" not in source
    assert {
        "get_logger",
        "get_access_logger",
        "get_application_logger",
        "close",
    }.isdisjoint(module_functions)
    assert "class RuntimeLoggerFactory" in source


def test_password_service_does_not_depend_on_infrastructure():
    violations = [
        edge
        for edge in _internal_import_edges()
        if edge.source == "application/password_service.py"
        and edge.imported_layer == "infrastructure"
    ]
    assert not violations, (
        "password operations must use the injected config port:\n" + _format_edges(violations)
    )


def test_runtime_workflow_state_has_no_module_global_factories():
    checks = {
        PACKAGE_ROOT / "application" / "launcher.py": (
            "_launcher_state",
            "_state_lock",
            "def start_all(",
            "def stop_all(",
            "def get_runtime_status(",
        ),
        PACKAGE_ROOT / "application" / "config_history_service.py": (
            "_history_logger",
            "get_config_history_logger",
            "get_config_watcher_logger",
        ),
        PACKAGE_ROOT / "infrastructure" / "detection" / "log_heuristic.py": (
            "_engine_instance",
            "get_log_heuristic_engine",
        ),
        PACKAGE_ROOT / "interfaces" / "web" / "blueprints" / "_shared.py": (
            "_scan_results_cache",
            "_cache_put",
            "_cache_get",
        ),
        PACKAGE_ROOT / "interfaces" / "web" / "blueprints" / "scanner_bp.py": (
            "_scan_jobs",
            "_scan_jobs_lock",
        ),
        PACKAGE_ROOT / "interfaces" / "web" / "blueprints" / "admin_bp.py": (
            "_login_attempts",
            "_login_lock",
            "_check_login_rate",
            "metrics._start_time",
        ),
    }
    violations: list[str] = []
    for path, forbidden in checks.items():
        source = path.read_text(encoding="utf-8")
        for token in forbidden:
            if token in source:
                violations.append(f"{path.relative_to(PROJECT_ROOT).as_posix()}: {token}")

    assert not violations, (
        "runtime workflow state must stay in RuntimeContainer-owned services:\n"
        + "\n".join(violations)
    )


def test_runtime_container_has_no_untyped_or_unused_service_slots():
    source = (PACKAGE_ROOT / "application" / "runtime_container.py").read_text(encoding="utf-8")

    assert "Any" not in source
    assert "hash_engine:" not in source
    assert "memory_shell_tracer:" not in source


def test_interfaces_and_plugins_do_not_reach_service_private_state():
    forbidden = ("._stats", "._clusters", "._profiles", "._safe_notify")
    violations: list[str] = []
    for root in (PACKAGE_ROOT / "interfaces", PACKAGE_ROOT / "plugins"):
        for path in root.rglob("*.py"):
            source = path.read_text(encoding="utf-8")
            for token in forbidden:
                if token in source:
                    violations.append(f"{path.relative_to(PACKAGE_ROOT).as_posix()}: {token}")

    assert not violations, "cross-module integrations must use public service ports:\n" + "\n".join(
        violations
    )


def test_symbol_logs_always_receive_an_explicit_logger():
    violations: list[str] = []
    for path in _python_files():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            function = node.func
            is_symbol_log = (
                isinstance(function, ast.Name) and function.id == "log_with_symbol"
            ) or (isinstance(function, ast.Attribute) and function.attr == "log_with_symbol")
            if not is_symbol_log:
                continue
            has_logger = len(node.args) >= 4 or any(
                keyword.arg == "logger" for keyword in node.keywords
            )
            if not has_logger:
                rel = path.relative_to(PACKAGE_ROOT).as_posix()
                violations.append(f"{rel}:{node.lineno}")

    assert not violations, "symbol logging must use a runtime-owned logger:\n" + "\n".join(
        violations
    )


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
        if edge.source_layer == "interfaces" and edge.imported_layer == "infrastructure"
    ]
    assert not violations, (
        "interfaces must depend on application/domain, not infrastructure. "
        "Route access through an application service:\n" + _format_edges(violations)
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
        "Use an EventPublisher port supplied by the composition root:\n" + _format_edges(violations)
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
        "inside the composition root:\n" + _format_edges(violations)
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
        + "\n".join(f"{source}: {imported}" for source, imported in sorted(stale_allowlist))
    )


def test_packaged_code_has_no_unscoped_legacy_branding():
    violations: list[str] = []
    for path in _packaged_text_files():
        rel = path.relative_to(PACKAGE_ROOT).as_posix()
        for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if "Trident" not in line and "trident_" not in line and '"trident"' not in line:
                continue
            if any(
                rel == allowed_path and allowed_text in line
                for allowed_path, allowed_text in KNOWN_LEGACY_BRANDING_LINES
            ):
                continue
            violations.append(f"{rel}:{line_no}: {line.strip()}")

    assert not violations, (
        "legacy Trident naming must stay inside explicit compatibility shims:\n"
        + "\n".join(violations)
    )


def test_runtime_composition_is_split_from_lifecycle():
    """Lifecycle orchestration must not regain service construction helpers."""
    application_root = PACKAGE_ROOT / "application"
    launcher = (application_root / "launcher.py").read_text(encoding="utf-8")

    assert "from anteumbra.application.runtime_builder import (" in launcher
    assert "from anteumbra.application.runtime_plugins import (" in launcher
    assert "from anteumbra.application.runtime_workers import (" in launcher
    for helper in (
        "build_runtime_container",
        "_start_site_monitors",
        "_start_profile_workers",
        "_start_plugins",
        "_build_builtin_plugin_factories",
    ):
        assert f"def {helper}(" not in launcher

    expected_owners = {
        "runtime_builder.py": "def build_runtime_container(",
        "runtime_workers.py": "def _start_site_monitors(",
        "runtime_plugins.py": "def _start_plugins(",
    }
    for filename, function in expected_owners.items():
        assert function in (application_root / filename).read_text(encoding="utf-8")


def test_admin_data_actions_are_registered():
    """Template and generated actions must resolve through the delegated registry."""
    frontend_root = PACKAGE_ROOT / "interfaces" / "web" / "static" / "js"
    sources = [
        frontend_root / "app.js",
        frontend_root / "dashboard.js",
        *sorted((frontend_root / "modules").glob("*.js")),
    ]
    registered: set[str] = set()
    generated: set[str] = set()
    for path in sources:
        source = path.read_text(encoding="utf-8")
        registered.update(
            re.findall(
                r"registerAction\(\s*['\"]([a-z][a-z0-9-]*(?:\.[a-z0-9-]+)+)['\"]",
                source,
            )
        )
        registered.update(
            re.findall(
                r"(?m)^\s*['\"]([a-z][a-z0-9-]*(?:\.[a-z0-9-]+)+)['\"]\s*:\s*\{\s*handler",
                source,
            )
        )
        generated.update(
            re.findall(
                r"(?:dataset\.action\s*=\s*|setAttribute\(\s*['\"]data-action['\"]\s*,\s*)['\"]([^'\"]+)['\"]",
                source,
            )
        )

    template_actions: set[str] = set()
    templates = PACKAGE_ROOT / "interfaces" / "web" / "templates" / "admin"
    for path in templates.rglob("*.html"):
        template_actions.update(
            re.findall(
                r"data-action\s*=\s*['\"]([^'\"]+)['\"]",
                path.read_text(encoding="utf-8"),
            )
        )

    missing = sorted((template_actions | generated) - registered)
    assert not missing, "unregistered admin data-action values:\n" + "\n".join(missing)


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
