"""Stage 0 architecture ratchets for the cleanup program."""

from __future__ import annotations

import ast
from pathlib import Path

from test_import_boundaries import _internal_import_edges

PROJECT_ROOT = Path(__file__).resolve().parents[2]
PACKAGE_ROOT = PROJECT_ROOT / "src" / "anteumbra"

# runtime_builder is the explicit composition root. Every other entry is
# temporary Stage 1 debt, documented so the allowlist can only shrink.
TEMPORARY_APPLICATION_TO_INFRASTRUCTURE = {
    ("application/runtime_builder.py", "anteumbra.infrastructure.config.provider"),
    ("application/runtime_builder.py", "anteumbra.infrastructure.process_identity"),
    ("application/runtime_builder.py", "anteumbra.infrastructure.utils.path_utils"),
    ("application/log_analysis_service.py", "anteumbra.infrastructure.detection.log_heuristic"),
    ("application/log_analysis_service.py", "anteumbra.infrastructure.monitoring.log_analyzer"),
    ("application/runtime_builder.py", "anteumbra.infrastructure.monitoring.notifier"),
    ("application/runtime_builder.py", "anteumbra.infrastructure.monitoring.log_analyzer"),
    ("application/runtime_builder.py", "anteumbra.infrastructure.monitoring.log_monitor"),
    ("application/runtime_builder.py", "anteumbra.infrastructure.monitoring.monitor"),
}

RUNTIME_BUILDER_IMPORTS = {
    "anteumbra.infrastructure.block_ledger",
    "anteumbra.infrastructure.config.provider",
    "anteumbra.infrastructure.detection.file_cluster",
    "anteumbra.infrastructure.detection.hash_engine",
    "anteumbra.infrastructure.detection.scanner",
    "anteumbra.infrastructure.detection.yara_engine",
    "anteumbra.infrastructure.ip_blocker",
    "anteumbra.infrastructure.monitoring.metrics",
    "anteumbra.infrastructure.monitoring.notifier",
    "anteumbra.infrastructure.monitoring.siem_exporter",
    "anteumbra.infrastructure.persistence.sqlite_repository",
    "anteumbra.infrastructure.quarantine",
    "anteumbra.infrastructure.runtime_adapters",
    "anteumbra.infrastructure.scan_history",
    "anteumbra.infrastructure.suspicious_registry",
    "anteumbra.infrastructure.threat_graph",
    "anteumbra.infrastructure.utils.logger_factory",
    "anteumbra.infrastructure.utils.path_utils",
    "anteumbra.infrastructure.utils.sse_manager",
    "anteumbra.infrastructure.waf_client",
    "anteumbra.infrastructure.wal_manager",
}

MODULE_SIZE_BASELINE = {
    "cli/main.py": 1427,
    "infrastructure/monitoring/monitor.py": 1119,
    "infrastructure/threat_graph.py": 924,
    "infrastructure/monitoring/notifier.py": 900,
    "infrastructure/suspicious_registry.py": 816,
    "interfaces/web/blueprints/admin_bp.py": 600,
    "interfaces/web/blueprints/monitor_bp.py": 595,
}


def test_application_to_infrastructure_debt_is_exact_and_shrinking():
    actual = {
        edge.key
        for edge in _internal_import_edges()
        if edge.source_layer == "application" and edge.imported_layer == "infrastructure"
    }
    expected = TEMPORARY_APPLICATION_TO_INFRASTRUCTURE | {
        ("application/runtime_builder.py", module) for module in RUNTIME_BUILDER_IMPORTS
    }
    assert actual == expected, (
        "application -> infrastructure imports may only be retired, never added; "
        "runtime_builder.py is the sole composition-root exception:\n"
        + "\n".join(f"{source}: {module}" for source, module in sorted(actual ^ expected))
    )


def test_module_size_baseline_records_cleanup_starting_point():
    actual = {
        path: len((PACKAGE_ROOT / path).read_text(encoding="utf-8").splitlines())
        for path in MODULE_SIZE_BASELINE
    }
    assert actual == MODULE_SIZE_BASELINE


def test_stage_one_must_retire_the_only_application_to_interface_edge():
    edges = {
        edge.key
        for edge in _internal_import_edges()
        if edge.source_layer == "application" and edge.imported_layer == "interfaces"
    }
    assert edges == {("application/runtime_builder.py", "anteumbra.interfaces.web.factory")}


def _route_contract(filename: str, blueprint: str) -> set[tuple[str, tuple[str, ...], bool]]:
    tree = ast.parse((PACKAGE_ROOT / "interfaces" / "web" / "blueprints" / filename).read_text(encoding="utf-8"))
    routes: set[tuple[str, tuple[str, ...], bool]] = set()
    for node in tree.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        protected = any(isinstance(item, ast.Name) and item.id == "require_auth" for item in node.decorator_list)
        for decorator in node.decorator_list:
            if not (
                isinstance(decorator, ast.Call)
                and isinstance(decorator.func, ast.Attribute)
                and isinstance(decorator.func.value, ast.Name)
                and decorator.func.value.id == blueprint
                and decorator.func.attr == "route"
            ):
                continue
            route = ast.literal_eval(decorator.args[0])
            methods = ("GET",)
            for keyword in decorator.keywords:
                if keyword.arg == "methods":
                    methods = tuple(ast.literal_eval(keyword.value))
            routes.add((route, methods, protected))
    return routes


def test_admin_and_monitor_route_contracts_preserve_methods_and_authentication():
    assert _route_contract("admin_bp.py", "admin_bp") == {
        ("/", ("GET",), True), ("/overview", ("GET",), True), ("/threats", ("GET",), True),
        ("/dashboard_content", ("GET",), True), ("/monitor_content", ("GET",), True),
        ("/login", ("GET", "POST"), False), ("/logout", ("GET",), True), ("/dashboard", ("GET",), True),
        ("/metrics/<metric_name>", ("GET",), True), ("/metrics", ("GET",), True),
        ("/metrics/data", ("GET",), True), ("/test", ("GET",), True),
        ("/debug/routes", ("GET",), True), ("/account", ("GET",), True),
        ("/account/password", ("POST",), True), ("/api/v1/health", ("GET",), False),
        ("/health", ("GET",), True),
    }
    assert _route_contract("monitor_bp.py", "monitor_bp") == {
        ("/stream_logs", ("GET",), False), ("/logs/history", ("GET",), True),
        ("/logs/access-analysis", ("GET",), True), ("/wal", ("GET",), True),
        ("/wal/current", ("GET",), True), ("/wal/list", ("GET",), True),
        ("/wal/replay", ("POST",), True), ("/registry", ("GET",), True),
        ("/registry/count", ("GET",), True), ("/registry/queue", ("GET",), True),
        ("/registry/last-save", ("GET",), True), ("/registry/compact", ("POST",), True),
        ("/session", ("GET",), True), ("/session/list", ("GET",), True),
        ("/session/cleanup", ("POST",), True), ("/config", ("GET",), True),
        ("/config/history", ("GET",), True), ("/config/signature", ("GET",), True),
        ("/sse/history", ("GET",), True), ("/registry/wal-status", ("GET",), True),
    }

TEMPORARY_APPLICATION_TO_INFRASTRUCTURE_RATIONALES = {
    ("application/runtime_builder.py", "anteumbra.infrastructure.config.provider"): "inject default provider",
    ("application/runtime_builder.py", "anteumbra.infrastructure.process_identity"): "extract process identity port",
    ("application/runtime_builder.py", "anteumbra.infrastructure.utils.path_utils"): "move path normalization to assembly",
    ("application/log_analysis_service.py", "anteumbra.infrastructure.detection.log_heuristic"): "define detection port",
    ("application/log_analysis_service.py", "anteumbra.infrastructure.monitoring.log_analyzer"): "define log-analysis port",
    ("application/runtime_builder.py", "anteumbra.infrastructure.monitoring.notifier"): "inject plugin formatter",
    ("application/runtime_builder.py", "anteumbra.infrastructure.monitoring.log_analyzer"): "inject worker analyzer factory",
    ("application/runtime_builder.py", "anteumbra.infrastructure.monitoring.log_monitor"): "inject log monitor factory",
    ("application/runtime_builder.py", "anteumbra.infrastructure.monitoring.monitor"): "inject site monitor factory",
}


def test_temporary_application_to_infrastructure_edges_have_stage_one_rationales():
    assert TEMPORARY_APPLICATION_TO_INFRASTRUCTURE == set(
        TEMPORARY_APPLICATION_TO_INFRASTRUCTURE_RATIONALES
    )
