# -*- coding: utf-8 -*-
"""Fault-isolated YARA rule loading and scanning."""

from __future__ import annotations

import logging
import math
import threading
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

from anteumbra.domain.runtime import ConfigProviderPort
from anteumbra.infrastructure.utils.logger_factory import log_with_symbol
from anteumbra.infrastructure.utils.path_utils import normalize_path

try:
    import yara
except ImportError:
    yara = None


@dataclass
class YaraMatch:
    rule_name: str
    namespace: str
    meta: Dict[str, Any]
    strings: List[Dict[str, Any]]
    severity: str


@dataclass(frozen=True)
class _CompiledRuleFile:
    filename: str
    namespace: str
    rules: Any
    rule_count: int


class CompositeYaraRules:
    """Compatibility adapter around independently compiled YARA files."""

    def __init__(
        self,
        bundles: List[_CompiledRuleFile],
        logger: logging.Logger,
    ) -> None:
        self._bundles = tuple(bundles)
        self._logger = logger
        self._rule_count = sum(bundle.rule_count for bundle in bundles)
        self.last_match_errors: Dict[str, str] = {}

    def __bool__(self) -> bool:
        return bool(self._bundles)

    def __len__(self) -> int:
        return self._rule_count

    def __iter__(self) -> Iterator[Any]:
        for bundle in self._bundles:
            yield from bundle.rules

    def match(
        self,
        *,
        data: bytes | str | None = None,
        filepath: str | None = None,
        timeout: int | None = None,
    ) -> List[Any]:
        """Match every valid file while containing per-file runtime failures."""
        if data is None and filepath is None:
            raise ValueError("data or filepath is required")

        deadline = time.monotonic() + timeout if timeout and timeout > 0 else None
        matches: List[Any] = []
        errors: Dict[str, str] = {}

        for bundle in self._bundles:
            match_kwargs: Dict[str, Any] = {}
            if data is not None:
                match_kwargs["data"] = data
            else:
                match_kwargs["filepath"] = filepath

            if deadline is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    errors[bundle.filename] = "global scan timeout exhausted"
                    self._logger.warning(
                        "[YARA][TIMEOUT] Global scan timeout exhausted before %s",
                        bundle.filename,
                    )
                    break
                match_kwargs["timeout"] = max(1, math.ceil(remaining))

            try:
                matches.extend(bundle.rules.match(**match_kwargs))
            except Exception as exc:
                errors[bundle.filename] = str(exc)
                self._logger.warning(
                    "[YARA][SKIP] Runtime failure in %s: %s",
                    bundle.filename,
                    exc,
                )

        self.last_match_errors = errors
        return matches


def get_bundled_rules_path() -> Path:
    """Return the package-owned YARA directory."""
    import anteumbra

    return Path(anteumbra.__file__).resolve().parent / "rules" / "webshell"


def _contains_yara_rules(path: Path) -> bool:
    try:
        return path.is_dir() and next(path.glob("*.yar"), None) is not None
    except OSError:
        return False


def resolve_yara_rules_path(
    configured_path: str | Path,
    logger: logging.Logger | None = None,
) -> Path:
    """Use bundled rules when the configured runtime directory is absent or empty."""
    configured = normalize_path(configured_path).resolve()
    if _contains_yara_rules(configured):
        return configured

    bundled = get_bundled_rules_path().resolve()
    if configured != bundled and _contains_yara_rules(bundled):
        if logger is not None:
            reason = "empty" if configured.is_dir() else "missing"
            logger.warning(
                "[YARA] Configured rules directory is %s (%s); using bundled rules: %s",
                reason,
                configured,
                bundled,
            )
        return bundled
    return configured


class YaraEngine:
    """YARA engine with file-level compile and scan isolation."""

    def __init__(
        self,
        rules_path: str | Path,
        logger: logging.Logger,
        config_provider: ConfigProviderPort,
    ):
        self.rules_path = normalize_path(rules_path).resolve()
        self.logger = logger
        self.config_provider = config_provider
        self.compiled_rules: Optional[CompositeYaraRules] = None
        self.loaded_rule_files: Tuple[str, ...] = ()
        self.load_errors: Dict[str, str] = {}
        self.last_reload_at: Optional[datetime] = None
        self._reload_lock = threading.RLock()
        self._load_rules()

    def _load_rules(self) -> bool:
        """Compile each rule file independently and atomically publish the result."""
        if yara is None:
            self.logger.warning("yara-python is not installed; YARA engine disabled")
            with self._reload_lock:
                self.compiled_rules = None
                self.loaded_rule_files = ()
                self.load_errors = {"<engine>": "yara-python is not installed"}
            return False

        rule_files = sorted(
            self.rules_path.glob("*.yar"),
            key=lambda path: path.name.lower(),
        ) if self.rules_path.is_dir() else []
        bundles: List[_CompiledRuleFile] = []
        errors: Dict[str, str] = {}

        for yar_file in rule_files:
            try:
                compiled = yara.compile(filepaths={yar_file.stem: str(yar_file)})
                bundles.append(_CompiledRuleFile(
                    filename=yar_file.name,
                    namespace=yar_file.stem,
                    rules=compiled,
                    rule_count=sum(1 for _ in compiled),
                ))
            except Exception as exc:
                errors[yar_file.name] = str(exc)
                self.logger.warning(
                    "[YARA][SKIP] Invalid rule file %s: %s",
                    yar_file.name,
                    exc,
                )

        if not bundles:
            with self._reload_lock:
                self.load_errors = errors or {"<rules>": "no .yar files found"}
                self.last_reload_at = datetime.now()
                if self.compiled_rules:
                    self.logger.error(
                        "[YARA] Reload produced no valid rules; retaining the previous ruleset"
                    )
                else:
                    self.compiled_rules = None
                    self.loaded_rule_files = ()
                    self.logger.warning(
                        "[YARA] No valid rules found in %s (files=%d)",
                        self.rules_path,
                        len(rule_files),
                    )
            return False

        composite = CompositeYaraRules(bundles, self.logger)
        with self._reload_lock:
            self.compiled_rules = composite
            self.loaded_rule_files = tuple(bundle.filename for bundle in bundles)
            self.load_errors = errors
            self.last_reload_at = datetime.now()

        log_with_symbol(
            "yara_list",
            "debug",
            (
                f"Loaded {len(composite)} rules from {len(bundles)}/{len(rule_files)} "
                f"files; skipped {len(errors)} invalid files"
            ),
            self.logger,
        )
        return True

    def reload(self) -> bool:
        """Reload rule files without exposing a partially compiled ruleset."""
        return self._load_rules()

    def _scan_timeout(self) -> int | None:
        config = self.config_provider.get()
        value = config.get("timeouts", {}).get("scan_timeout", 30)
        try:
            parsed = int(value)
        except (TypeError, ValueError):
            parsed = 30
        return parsed if parsed > 0 else None

    def scan_data(
        self,
        data: bytes | str,
        source_name: str = "<memory>",
    ) -> List[YaraMatch]:
        """Scan bytes or decoded text using the same timeout and result mapping."""
        compiled = self.compiled_rules
        if not compiled:
            self.logger.warning("[YARA] Rules are not loaded; skipping %s", source_name)
            return []

        try:
            raw_matches = compiled.match(data=data, timeout=self._scan_timeout())
        except Exception as exc:
            self.logger.error(
                "[YARA][SCAN] Scan failed for %s: %s",
                source_name,
                exc,
                exc_info=True,
            )
            return []

        results = []
        for match in raw_matches:
            meta = match.meta if hasattr(match, "meta") else {}
            severity = str(meta.get("severity", "medium")).lower()
            results.append(YaraMatch(
                rule_name=match.rule,
                namespace=match.namespace,
                meta=meta,
                strings=[],
                severity=severity,
            ))

        severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        results.sort(
            key=lambda item: severity_order.get(item.severity, 0),
            reverse=True,
        )
        if results:
            self.logger.info(
                "[YARA][MATCH] %s matched %d rules",
                source_name,
                len(results),
            )
        else:
            self.logger.debug("[YARA][SAFE] %s", source_name)
        return results

    def scan(self, file_path: Path) -> List[YaraMatch]:
        """Scan a file from memory so Windows Unicode paths remain supported."""
        if not file_path.exists():
            self.logger.warning("[YARA] File does not exist: %s", file_path)
            return []

        config = self.config_provider.get()
        max_size_mb = config.get("filesizes", {}).get("max_scan_file_size_mb", 10)
        if file_path.stat().st_size > max_size_mb * 1024 * 1024:
            self.logger.warning("[YARA] File is too large; skipping %s", file_path.name)
            return []

        try:
            file_data = file_path.read_bytes()
        except OSError as exc:
            self.logger.error("[YARA][SCAN] Cannot read %s: %s", file_path, exc)
            return []
        return self.scan_data(file_data, str(file_path))

    def get_rule_stats(self) -> Dict[str, int]:
        """Count loaded rules by their common language naming conventions."""
        if not self.compiled_rules:
            return {}

        stats: Dict[str, int] = {}
        for rule in self.compiled_rules:
            rule_name = rule.identifier if hasattr(rule, "identifier") else str(rule)
            lowered = rule_name.lower()
            if rule_name.startswith("PHP") or "php" in lowered:
                category = "php"
            elif rule_name.startswith("ASP") or "asp" in lowered:
                category = "asp"
            elif rule_name.startswith("JSP") or "jsp" in lowered:
                category = "jsp"
            elif rule_name.startswith("Custom_"):
                category = "custom"
            else:
                category = "other"
            stats[category] = stats.get(category, 0) + 1
        return stats

    def get_rule_files(self) -> List[Dict[str, Any]]:
        """Return rule file metadata for application-facing diagnostics."""
        files = []
        for yar_file in sorted(self.rules_path.glob("*.yar"), key=lambda p: p.name.lower()):
            try:
                stats = yar_file.stat()
            except OSError:
                self.logger.debug("[YARA] Failed to stat %s", yar_file, exc_info=True)
                continue
            files.append({
                "filename": yar_file.name,
                "size": stats.st_size,
                "modified": datetime.fromtimestamp(stats.st_mtime).isoformat(),
                "loaded": yar_file.name in self.loaded_rule_files,
                "error": self.load_errors.get(yar_file.name),
            })
        return files

    def validate_rule_string(self, rule_content: str) -> Tuple[bool, Optional[str]]:
        """Validate YARA source without changing the active ruleset."""
        if yara is None:
            return False, "yara-python is not installed"
        try:
            yara.compile(source=rule_content)
            return True, None
        except Exception as exc:
            return False, str(exc)



class DisabledYaraEngine:
    """Explicit null object used when YARA scanning is disabled."""

    compiled_rules = None
    loaded_rule_files: Tuple[str, ...] = ()
    load_errors: Dict[str, str] = {}

    def __init__(self, rules_path: str | Path, logger: logging.Logger) -> None:
        self.rules_path = normalize_path(rules_path).resolve()
        self.logger = logger

    def scan(self, _path: str | Path) -> List[YaraMatch]:
        return []

    def scan_data(
        self,
        _data: bytes | str,
        source_name: str = "<memory>",
    ) -> List[YaraMatch]:
        return []

    def get_rule_stats(self) -> Dict[str, Any]:
        return {"enabled": False, "loaded_files": 0, "rules": 0}

    def reload(self) -> bool:
        return False


def build_yara_engine(
    config_provider: ConfigProviderPort,
    logger: logging.Logger,
) -> YaraEngine | DisabledYaraEngine:
    """Build one YARA engine from an explicit runtime configuration."""
    config = config_provider.get()
    yara_config = config.get("scanner", {}).get("yara", {})
    paths_config = config.get("paths", {})
    configured_path = (
        yara_config.get("rules_path")
        or paths_config.get("yara_rules_path", "rules/webshell")
    )
    rules_path = resolve_yara_rules_path(configured_path, logger)
    if not yara_config.get("enabled", False):
        logger.warning("[YARA] Engine is disabled")
        return DisabledYaraEngine(rules_path, logger)
    return YaraEngine(rules_path, logger, config_provider)
