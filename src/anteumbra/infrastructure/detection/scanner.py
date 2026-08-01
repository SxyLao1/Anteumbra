"""Instance-owned file scanning pipeline."""

from __future__ import annotations

import logging
import re
import socket
import time
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Mapping, Sequence

from anteumbra.domain.entities import ScanResult
from anteumbra.domain.runtime import ConfigProviderPort, MetricsPort
from anteumbra.domain.service_ports import YaraEnginePort
from anteumbra.infrastructure.models import ScanOptions

_WEB_EXTENSIONS = {".php", ".php5", ".phtml", ".asp", ".aspx", ".ashx", ".jsp", ".jspx"}


class BaseScanner(ABC):
    """Contract implemented by one scanning strategy."""

    @abstractmethod
    def can_scan(self, file_path: Path, scan_options: ScanOptions) -> bool:
        """Return whether this strategy can inspect the file."""

    @abstractmethod
    def scan(
        self,
        file_path: Path,
        scan_options: ScanOptions,
        logger: logging.Logger,
    ) -> ScanResult:
        """Inspect one file and return a canonical result."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Return the strategy name used in diagnostics."""


class StaticScanner(BaseScanner):
    """Simple literal fallback scanner useful for isolated integrations."""

    def __init__(
        self,
        config_provider: ConfigProviderPort,
        patterns: Sequence[str] | None = None,
    ) -> None:
        self.config_provider = config_provider
        self.patterns = tuple(
            patterns
            or (
                "eval(",
                "exec(",
                "system(",
                "base64_decode(",
                "passthru(",
                "shell_exec(",
                "Runtime.getRuntime().exec(",
            )
        )
        self._regexes = tuple(re.compile(re.escape(item), re.IGNORECASE) for item in self.patterns)

    @property
    def name(self) -> str:
        return "static"

    def can_scan(self, file_path: Path, scan_options: ScanOptions) -> bool:
        return _within_size_limit(file_path, scan_options, self.config_provider.get())

    def scan(
        self,
        file_path: Path,
        scan_options: ScanOptions,
        logger: logging.Logger,
    ) -> ScanResult:
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except OSError as exc:
            return ScanResult(file_path, False, [], engine=self.name, error=str(exc))
        matches = [
            pattern for pattern, regex in zip(self.patterns, self._regexes) if regex.search(content)
        ]
        return ScanResult(
            file_path=file_path,
            is_suspicious=bool(matches),
            features=matches,
            score=min(len(matches) * 0.3, 0.95),
            engine=self.name,
        )


class YaraScanner(BaseScanner):
    """Adapter from the runtime-owned YARA engine to the scanner strategy API."""

    def __init__(
        self,
        config_provider: ConfigProviderPort,
        engine: YaraEnginePort,
    ) -> None:
        self.config_provider = config_provider
        self.engine = engine

    @property
    def name(self) -> str:
        return "yara"

    def can_scan(self, file_path: Path, scan_options: ScanOptions) -> bool:
        return file_path.suffix.lower() in _WEB_EXTENSIONS and _within_size_limit(
            file_path, scan_options, self.config_provider.get()
        )

    def scan(
        self,
        file_path: Path,
        scan_options: ScanOptions,
        logger: logging.Logger,
    ) -> ScanResult:
        if not self.engine.compiled_rules:
            return ScanResult(file_path, False, [], engine=self.name)
        matches = self.engine.scan(file_path)
        if not matches:
            return ScanResult(file_path, False, [], engine=self.name)
        severity_score = {"critical": 0.95, "high": 0.85, "medium": 0.7, "low": 0.5}
        score = max(severity_score.get(match.severity, 0.6) for match in matches)
        return ScanResult(
            file_path=file_path,
            is_suspicious=True,
            features=[f"YARA:{match.rule_name}({match.severity})" for match in matches[:5]],
            score=score,
            engine=self.name,
        )


class EmergencyScanner(BaseScanner):
    """Focused zero-dependency fallback for direct request-to-execution patterns."""

    _PATTERNS = {
        "php_dynamic_exec": re.compile(
            r"\b(?:eval|assert|system|exec|passthru|shell_exec)\s*\(\s*"
            r"(?:base64_decode\s*\(\s*)?\$_(?:POST|GET|REQUEST|COOKIE)\s*\[",
            re.IGNORECASE,
        ),
        "php_encoded_exec": re.compile(
            r"\b(?:eval|assert)\s*\(\s*(?:gzinflate|gzuncompress|base64_decode|str_rot13)\s*\(",
            re.IGNORECASE,
        ),
        "java_process_exec": re.compile(
            r"(?:Runtime\.getRuntime\(\)\.exec|new\s+ProcessBuilder)\s*\(",
            re.IGNORECASE,
        ),
        "asp_dynamic_exec": re.compile(
            r"\b(?:eval|execute|executeglobal)\s*\(?\s*request(?:\.|\()",
            re.IGNORECASE,
        ),
    }

    def __init__(self, config_provider: ConfigProviderPort) -> None:
        self.config_provider = config_provider

    @property
    def name(self) -> str:
        return "emergency"

    def can_scan(self, file_path: Path, scan_options: ScanOptions) -> bool:
        return file_path.suffix.lower() in _WEB_EXTENSIONS and _within_size_limit(
            file_path, scan_options, self.config_provider.get()
        )

    def scan(
        self,
        file_path: Path,
        scan_options: ScanOptions,
        logger: logging.Logger,
    ) -> ScanResult:
        try:
            stat = file_path.stat()
        except PermissionError as exc:
            logger.warning("[SCAN][PERMISSION] Cannot inspect %s", file_path)
            return ScanResult(
                file_path,
                True,
                ["PERMISSION_CONFUSION"],
                score=0.85,
                engine=self.name,
                error=str(exc),
            )
        except OSError as exc:
            return ScanResult(file_path, False, [], engine=self.name, error=str(exc))

        if stat.st_size > scan_options.max_size_bytes:
            return ScanResult(file_path, False, [], engine=self.name, error="file too large")

        content: str | None = None
        last_error: OSError | None = None
        for attempt in range(3):
            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
                break
            except PermissionError as exc:
                last_error = exc
                if attempt < 2:
                    time.sleep(0.1)
            except OSError as exc:
                return ScanResult(file_path, False, [], engine=self.name, error=str(exc))
        if content is None:
            return ScanResult(file_path, False, [], engine=self.name, error=str(last_error))

        features = [name for name, pattern in self._PATTERNS.items() if pattern.search(content)]
        return ScanResult(
            file_path=file_path,
            is_suspicious=bool(features),
            features=[f"EMERGENCY:{name}" for name in features],
            score=min(0.6 + len(features) * 0.1, 0.95) if features else 0.0,
            engine=self.name,
        )


class ScannerChain:
    """Ordered, stateless orchestration of scanning strategies."""

    def __init__(self, engines: Sequence[tuple[int, BaseScanner]]) -> None:
        self.engines = tuple(sorted(engines, key=lambda item: item[0]))

    def scan(
        self,
        file_path: Path,
        scan_options: ScanOptions,
        logger: logging.Logger,
    ) -> ScanResult:
        errors: list[str] = []
        for _priority, engine in self.engines:
            if not engine.can_scan(file_path, scan_options):
                continue
            try:
                result = engine.scan(file_path, scan_options, logger)
            except Exception as exc:
                logger.exception("[SCAN][%s] Strategy failed", engine.name)
                errors.append(f"{engine.name}: {exc}")
                continue
            if result.is_suspicious:
                return result
            if result.error:
                errors.append(f"{engine.name}: {result.error}")
        return ScanResult(
            file_path,
            False,
            [],
            engine="chain",
            error="; ".join(errors) or None,
        )


class ScannerService:
    """Runtime-owned scanner used by file monitors and active scans."""

    def __init__(
        self,
        config_provider: ConfigProviderPort,
        yara_engine: YaraEnginePort,
        metrics: MetricsPort,
    ) -> None:
        self.config_provider = config_provider
        self.yara_engine = yara_engine
        self.metrics = metrics
        self.chain = ScannerChain(
            (
                (5, YaraScanner(config_provider, yara_engine)),
                (20, EmergencyScanner(config_provider)),
            )
        )

    def scan(
        self,
        file_path: Path,
        scan_options: ScanOptions,
        logger: logging.Logger,
    ) -> ScanResult:
        """Scan one file and record exactly one global attempt/outcome."""
        file_path = Path(file_path)
        configured_extensions = scan_options.monitor_extensions or self.config_provider.get().get(
            "paths", {}
        ).get("monitor_extensions", sorted(_WEB_EXTENSIONS))
        extensions = {str(extension).lower() for extension in configured_extensions}
        if file_path.suffix.lower() not in extensions:
            return ScanResult(file_path, False, [], engine="filter")

        self.metrics.increment("scan_total")
        result = self.chain.scan(file_path, scan_options, logger)
        if not result.is_suspicious:
            decoded_result = self._scan_decoded(file_path, logger)
            if decoded_result is not None:
                result = decoded_result
        if result.is_suspicious:
            self.metrics.increment("scan_suspicious")
        return result

    def _scan_decoded(
        self,
        file_path: Path,
        logger: logging.Logger,
    ) -> ScanResult | None:
        if not self.yara_engine.compiled_rules:
            return None
        try:
            raw_data = file_path.read_bytes()
            if len(raw_data) >= 5 * 1024 * 1024:
                return None
            from anteumbra.infrastructure.detection.decoder import WebShellDecoder

            decoded = WebShellDecoder.decode(raw_data)
            content = raw_data.decode("utf-8", errors="replace") + "\n" + decoded
            matches = self.yara_engine.scan_data(content, source_name=f"{file_path}#decoded")
        except OSError:
            logger.debug("Decoder pass could not read %s", file_path, exc_info=True)
            return None
        except Exception:
            logger.exception("Decoder pass failed for %s", file_path)
            return None
        if not matches:
            return None
        return ScanResult(
            file_path=file_path,
            is_suspicious=True,
            features=[f"DECODED:{match.rule_name}" for match in matches[:5]],
            score=max(
                {"critical": 0.95, "high": 0.85, "medium": 0.7, "low": 0.5}.get(
                    match.severity,
                    0.6,
                )
                for match in matches
            ),
            engine="yara-decoded",
        )


def quick_scan_yara(
    file_path: Path,
    scan_options: ScanOptions,
    logger: logging.Logger,
    *,
    scanner_service: ScannerService,
) -> ScanResult:
    """Compatibility-shaped call requiring an explicitly supplied scanner."""
    return scanner_service.scan(file_path, scan_options, logger)


def _within_size_limit(
    file_path: Path,
    scan_options: ScanOptions,
    config: Mapping[str, Any],
) -> bool:
    try:
        configured_mb = float(config.get("filesizes", {}).get("max_scan_file_size_mb", 10))
        limit = min(scan_options.max_size_bytes, int(configured_mb * 1024 * 1024))
        return file_path.is_file() and file_path.stat().st_size <= limit
    except (OSError, TypeError, ValueError):
        return False


def check_port(host: str, port: int, timeout: float = 3.0) -> bool:
    """Return whether a TCP endpoint accepts a connection within the timeout."""
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True
    except (OSError, TypeError, ValueError):
        return False


__all__ = [
    "BaseScanner",
    "EmergencyScanner",
    "ScannerChain",
    "ScannerService",
    "StaticScanner",
    "YaraScanner",
    "check_port",
    "quick_scan_yara",
]
