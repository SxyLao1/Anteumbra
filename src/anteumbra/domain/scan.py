"""Scanning policy data shared by configuration and application workflows."""

from dataclasses import dataclass, field


@dataclass
class ScanOptions:
    """Resolved scanning policy for one website."""

    monitor_extensions: list[str] = field(default_factory=lambda: [".php"])
    exclude_dirs: list[str] = field(default_factory=list)
    exclude_files: list[str] = field(default_factory=list)
    max_file_size: str = "10MB"
    debug_mode: bool = False
    access_log_path: str | None = None

    @property
    def max_size_bytes(self) -> int:
        value = self.max_file_size.upper()
        multipliers = {"KB": 1024, "MB": 1024**2, "GB": 1024**3, "TB": 1024**4}
        for unit, multiplier in multipliers.items():
            if value.endswith(unit):
                return int(value.removesuffix(unit)) * multiplier
        return int(value)
