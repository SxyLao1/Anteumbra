"""Scanning policy data shared by configuration and application workflows."""

from dataclasses import dataclass, field

# Applied when a site's [website.scan_options] table is absent.  These used to be
# empty lists, which meant the *unknown* case (an ad-hoc scan of an unassigned
# path) received a conservative set while a *configured* site received no
# exclusions at all — the opposite of what an operator expects.  A config that
# supplies only a site path and a log path is now safe by default.  Listing
# exclude_dirs / exclude_files in the config still replaces the set entirely, so
# this changes nothing for existing configurations.
DEFAULT_EXCLUDE_DIRS: tuple[str, ...] = (
    ".git",
    ".svn",
    ".hg",
    "node_modules",
    "vendor",
    "cache",
    "logs",
    "temp",
    "tmp",
    "data",
)
DEFAULT_EXCLUDE_FILES: tuple[str, ...] = ("*.log", "*.cache", "*.tmp", "*.swp")


@dataclass
class ScanOptions:
    """Resolved scanning policy for one website."""

    monitor_extensions: list[str] = field(default_factory=lambda: [".php"])
    exclude_dirs: list[str] = field(default_factory=lambda: list(DEFAULT_EXCLUDE_DIRS))
    exclude_files: list[str] = field(default_factory=lambda: list(DEFAULT_EXCLUDE_FILES))
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
