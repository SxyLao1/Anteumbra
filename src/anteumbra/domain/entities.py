# -*- coding: utf-8 -*-
"""
v1.0: Domain Entities — Pydantic models for core business objects.

Design principles:
  - Immutable where possible (frozen=True for value objects)
  - Validation at construction (no invalid state can exist)
  - JSON-serializable (to_dict() / from_dict())
  - Zero infrastructure dependencies (no DB, no Flask, no filesystem)
"""
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from typing import List, Optional, Dict, Any

try:
    from pydantic import BaseModel, Field, field_validator
    _HAS_PYDANTIC = True
except ImportError:
    # Graceful fallback: use dataclasses if pydantic not installed
    from dataclasses import dataclass, field, asdict
    _HAS_PYDANTIC = False


class DetectionSource(str, Enum):
    """How a detection was discovered."""
    PASSIVE = "passive"    # Watchdog file monitoring
    ACTIVE = "active"      # Manual directory scanner
    WAF = "waf"            # WAF event correlation
    LOG = "log_heuristic"  # Access log behavior analysis
    MEMORY = "memory"      # Memory shell scanner


class FileStatus(str, Enum):
    ACTIVE = "active"
    QUARANTINED = "quarantined"
    DELETED = "deleted"
    FALSE_POSITIVE = "false_positive"


# ── FileRecord (Domain Entity) ──────────────────────────

if _HAS_PYDANTIC:

    from pydantic import model_validator

    class FileRecord(BaseModel):
        """Core domain entity: a detected suspicious file."""
        file_path: str = Field(..., description="Absolute path (normalized)")
        display_name: Optional[str] = Field(default=None, description="Filename only")
        detected_at: str = Field(
            default_factory=lambda: datetime.now(timezone.utc).isoformat())
        features: List[str] = Field(default_factory=list)
        file_exists: bool = True
        file_size: int = 0
        communication_count: int = 0
        first_seen_ip: Optional[str] = None
        alerted: bool = False
        marked_false_positive: bool = False
        false_positive_at: Optional[str] = None
        quarantine_id: Optional[str] = None
        deleted_at: Optional[str] = None
        detection_source: DetectionSource = DetectionSource.PASSIVE
        metadata: Dict[str, Any] = Field(default_factory=dict)

        @field_validator("file_path")
        @classmethod
        def normalize_path(cls, v: str) -> str:
            return v.replace("\\", "/")

        @field_validator("display_name", mode="before")
        @classmethod
        def coerce_display_name(cls, v) -> str:
            return v or ""

        @model_validator(mode="after")
        def auto_display_name(self):
            if not self.display_name:
                self.display_name = Path(self.file_path).name
            return self

        @property
        def status(self) -> FileStatus:
            if self.quarantine_id:
                return FileStatus.QUARANTINED
            if self.marked_false_positive:
                return FileStatus.FALSE_POSITIVE
            if self.deleted_at:
                return FileStatus.DELETED
            return FileStatus.ACTIVE

        @property
        def is_active(self) -> bool:
            return self.status == FileStatus.ACTIVE

        def to_dict(self) -> Dict[str, Any]:
            return self.model_dump()

        @classmethod
        def from_dict(cls, data: Dict[str, Any]) -> "FileRecord":
            # Filter to known model fields only (SQLite rows include 'id', etc.)
            valid_fields = set(cls.model_fields.keys())
            filtered = {k: v for k, v in data.items() if k in valid_fields}
            return cls(**filtered)

else:
    # Fallback: dataclass implementation
    @dataclass
    class FileRecord:
        file_path: str
        display_name: str = ""
        detected_at: str = ""
        features: List[str] = None
        file_exists: bool = True
        file_size: int = 0
        communication_count: int = 0
        first_seen_ip: Optional[str] = None
        alerted: bool = False
        marked_false_positive: bool = False
        false_positive_at: Optional[str] = None
        quarantine_id: Optional[str] = None
        deleted_at: Optional[str] = None
        detection_source: DetectionSource = DetectionSource.PASSIVE
        metadata: Dict[str, Any] = None

        def __post_init__(self):
            if self.features is None: self.features = []
            if self.metadata is None: self.metadata = {}
            if not self.detected_at:
                self.detected_at = datetime.now(timezone.utc).isoformat()
            self.file_path = self.file_path.replace("\\", "/")
            if not self.display_name:
                self.display_name = Path(self.file_path).name

        @property
        def status(self) -> FileStatus:
            if self.quarantine_id: return FileStatus.QUARANTINED
            if self.marked_false_positive: return FileStatus.FALSE_POSITIVE
            if self.deleted_at: return FileStatus.DELETED
            return FileStatus.ACTIVE

        @property
        def is_active(self) -> bool:
            return self.status == FileStatus.ACTIVE

        def to_dict(self) -> Dict[str, Any]:
            d = asdict(self)
            d["detection_source"] = self.detection_source.value
            return d

        @classmethod
        def from_dict(cls, data: Dict[str, Any]) -> "FileRecord":
            from dataclasses import fields as dc_fields
            if "detection_source" in data and isinstance(data["detection_source"], str):
                data["detection_source"] = DetectionSource(data["detection_source"])
            # Filter to known fields only (SQLite rows include 'id', etc.)
            valid_fields = {f.name for f in dc_fields(cls)}
            filtered = {k: v for k, v in data.items() if k in valid_fields}
            return cls(**filtered)


# ── Value Objects ────────────────────────────────────────

@dataclass
class ScanResult:
    """Unified scan result — canonical definition (v1.0.5: triple-merge fix).

    All detection engines return this type:
      - StaticScanner (regex pattern matching)
      - YaraScanner (YARA rule matching)
      - EmergencyScanner (fallback when YARA unavailable)
      - ApiEngine (remote API scan)
      - Decoder (deobfuscated re-scan)
      - ScannerChain (orchestrated multi-engine pipeline)

    Field order is intentional — matches historical callers' positional args:
      ScanResult(file_path, is_suspicious, features, engine=..., error=...)
    """
    file_path: Path
    is_suspicious: bool
    features: List[str] = field(default_factory=list)
    score: float = 0.0
    engine: str = "static"
    error: Optional[str] = None
    analysis_data: Optional[dict] = None
    detection_source: str = "unknown"  # passive | active | waf | log | unknown
    confidence: float = 0.0           # 0.0~1.0 (detector.py version)
    metadata: dict = field(default_factory=dict)  # extra context

    def to_record(self) -> "FileRecord":
        """Convert scan result to a FileRecord for persistence."""
        ds = DetectionSource.PASSIVE
        try:
            if self.detection_source in ("passive", "active", "waf", "log"):
                ds = DetectionSource(self.detection_source)
        except ValueError:
            pass
        return FileRecord(
            file_path=str(self.file_path),
            display_name=self.file_path.name,
            features=list(self.features),
            detection_source=ds,
        )


class QuarantineRecord:
    """Value object: a quarantined file."""
    def __init__(self, quarantine_id: str, original_path: str,
                 quarantine_path: str, rule_name: str = "",
                 features: List[str] = None, file_size: int = 0,
                 created_at: Optional[str] = None):
        self.quarantine_id = quarantine_id
        self.original_path = original_path
        self.quarantine_path = quarantine_path
        self.rule_name = rule_name
        self.features = features or []
        self.file_size = file_size
        self.created_at = created_at or datetime.now(timezone.utc).isoformat()
