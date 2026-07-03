from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


@dataclass
class AuditRun:
    id: str
    hostname: str
    started_at: str
    finished_at: str | None = None
    status: str = "running"
    is_admin: bool = False
    summary: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def create(cls, hostname: str, is_admin: bool) -> "AuditRun":
        return cls(id=str(uuid4()), hostname=hostname, started_at=utc_now(), is_admin=is_admin)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class InventoryObject:
    category_id: str
    category_name: str
    object_type: str
    title: str
    fields: dict[str, Any]
    source: str
    confidence: str = "high"
    raw: dict[str, Any] = field(default_factory=dict)
    collected_at: str = field(default_factory=utc_now)
    uid: str = field(default_factory=lambda: str(uuid4()))
    source_section: str = ""
    source_position: int = 0
    source_document_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class CollectorDiagnostic:
    module: str
    severity: str
    message: str
    source: str
    collected_at: str = field(default_factory=utc_now)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class VulnerabilityMatch:
    cve: str
    source: str
    severity: str
    cvss: float | None
    kev: bool
    affected_title: str
    evidence: str
    confidence: str
    remediation: str
    references: list[str] = field(default_factory=list)
    matched_at: str = field(default_factory=utc_now)
    object_uid: str = ""
    applicability: str = "confirmed"
    cpe: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class VulnerabilityCoverage:
    object_uid: str
    state: str
    cpe_status: str
    sources_checked: tuple[str, ...]
    candidate_count: int
    evaluated_count: int
    truncated: bool
    reason: str
    trace: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class VulnerabilityCorrelationResult:
    matches: list[VulnerabilityMatch]
    diagnostics: list[CollectorDiagnostic]
    coverage: dict[str, VulnerabilityCoverage] = field(default_factory=dict)
    snapshots: list[SourceSnapshot] = field(default_factory=list)

    def __iter__(self):
        yield self.matches
        yield self.diagnostics


@dataclass
class ReportRecord:
    run_id: str
    path: str
    report_type: str
    generated_at: str = field(default_factory=utc_now)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class SourceDocument:
    id: str
    report_format: str
    title: str
    path: str
    size_bytes: int
    sha256: str
    imported_at: str = field(default_factory=utc_now)

    @classmethod
    def create(cls, report_format: str, title: str, path: str, size_bytes: int, sha256: str) -> "SourceDocument":
        return cls(str(uuid4()), report_format, title, path, size_bytes, sha256)


@dataclass
class SourceSnapshot:
    id: str
    source: str
    cache_key: str
    path: str
    sha256: str
    fetched_at: str
    status: str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class RuleResult:
    object_uid: str
    rule_id: str
    rule_version: str
    kind: str
    status: str
    severity: str
    title: str
    actual: str
    expected: str
    evidence: str
    confidence: str
    remediation: str
    references: list[str] = field(default_factory=list)
    evaluated_at: str = field(default_factory=utc_now)


@dataclass
class ObjectAssessment:
    object_uid: str
    status: str
    applied_rules: int
    passed_rules: int
    failed_rules: int
    insufficient_rules: int


@dataclass
class CoverageSummary:
    total_objects: int
    risk: int
    passed: int
    insufficient_data: int
    not_applicable: int

    @property
    def evaluated_percent(self) -> int:
        evaluated = self.risk + self.passed
        return round((evaluated / self.total_objects) * 100) if self.total_objects else 0

    @property
    def rule_checked_percent(self) -> int:
        return self.evaluated_percent

    @property
    def classified_objects(self) -> int:
        return self.risk + self.passed + self.insufficient_data + self.not_applicable

    @property
    def document_percent(self) -> int:
        return round((self.classified_objects / self.total_objects) * 100) if self.total_objects else 0


@dataclass(frozen=True)
class ProductIdentity:
    vendor: str
    product: str
    version: str
    kind: str

    def as_tuple(self) -> tuple[str, str, str, str]:
        return self.vendor, self.product, self.version, self.kind


@dataclass(frozen=True)
class WindowsProfile:
    profile_id: str
    caption: str
    version: str
    build: str
    edition: str
    architecture: str
    role: str
    domain_joined: bool | None
