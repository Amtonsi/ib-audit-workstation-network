from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from uuid import uuid4

from .assessment import AssessmentBundle
from .models import (
    AuditRun,
    CollectorDiagnostic,
    CoverageSummary,
    InventoryObject,
    RuleResult,
    utc_now,
)


SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}


@dataclass(frozen=True)
class BatchProgress:
    index: int
    total: int
    stage: str
    source_path: Path
    hostname: str = ""


@dataclass
class BatchDocumentResult:
    source_path: Path
    source_format: str
    run: AuditRun
    inventory: list[InventoryObject]
    diagnostics: list[CollectorDiagnostic]
    assessment: AssessmentBundle


@dataclass(frozen=True)
class BatchDocumentFailure:
    source_path: Path
    message: str
    stage: str = "import"


@dataclass(frozen=True)
class CommonFinding:
    key: str
    kind: str
    severity: str
    title: str
    evidence: str
    remediation: str
    references: list[str]
    hostnames: list[str]


@dataclass
class BatchAssessment:
    id: str
    started_at: str
    finished_at: str
    status: str
    selected_paths: list[Path]
    completed: list[BatchDocumentResult]
    failures: list[BatchDocumentFailure]
    coverage: CoverageSummary
    severity_counts: dict[str, int]
    common_findings: list[CommonFinding]

    @classmethod
    def create(
        cls,
        selected_paths: list[Path],
        completed: list[BatchDocumentResult],
        failures: list[BatchDocumentFailure],
        status: str,
        started_at: str | None = None,
    ) -> "BatchAssessment":
        coverage = CoverageSummary(
            total_objects=sum(item.assessment.coverage.total_objects for item in completed),
            risk=sum(item.assessment.coverage.risk for item in completed),
            passed=sum(item.assessment.coverage.passed for item in completed),
            insufficient_data=sum(
                item.assessment.coverage.insufficient_data for item in completed
            ),
            not_applicable=sum(
                item.assessment.coverage.not_applicable for item in completed
            ),
        )
        severity_counts = {name: 0 for name in SEVERITY_ORDER}
        grouped: dict[str, dict[str, object]] = {}
        for document in completed:
            hostname = document.run.hostname
            for result in document.assessment.rule_results:
                if result.status != "risk":
                    continue
                severity = result.severity.casefold()
                if severity not in severity_counts:
                    severity = "info"
                severity_counts[severity] += 1
                key = result.rule_id
                group = grouped.setdefault(
                    key,
                    {
                        "result": result,
                        "severity": severity,
                        "hostnames": [],
                    },
                )
                current_severity = str(group["severity"])
                if SEVERITY_ORDER[severity] < SEVERITY_ORDER[current_severity]:
                    group["severity"] = severity
                hostnames = group["hostnames"]
                if isinstance(hostnames, list) and hostname not in hostnames:
                    hostnames.append(hostname)
        common_findings = []
        for key, group in grouped.items():
            result = group["result"]
            if not isinstance(result, RuleResult):
                continue
            hostnames = group["hostnames"]
            common_findings.append(
                CommonFinding(
                    key=key,
                    kind=result.kind,
                    severity=str(group["severity"]),
                    title=result.title,
                    evidence=result.evidence,
                    remediation=result.remediation,
                    references=list(result.references),
                    hostnames=sorted(
                        [str(item) for item in hostnames],
                        key=str.casefold,
                    ),
                )
            )
        common_findings.sort(
            key=lambda item: (
                SEVERITY_ORDER.get(item.severity, SEVERITY_ORDER["info"]),
                item.key.casefold(),
            )
        )
        return cls(
            id=str(uuid4()),
            started_at=started_at or utc_now(),
            finished_at=utc_now(),
            status=status,
            selected_paths=list(selected_paths),
            completed=list(completed),
            failures=list(failures),
            coverage=coverage,
            severity_counts=severity_counts,
            common_findings=common_findings,
        )

    @property
    def selected_count(self) -> int:
        return len(self.selected_paths)

    @property
    def processed_count(self) -> int:
        return len(self.completed)

    @property
    def failed_count(self) -> int:
        return len(self.failures)


def normalize_report_paths(values) -> list[Path]:
    result: list[Path] = []
    seen: set[str] = set()
    for value in values:
        path = Path(value)
        key = str(path.resolve(strict=False)).casefold()
        if key in seen:
            continue
        seen.add(key)
        result.append(path)
    return result


__all__ = [
    "BatchAssessment",
    "BatchDocumentFailure",
    "BatchDocumentResult",
    "BatchProgress",
    "CommonFinding",
    "normalize_report_paths",
]
