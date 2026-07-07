from __future__ import annotations

import json
from dataclasses import dataclass, field

from .cancellation import CancellationToken
from .models import (
    CollectorDiagnostic,
    CoverageSummary,
    InventoryObject,
    ObjectAssessment,
    RuleResult,
    SourceSnapshot,
    VulnerabilityCoverage,
    VulnerabilityCorrelationResult,
    VulnerabilityMatch,
    WindowsProfile,
)
from .normalization import detect_windows_profile, product_identity
from .rules import RuleEngine, aggregate_assessments, load_rules_for_profile
from .vulnerabilities import VulnerabilityCorrelator


VERSION_REQUIRED_FOR_VULN_COVERAGE = {
    "software",
    "operating_system",
    "driver",
    "odbc_driver",
    "oledb_provider",
    "bios",
    "base_board",
    "device",
    "display_adapter",
    "network_adapter",
    "physical_disk",
    "processor",
    "network_service",
}


@dataclass
class AssessmentBundle:
    profile: WindowsProfile
    vulnerabilities: list[VulnerabilityMatch]
    rule_results: list[RuleResult]
    assessments: list[ObjectAssessment]
    coverage: CoverageSummary
    diagnostics: list[CollectorDiagnostic]
    snapshots: list[SourceSnapshot]
    vulnerability_coverage: dict[str, VulnerabilityCoverage] = field(default_factory=dict)


class AssessmentService:
    def __init__(self, correlator=None):
        self.correlator = correlator or VulnerabilityCorrelator()

    def assess(
        self,
        inventory: list[InventoryObject],
        progress=None,
        cancel_token: CancellationToken | None = None,
    ) -> AssessmentBundle:
        token = cancel_token or CancellationToken()
        token.raise_if_cancelled()
        profile = detect_windows_profile(inventory)
        rule_results = RuleEngine(load_rules_for_profile(profile.role)).evaluate(inventory, profile)
        correlation = self.correlator.enrich_from_sources(
            inventory,
            progress=progress,
            cancel_token=token,
        )
        if isinstance(correlation, VulnerabilityCorrelationResult):
            vulnerabilities = correlation.matches
            diagnostics = correlation.diagnostics
            vulnerability_coverage = correlation.coverage
            snapshots = correlation.snapshots
        else:
            vulnerabilities, diagnostics = correlation
            vulnerability_coverage = {}
            snapshots = list(getattr(self.correlator, "used_snapshots", []))
        by_title = {item.title: item for item in inventory}
        matched_uids: set[str] = set()
        for match in vulnerabilities:
            token.raise_if_cancelled()
            if not match.object_uid and match.affected_title in by_title:
                match.object_uid = by_title[match.affected_title].uid
            matched_uids.add(match.object_uid)
            rule_results.append(
                RuleResult(
                    match.object_uid, match.cve, match.source, "vulnerability", "risk",
                    match.severity, f"{match.cve}: {match.affected_title}",
                    match.evidence, "vendor fixed version", match.evidence,
                    match.confidence, match.remediation, match.references,
                )
            )
        failed_sources = any(
            item.severity in {"warning", "error"}
            and item.module in {"vulnerability_sources", "fstec_bdu", "vulnerability_correlation"}
            for item in diagnostics
        )
        candidate_types = getattr(self.correlator, "candidate_types", VulnerabilityCorrelator.candidate_types)
        for obj in inventory:
            token.raise_if_cancelled()
            if obj.object_type not in candidate_types or obj.uid in matched_uids:
                continue
            coverage_item = vulnerability_coverage.get(obj.uid)
            if failed_sources:
                status = "insufficient_data"
                actual = "source unavailable"
                evidence = f"{obj.category_name} / {obj.title}"
                confidence = "low"
                remediation = "Update vulnerability sources and verify product name/version."
            elif coverage_item is not None:
                if coverage_item.state == "complete":
                    status = "passed"
                    confidence = "high"
                    remediation = "No action required."
                else:
                    status = "insufficient_data"
                    confidence = "low"
                    remediation = "Update vulnerability sources and verify product name/version."
                actual = coverage_item.reason
                evidence = json.dumps(coverage_item.trace, ensure_ascii=False, sort_keys=True)
            elif obj.object_type not in VERSION_REQUIRED_FOR_VULN_COVERAGE:
                status = "not_applicable"
                actual = "no reliable versioned product identity for automated CVE/BDU matching"
                evidence = f"{obj.category_name} / {obj.title}"
                confidence = "medium"
                remediation = "Review manually only if this inventory item represents a separately updateable product."
            else:
                identity = product_identity(obj)
                complete_identity = bool(identity.product and identity.version)
                if complete_identity:
                    status = "passed"
                    actual = "no known match"
                    confidence = "medium"
                    remediation = "No action required."
                else:
                    status = "insufficient_data"
                    actual = "missing product version"
                    confidence = "low"
                    remediation = "Update vulnerability sources and verify product name/version."
                evidence = f"{obj.category_name} / {obj.title}"
            rule_results.append(
                RuleResult(
                    obj.uid, "VULN-COVERAGE", "1", "vulnerability", status, "info",
                    "Known-vulnerability coverage", actual,
                    "current sources and complete product identity",
                    evidence, confidence, remediation,
                )
            )
        token.raise_if_cancelled()
        assessments, coverage = aggregate_assessments(inventory, rule_results)
        return AssessmentBundle(
            profile, vulnerabilities, rule_results, assessments, coverage,
            diagnostics, snapshots, vulnerability_coverage,
        )
