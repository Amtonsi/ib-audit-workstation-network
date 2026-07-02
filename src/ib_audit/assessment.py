from __future__ import annotations

from dataclasses import dataclass

from .cancellation import CancellationToken
from .models import (
    CollectorDiagnostic,
    CoverageSummary,
    InventoryObject,
    ObjectAssessment,
    RuleResult,
    SourceSnapshot,
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
        vulnerabilities, diagnostics = self.correlator.enrich_from_sources(
            inventory,
            progress=progress,
            cancel_token=token,
        )
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
            identity = product_identity(obj)
            complete_identity = bool(identity.product and identity.version)
            if failed_sources:
                status = "insufficient_data"
                actual = "source unavailable"
                confidence = "low"
                remediation = "Update vulnerability sources and verify product name/version."
            elif complete_identity:
                status = "passed"
                actual = "no known match"
                confidence = "medium"
                remediation = "No action required."
            elif obj.object_type not in VERSION_REQUIRED_FOR_VULN_COVERAGE:
                status = "not_applicable"
                actual = "no reliable versioned product identity for automated CVE/BDU matching"
                confidence = "medium"
                remediation = "Review manually only if this inventory item represents a separately updateable product."
            else:
                status = "insufficient_data"
                actual = "missing product version"
                confidence = "low"
                remediation = "Update vulnerability sources and verify product name/version."
            rule_results.append(
                RuleResult(
                    obj.uid, "VULN-COVERAGE", "1", "vulnerability", status, "info",
                    "Known-vulnerability coverage", actual,
                    "current sources and complete product identity",
                    f"{obj.category_name} / {obj.title}", confidence, remediation,
                )
            )
        token.raise_if_cancelled()
        assessments, coverage = aggregate_assessments(inventory, rule_results)
        return AssessmentBundle(
            profile, vulnerabilities, rule_results, assessments, coverage,
            diagnostics, list(getattr(self.correlator, "used_snapshots", [])),
        )
