import os
import sys
import unittest

sys.path.insert(0, os.path.abspath("src"))

from ib_audit.assessment import AssessmentService
from ib_audit.cancellation import AuditCancelled, CancellationToken
from ib_audit.models import (
    CollectorDiagnostic,
    InventoryObject,
    VulnerabilityCoverage,
    VulnerabilityCorrelationResult,
    VulnerabilityMatch,
)


class FakeCorrelator:
    used_snapshots = []

    def enrich_from_sources(self, inventory, progress=None, cancel_token=None):
        return [], [CollectorDiagnostic("vulnerability_sources", "warning", "offline", "fixture")]


class OnlineNoMatchCorrelator:
    used_snapshots = []
    candidate_types = {"software", "operating_system", "service", "driver", "odbc_driver", "oledb_provider", "bios", "device"}

    def enrich_from_sources(self, inventory, progress=None, cancel_token=None):
        return [], []


class UnresolvedCpeCorrelator:
    used_snapshots = []
    candidate_types = {"software"}

    def enrich_from_sources(self, inventory, progress=None, cancel_token=None):
        obj = inventory[0]
        return VulnerabilityCorrelationResult(
            [],
            [],
            {
                obj.uid: VulnerabilityCoverage(
                    obj.uid, "incomplete", "not_found", ("NVD",), 0, 0, False,
                    "no CPE candidate passed the confidence threshold",
                )
            },
        )


class CompleteNoMatchCorrelator:
    used_snapshots = []
    candidate_types = {"software"}

    def enrich_from_sources(self, inventory, progress=None, cancel_token=None):
        obj = inventory[0]
        return VulnerabilityCorrelationResult(
            [],
            [],
            {
                obj.uid: VulnerabilityCoverage(
                    obj.uid, "complete", "resolved", ("NVD",), 1, 1, False,
                    "CPE candidates evaluated",
                )
            },
        )


class NetworkServiceCompleteCorrelator:
    used_snapshots = []
    candidate_types = {"network_service"}

    def enrich_from_sources(self, inventory, progress=None, cancel_token=None):
        obj = inventory[0]
        return VulnerabilityCorrelationResult(
            [],
            [],
            {
                obj.uid: VulnerabilityCoverage(
                    obj.uid, "complete", "resolved", ("NVD",), 1, 1, False,
                    "CPE candidates evaluated",
                )
            },
        )


class PotentialHardwareCorrelator:
    used_snapshots = []
    candidate_types = {"processor"}

    def enrich_from_sources(self, inventory, progress=None, cancel_token=None):
        obj = inventory[0]
        return VulnerabilityCorrelationResult(
            [
                VulnerabilityMatch(
                    cve="CVE-2099-8800",
                    source="NVD",
                    severity="HIGH",
                    cvss=8.1,
                    kev=False,
                    affected_title=obj.title,
                    evidence="hardware matched; firmware version is unknown",
                    confidence="Medium",
                    remediation="Apply vendor security updates.",
                    object_uid=obj.uid,
                    applicability="potential",
                    cpe="cpe:2.3:o:intel:xeon_e5620_firmware:*:*:*:*:*:*:*:*",
                )
            ],
            [],
            {
                obj.uid: VulnerabilityCoverage(
                    obj.uid, "complete", "resolved", ("NVD",), 1, 1, False,
                    "CPE candidates evaluated",
                )
            },
        )


class AssessmentServiceTests(unittest.TestCase):
    def test_assessment_stops_when_token_is_cancelled(self):
        token = CancellationToken()
        token.cancel()

        with self.assertRaises(AuditCancelled):
            AssessmentService(correlator=FakeCorrelator()).assess([], cancel_token=token)

    def test_every_object_gets_one_summary_even_when_sources_are_offline(self):
        inventory = [
            InventoryObject("s", "Installed Software", "software", "Tool", {"DisplayVersion": "1.0"}, "fixture"),
            InventoryObject("m", "Memory", "memory_module", "DIMM", {"Capacity": "8 GB"}, "fixture"),
        ]
        bundle = AssessmentService(correlator=FakeCorrelator()).assess(inventory)
        self.assertEqual(2, len(bundle.assessments))
        self.assertEqual(2, bundle.coverage.total_objects)
        self.assertEqual({item.uid for item in inventory}, {item.object_uid for item in bundle.assessments})
        self.assertEqual("insufficient_data", bundle.assessments[0].status)
        self.assertEqual("not_applicable", bundle.assessments[1].status)

    def test_configuration_risk_and_vulnerability_results_share_one_bundle(self):
        inventory = [
            InventoryObject("security", "Security Settings", "uac_setting", "UAC", {"EnableLUA": "0"}, "fixture")
        ]
        bundle = AssessmentService(correlator=FakeCorrelator()).assess(inventory)
        self.assertTrue(any(item.rule_id == "CFG-UAC-001" and item.status == "risk" for item in bundle.rule_results))
        self.assertEqual("risk", bundle.assessments[0].status)

    def test_unversioned_device_is_marked_insufficient_for_hardware_cve_coverage(self):
        inventory = [
            InventoryObject("z", "Devices", "device", "Keyboard", {"Name": "Keyboard"}, "fixture")
        ]

        bundle = AssessmentService(correlator=OnlineNoMatchCorrelator()).assess(inventory)

        coverage_rule = next(item for item in bundle.rule_results if item.rule_id == "VULN-COVERAGE")
        self.assertEqual("insufficient_data", coverage_rule.status)
        self.assertEqual("missing product version", coverage_rule.actual)
        self.assertEqual("insufficient_data", bundle.assessments[0].status)
        self.assertEqual(1, bundle.coverage.insufficient_data)

    def test_complete_identity_without_cpe_resolution_is_not_passed(self):
        software = InventoryObject(
            "s", "Installed Software", "software", "Example Tool",
            {"Vendor": "Example", "Version": "1.0"},
            "fixture",
        )

        bundle = AssessmentService(correlator=UnresolvedCpeCorrelator()).assess([software])

        self.assertEqual("insufficient_data", bundle.assessments[0].status)
        coverage_rule = next(item for item in bundle.rule_results if item.rule_id == "VULN-COVERAGE")
        self.assertEqual("no CPE candidate passed the confidence threshold", coverage_rule.actual)

    def test_complete_no_match_coverage_is_passed(self):
        software = InventoryObject(
            "s", "Installed Software", "software", "Example Tool",
            {"Vendor": "Example", "Version": "1.0"},
            "fixture",
        )

        bundle = AssessmentService(correlator=CompleteNoMatchCorrelator()).assess([software])

        self.assertEqual("passed", bundle.assessments[0].status)

    def test_network_service_is_covered_by_vulnerability_assessment(self):
        service = InventoryObject(
            "N",
            "Network Service Discovery",
            "network_service",
            "192.168.1.20 443/TCP nginx",
            {
                "Service Product": "nginx",
                "Service Version": "1.18.0",
                "Port": "443",
                "Protocol": "TCP",
            },
            "nmap",
        )

        bundle = AssessmentService(correlator=NetworkServiceCompleteCorrelator()).assess([service])

        self.assertEqual("passed", bundle.assessments[0].status)
        coverage_rule = next(item for item in bundle.rule_results if item.rule_id == "VULN-COVERAGE")
        self.assertEqual("passed", coverage_rule.status)

    def test_potential_hardware_match_is_risk(self):
        processor = InventoryObject(
            "p", "Processors", "processor", "Intel(R) Xeon(R) CPU E5620 @ 2.40GHz",
            {"Manufacturer": "Intel(R) Corporation"},
            "fixture",
        )

        bundle = AssessmentService(correlator=PotentialHardwareCorrelator()).assess([processor])

        self.assertEqual("risk", bundle.assessments[0].status)
        self.assertEqual("potential", bundle.vulnerabilities[0].applicability)
