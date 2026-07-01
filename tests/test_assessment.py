import os
import sys
import unittest

sys.path.insert(0, os.path.abspath("src"))

from ib_audit.assessment import AssessmentService
from ib_audit.cancellation import AuditCancelled, CancellationToken
from ib_audit.models import CollectorDiagnostic, InventoryObject


class FakeCorrelator:
    used_snapshots = []

    def enrich_from_sources(self, inventory, progress=None, cancel_token=None):
        return [], [CollectorDiagnostic("vulnerability_sources", "warning", "offline", "fixture")]


class OnlineNoMatchCorrelator:
    used_snapshots = []
    candidate_types = {"software", "operating_system", "service", "driver", "odbc_driver", "oledb_provider", "bios", "device"}

    def enrich_from_sources(self, inventory, progress=None, cancel_token=None):
        return [], []


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

    def test_unversioned_device_is_not_marked_insufficient_only_for_cve_coverage(self):
        inventory = [
            InventoryObject("z", "Devices", "device", "Keyboard", {"Name": "Keyboard"}, "fixture")
        ]

        bundle = AssessmentService(correlator=OnlineNoMatchCorrelator()).assess(inventory)

        coverage_rule = next(item for item in bundle.rule_results if item.rule_id == "VULN-COVERAGE")
        self.assertEqual("not_applicable", coverage_rule.status)
        self.assertEqual("not_applicable", bundle.assessments[0].status)
        self.assertEqual(1, bundle.coverage.not_applicable)
