import os
import sys
import unittest

sys.path.insert(0, os.path.abspath("src"))

from ib_audit.models import InventoryObject, WindowsProfile
from ib_audit.rules import RuleEngine, aggregate_assessments, load_rules_for_profile


PROFILE = WindowsProfile("windows-26100-workstation", "Windows 11", "10.0", "26100", "Pro", "x64", "workstation", False)


class RuleEngineTests(unittest.TestCase):
    def setUp(self):
        self.engine = RuleEngine(load_rules_for_profile("workstation"))

    def test_uac_disabled_is_a_risk_with_field_evidence(self):
        obj = InventoryObject("security", "Security Settings", "uac_setting", "UAC", {"EnableLUA": "0"}, "fixture")
        result = next(item for item in self.engine.evaluate([obj], PROFILE) if item.rule_id == "CFG-UAC-001")
        self.assertEqual("risk", result.status)
        self.assertIn("EnableLUA=0", result.evidence)

    def test_missing_driver_signature_is_insufficient_not_passed(self):
        obj = InventoryObject("drivers", "Services and Drivers", "driver", "Driver", {"DriverVersion": "1.0"}, "fixture")
        result = next(item for item in self.engine.evaluate([obj], PROFILE) if item.rule_id == "EXP-DRV-001")
        self.assertEqual("insufficient_data", result.status)

    def test_user_writable_autorun_path_is_a_risk(self):
        obj = InventoryObject(
            "startup", "Startup Programs", "startup_program", "Agent",
            {"Command": r"C:\Users\Public\agent.exe"}, "fixture",
        )
        result = next(item for item in self.engine.evaluate([obj], PROFILE) if item.rule_id == "EXP-AUTORUN-001")
        self.assertEqual("risk", result.status)

    def test_active_setup_stubpath_is_used_as_autorun_command(self):
        obj = InventoryObject(
            "s", "Active Setup", "active_setup", "Active Component",
            {"StubPath": r"C:\Windows\System32\rundll32.exe setup.dll,Install"}, "fixture",
        )
        result = next(item for item in self.engine.evaluate([obj], PROFILE) if item.rule_id == "EXP-AUTORUN-001")
        self.assertEqual("passed", result.status)
        self.assertIn("StubPath", result.evidence)

    def test_industrial_protocol_open_port_is_reported_as_risk(self):
        obj = InventoryObject(
            "ports",
            "Open Ports",
            "open_port",
            "Modbus TCP",
            {"Local Port": "502", "Local Address": "0.0.0.0", "Port Protocol": "TCP"},
            "fixture",
        )

        result = next(item for item in self.engine.evaluate([obj], PROFILE) if item.rule_id == "EXP-ICS-001")

        self.assertEqual("risk", result.status)
        self.assertEqual("high", result.severity)
        self.assertIn("industrial", result.title.casefold())

    def test_user_password_age_warns_after_60_days_and_critical_after_90_days(self):
        fresh = InventoryObject("users", "Users", "user", "fresh", {"PasswordAgeDays": "60"}, "fixture")
        stale = InventoryObject("users", "Users", "user", "stale", {"PasswordAgeDays": "61"}, "fixture")
        critical = InventoryObject("users", "Users", "user", "critical", {"PasswordAgeDays": "91"}, "fixture")

        results = self.engine.evaluate([fresh, stale, critical], PROFILE)
        by_title = {}
        for result in results:
            if result.rule_id == "CFG-PASS-AGE-001":
                by_title[result.evidence.split(" / ")[1]] = result

        self.assertEqual("passed", by_title["fresh"].status)
        self.assertEqual("risk", by_title["stale"].status)
        self.assertEqual("warning", by_title["stale"].severity)
        self.assertEqual("risk", by_title["critical"].status)
        self.assertEqual("critical", by_title["critical"].severity)

    def test_every_object_gets_exactly_one_summary(self):
        safe = InventoryObject("security", "Security Settings", "uac_setting", "UAC", {"EnableLUA": "1"}, "fixture")
        info = InventoryObject("memory", "Memory", "memory_module", "DIMM 0", {"Capacity": "8 GB"}, "fixture")
        results = self.engine.evaluate([safe, info], PROFILE)
        assessments, coverage = aggregate_assessments([safe, info], results)
        self.assertEqual(2, len(assessments))
        self.assertEqual("passed", assessments[0].status)
        self.assertEqual("not_applicable", assessments[1].status)
        self.assertEqual(2, coverage.total_objects)
