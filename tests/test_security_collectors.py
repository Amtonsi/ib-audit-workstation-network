import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.abspath("src"))

from ib_audit.commands import CommandResult
from ib_audit.models import InventoryObject
from ib_audit.security_collectors import (
    collect_security_posture,
    ensure_category_diagnostics,
    parse_firewall_profiles,
)


class SecurityCollectorTests(unittest.TestCase):
    def test_parses_firewall_profiles_as_individual_objects(self):
        rows = parse_firewall_profiles([
            {"Name": "Domain", "Enabled": True},
            {"Name": "Public", "Enabled": False},
        ])
        self.assertEqual(["Domain", "Public"], [row["Name"] for row in rows])
        self.assertFalse(rows[1]["Enabled"])

    @patch("ib_audit.security_collectors.run_powershell_json")
    def test_security_posture_emits_structured_objects(self, run_ps):
        ok = CommandResult([], 0, "", "")
        run_ps.side_effect = [
            ([{"EnableLUA": 1}], ok),
            ([{"RealTimeProtectionEnabled": True}], ok),
            ([{"EnableSMB1Protocol": False}], ok),
            ([{"fDenyTSConnections": 0, "UserAuthentication": 1}], ok),
            ([{"Name": "Domain", "Enabled": True}], ok),
        ]
        objects, diagnostics = collect_security_posture()
        self.assertEqual(
            {"uac_setting", "defender_status", "smb_configuration", "remote_desktop", "windows_firewall"},
            {obj.object_type for obj in objects},
        )
        self.assertFalse([item for item in diagnostics if item.severity == "error"])

    def test_missing_catalog_categories_get_explicit_diagnostics(self):
        inventory = [InventoryObject("x", "System Overview", "system", "host", {}, "fixture")]
        diagnostics = ensure_category_diagnostics(inventory, [])
        missing = {item.source for item in diagnostics if item.module == "category_coverage"}
        self.assertIn("Installed Software", missing)
        self.assertNotIn("System Overview", missing)
