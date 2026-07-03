import os
import sys
import unittest

sys.path.insert(0, os.path.abspath("src"))

from ib_audit.identity import InventoryIdentityResolver
from ib_audit.models import InventoryObject


class InventoryIdentityResolverTests(unittest.TestCase):
    def test_software_identity_keeps_product_family_and_installed_version(self):
        obj = InventoryObject(
            "s",
            "Installed Software",
            "software",
            "Acronis Backup 11.7 Agent Core",
            {"Vendor": "Acronis", "Version": "11.7.50058"},
            "fixture",
        )

        identity = InventoryIdentityResolver().resolve(obj, [obj])

        self.assertEqual("acronis", identity.vendor)
        self.assertEqual("acronis backup 11.7 agent core", identity.product)
        self.assertEqual("11.7.50058", identity.version)

    def test_device_identity_reads_spaced_driver_version_and_pci_id(self):
        obj = InventoryObject(
            "z",
            "Devices",
            "device",
            "Display adapter",
            {
                "Description": "AMD FirePro 2270",
                "Manufacturer": "Advanced Micro Devices, Inc.",
                "Driver Version": "14.301.1019.0",
                "Device ID": r"PCI\VEN_1002&DEV_68F2&SUBSYS_01261028&REV_00",
            },
            "fixture",
        )

        identity = InventoryIdentityResolver().resolve(obj, [obj])

        self.assertEqual("14.301.1019.0", identity.version)
        self.assertEqual(("pci:1002:68f2:01261028",), identity.hardware_ids)

    def test_processor_identity_extracts_exact_model_without_clock_noise(self):
        obj = InventoryObject(
            "p",
            "Processors",
            "processor",
            "Intel(R) Xeon(R) CPU E5620 @ 2.40GHz",
            {"Manufacturer": "Intel(R) Corporation"},
            "fixture",
        )

        identity = InventoryIdentityResolver().resolve(obj, [obj])

        self.assertEqual("intel", identity.vendor)
        self.assertEqual("e5620", identity.model)
        self.assertIn("xeon e5620", identity.variants)
