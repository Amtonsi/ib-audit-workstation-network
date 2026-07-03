import os
import sys
import unittest

sys.path.insert(0, os.path.abspath("src"))

from ib_audit.models import InventoryObject
from ib_audit.normalization import detect_windows_profile, product_identity


class NormalizationTests(unittest.TestCase):
    def test_driver_identity_uses_provider_name_and_driver_version(self):
        obj = InventoryObject(
            "services-and-drivers", "Services and Drivers", "driver",
            "Example Display Driver",
            {"DriverProviderName": "Example Corp", "DriverVersion": "31.2.4"},
            "fixture",
        )
        self.assertEqual(
            ("Example Corp", "Example Display Driver", "31.2.4", "driver"),
            product_identity(obj).as_tuple(),
        )

    def test_detects_server_profile_from_product_type(self):
        inventory = [
            InventoryObject(
                "operating-system", "Operating System", "operating_system",
                "Windows Server 2025",
                {"Caption": "Microsoft Windows Server 2025", "BuildNumber": "26100", "ProductType": "3"},
                "fixture",
            )
        ]
        profile = detect_windows_profile(inventory)
        self.assertEqual("server", profile.role)
        self.assertEqual("26100", profile.build)

    def test_missing_version_is_explicit(self):
        obj = InventoryObject("s", "Installed Software", "software", "Tool", {"Publisher": "Vendor"}, "fixture")
        self.assertEqual("", product_identity(obj).version)

    def test_bios_identity_reads_spaced_vendor_and_version(self):
        obj = InventoryObject(
            "bios",
            "BIOS Version",
            "bios",
            "BIOS Version",
            {"BIOS Vendor": "Dell Inc.", "BIOS Version": "2.11.0"},
            "fixture",
        )
        identity = product_identity(obj)
        self.assertEqual("Dell Inc.", identity.vendor)
        self.assertEqual("2.11.0", identity.version)

    def test_disk_identity_reads_firmware_revision(self):
        obj = InventoryObject(
            "disk",
            "Physical Disks",
            "physical_disk",
            "Samsung SSD",
            {"Model": "Samsung SSD 870 EVO", "Firmware Revision": "SVT03B6Q"},
            "fixture",
        )
        self.assertEqual("SVT03B6Q", product_identity(obj).version)

    def test_device_identity_reads_spaced_driver_version(self):
        obj = InventoryObject(
            "device",
            "Devices",
            "device",
            "AMD FirePro 2270",
            {"Driver Version": "14.301.1019.0"},
            "fixture",
        )
        self.assertEqual("14.301.1019.0", product_identity(obj).version)
