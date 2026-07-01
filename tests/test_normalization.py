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
