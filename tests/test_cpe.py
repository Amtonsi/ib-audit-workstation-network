import os
import sys
import unittest

sys.path.insert(0, os.path.abspath("src"))

from ib_audit.cpe import CpeName, compare_version


class CpeTests(unittest.TestCase):
    def test_parse_cpe_preserves_hardware_model_in_version_component(self):
        cpe = CpeName.parse("cpe:2.3:h:intel:xeon:e5620:*:*:*:*:*:*:*")
        self.assertEqual(
            ("h", "intel", "xeon", "e5620"),
            (cpe.part, cpe.vendor, cpe.product, cpe.version),
        )

    def test_version_range_marks_old_acronis_release_affected(self):
        decision = compare_version(
            "11.7.50058",
            cpe_version="*",
            version_end_including="12.5",
        )
        self.assertEqual("affected", decision.state)

    def test_version_range_rejects_fixed_release(self):
        decision = compare_version(
            "12.5.16342",
            cpe_version="*",
            version_end_excluding="12.5.16342",
        )
        self.assertEqual("not_affected", decision.state)

    def test_missing_firmware_version_is_explicit(self):
        decision = compare_version(
            "",
            cpe_version="*",
            version_end_excluding="2.0",
        )
        self.assertEqual("unknown_version", decision.state)
