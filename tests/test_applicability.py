import os
import sys
import unittest

sys.path.insert(0, os.path.abspath("src"))

from ib_audit.applicability import CpeApplicabilityEvaluator
from ib_audit.identity import InventoryIdentity


class CpeApplicabilityEvaluatorTests(unittest.TestCase):
    def test_and_tree_links_vulnerable_firmware_to_matching_hardware(self):
        identity = InventoryIdentity(
            object_uid="cpu-1",
            object_type="processor",
            vendor="intel",
            product="intel xeon e5620",
            version="",
            model="e5620",
            variants=("xeon e5620", "e5620 firmware", "e5620 microcode"),
            hardware_ids=(),
        )

        result = CpeApplicabilityEvaluator().evaluate(
            [
                {
                    "operator": "AND",
                    "nodes": [
                        {
                            "cpeMatch": [
                                {
                                    "vulnerable": False,
                                    "criteria": "cpe:2.3:h:intel:xeon:e5620:*:*:*:*:*:*:*",
                                }
                            ]
                        },
                        {
                            "cpeMatch": [
                                {
                                    "vulnerable": True,
                                    "criteria": "cpe:2.3:o:intel:xeon_e5620_firmware:*:*:*:*:*:*:*:*",
                                    "versionEndExcluding": "2.0",
                                }
                            ]
                        },
                    ],
                }
            ],
            target=identity,
            host_identities=[identity],
        )

        self.assertEqual("potential", result.state)
        self.assertEqual("hardware matched; firmware version is unknown", result.reason)

    def test_or_tree_accepts_one_affected_software_branch(self):
        identity = InventoryIdentity(
            object_uid="sql-1",
            object_type="software",
            vendor="microsoft",
            product="sql server 2012 common files",
            version="11.1.3000.0",
            model="",
            variants=("sql server 2012",),
            hardware_ids=(),
        )

        result = CpeApplicabilityEvaluator().evaluate(
            [
                {
                    "operator": "OR",
                    "nodes": [
                        {
                            "cpeMatch": [
                                {
                                    "vulnerable": True,
                                    "criteria": "cpe:2.3:a:microsoft:sql_server:*:*:*:*:*:*:*:*",
                                    "versionEndExcluding": "11.2",
                                }
                            ]
                        },
                        {
                            "cpeMatch": [
                                {
                                    "vulnerable": True,
                                    "criteria": "cpe:2.3:a:microsoft:exchange_server:*:*:*:*:*:*:*:*",
                                }
                            ]
                        },
                    ],
                }
            ],
            target=identity,
            host_identities=[identity],
        )

        self.assertEqual("confirmed", result.state)

    def test_negated_platform_branch_blocks_match(self):
        target = InventoryIdentity(
            object_uid="app-1",
            object_type="software",
            vendor="example",
            product="example agent",
            version="1.0",
            model="",
            variants=("example agent",),
            hardware_ids=(),
        )
        blocked_platform = InventoryIdentity(
            object_uid="os-1",
            object_type="operating_system",
            vendor="microsoft",
            product="windows server 2008 r2",
            version="6.1",
            model="",
            variants=("windows server 2008 r2",),
            hardware_ids=(),
        )

        result = CpeApplicabilityEvaluator().evaluate(
            [
                {
                    "operator": "AND",
                    "nodes": [
                        {
                            "cpeMatch": [
                                {
                                    "vulnerable": True,
                                    "criteria": "cpe:2.3:a:example:example_agent:*:*:*:*:*:*:*:*",
                                }
                            ]
                        },
                        {
                            "negate": True,
                            "cpeMatch": [
                                {
                                    "vulnerable": False,
                                    "criteria": "cpe:2.3:o:microsoft:windows_server_2008_r2:*:*:*:*:*:*:*:*",
                                }
                            ],
                        },
                    ],
                }
            ],
            target=target,
            host_identities=[target, blocked_platform],
        )

        self.assertEqual("not_affected", result.state)
