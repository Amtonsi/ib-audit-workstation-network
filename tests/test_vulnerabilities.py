import os
import gzip
import json
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

sys.path.insert(0, os.path.abspath("src"))

from ib_audit.cancellation import AuditCancelled, CancellationToken
from ib_audit.models import CollectorDiagnostic, InventoryObject, VulnerabilityMatch
from ib_audit.source_cache import SnapshotCache
from ib_audit.vulnerabilities import (
    VulnerabilityCorrelator,
    VulnerabilityDatabaseSourceClient,
    VulnerabilitySourceClient,
)
from ib_audit.vulnerability_database import DownloadedSource, VulnerabilityDatabaseBuilder


class VulnerabilityCorrelatorTests(unittest.TestCase):
    def test_enrichment_stops_before_source_fetch_when_cancelled(self):
        token = CancellationToken()
        token.cancel()
        client = Mock()

        with self.assertRaises(AuditCancelled):
            VulnerabilityCorrelator().enrich_from_sources(
                [], client=client, cancel_token=token
            )

        client.fetch_cisa_kev.assert_not_called()

    def test_driver_matches_nvd_cpe_and_links_object(self):
        driver = InventoryObject(
            "drivers", "Services and Drivers", "driver", "Example Driver",
            {"DriverProviderName": "Example", "DriverVersion": "1.5"}, "fixture",
        )
        record = {
            "id": "CVE-2099-7000",
            "configurations": [{"nodes": [{"cpeMatch": [{
                "vulnerable": True,
                "criteria": "cpe:2.3:a:example:example_driver:*:*:*:*:*:*:*:*",
                "versionEndExcluding": "2.0",
            }]}]}],
            "descriptions": [{"lang": "en", "value": "Example Driver before 2.0 is vulnerable."}],
        }
        matches = VulnerabilityCorrelator().match_inventory([driver], [], [record])
        self.assertEqual("CVE-2099-7000", matches[0].cve)
        self.assertEqual(driver.uid, matches[0].object_uid)

    def test_nvd_version_range_rejects_fixed_driver(self):
        driver = InventoryObject(
            "drivers", "Services and Drivers", "driver", "Example Driver",
            {"DriverProviderName": "Example", "DriverVersion": "2.1"}, "fixture",
        )
        record = {
            "id": "CVE-2099-7000",
            "configurations": [{"nodes": [{"cpeMatch": [{
                "vulnerable": True,
                "criteria": "cpe:2.3:a:example:example_driver:*:*:*:*:*:*:*:*",
                "versionEndExcluding": "2.0",
            }]}]}],
            "descriptions": [{"lang": "en", "value": "Example Driver before 2.0 is vulnerable."}],
        }
        self.assertEqual([], VulnerabilityCorrelator().match_inventory([driver], [], [record]))

    def test_nested_nvd_cpe_configuration_matches_hardware(self):
        bios = InventoryObject(
            "bios", "BIOS Version", "bios", "Example BIOS",
            {"Manufacturer": "Example", "BIOS Version": "1.5"}, "fixture",
        )
        record = {
            "id": "CVE-2099-7010",
            "configurations": [{"nodes": [{
                "operator": "OR",
                "children": [{"cpeMatch": [{
                    "vulnerable": True,
                    "criteria": "cpe:2.3:h:example:example_bios:*:*:*:*:*:*:*:*",
                    "versionEndExcluding": "2.0",
                }]}],
            }]}],
            "descriptions": [{"lang": "en", "value": "Example BIOS before 2.0 is vulnerable."}],
        }

        matches = VulnerabilityCorrelator().match_inventory([bios], [], [record])

        self.assertEqual("CVE-2099-7010", matches[0].cve)
        self.assertEqual(bios.uid, matches[0].object_uid)

    def test_exact_cpe_version_rejects_different_installed_version(self):
        software = InventoryObject(
            "s", "Installed Software", "software", "Widget Tool",
            {"Vendor": "WidgetCo", "Version": "2.0"}, "fixture",
        )
        record = {
            "id": "CVE-2099-7020",
            "configurations": [{"nodes": [{"cpeMatch": [{
                "vulnerable": True,
                "criteria": "cpe:2.3:a:widgetco:widget_tool:1.0:*:*:*:*:*:*:*",
            }]}]}],
            "descriptions": [{"lang": "en", "value": "Widget Tool 1.0 is vulnerable."}],
        }

        self.assertEqual([], VulnerabilityCorrelator().match_inventory([software], [], [record]))

    def test_nvd_configuration_match_requires_installed_version(self):
        service = InventoryObject(
            "svc", "Services", "service", "Google Chrome Elevation Service",
            {"Name": "GoogleChromeElevationService", "CompanyName": "Google"}, "fixture",
        )
        record = {
            "id": "CVE-2099-7030",
            "configurations": [{"nodes": [{"cpeMatch": [{
                "vulnerable": True,
                "criteria": "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*",
                "versionEndExcluding": "120.0",
            }]}]}],
            "descriptions": [{"lang": "en", "value": "Google Chrome before 120 is vulnerable."}],
        }

        self.assertEqual([], VulnerabilityCorrelator().match_inventory([service], [], [record]))

    def test_database_records_do_not_fall_back_to_description_when_cpe_misses(self):
        software = InventoryObject(
            "s", "Installed Software", "software", "Widget Tool",
            {"Vendor": "WidgetCo", "Version": "2.0"}, "fixture",
        )
        record = {
            "id": "CVE-2099-7040",
            "_ib_match_requires_configuration": True,
            "configurations": [{"nodes": [{"cpeMatch": [{
                "vulnerable": True,
                "criteria": "cpe:2.3:a:other_vendor:other_tool:*:*:*:*:*:*:*:*",
            }]}]}],
            "descriptions": [{"lang": "en", "value": "Widget Tool 2.0 is mentioned in this text."}],
        }

        self.assertEqual([], VulnerabilityCorrelator().match_inventory([software], [], [record]))

    def test_generic_legacy_windows_cpe_does_not_match_modern_windows(self):
        os_item = InventoryObject(
            "os", "Operating System", "operating_system", "Microsoft Windows 11 Pro",
            {"Manufacturer": "Microsoft Corporation", "Version": "10.0.26200"}, "fixture",
        )
        record = {
            "id": "CVE-1999-0511",
            "configurations": [{"nodes": [{"cpeMatch": [{
                "vulnerable": True,
                "criteria": "cpe:2.3:o:microsoft:windows_nt:*:*:*:*:*:*:*:*",
            }]}]}],
            "descriptions": [{"lang": "en", "value": "Legacy Windows NT vulnerability."}],
        }

        self.assertEqual([], VulnerabilityCorrelator().match_inventory([os_item], [], [record]))

    def test_source_client_uses_cached_kev_offline(self):
        with tempfile.TemporaryDirectory() as temp:
            cache = SnapshotCache(Path(temp))
            cache.store_json("cisa-kev", "catalog", {"vulnerabilities": [{"cveID": "CVE-CACHED"}]})
            client = VulnerabilitySourceClient(cache=cache, online=False)
            records, diagnostics = client.fetch_cisa_kev()
        self.assertEqual("CVE-CACHED", records[0]["cveID"])
        self.assertEqual("cached", diagnostics[0].message)
        self.assertEqual(1, len(client.used_snapshots))
    def test_matches_kev_record_by_product_text(self):
        inventory = [
            InventoryObject(
                category_id="s",
                category_name="Installed Software",
                object_type="software",
                title="Example Browser",
                fields={"Version": "1.0", "Vendor": "Example"},
                source="fixture",
            )
        ]
        kev_records = [
            {
                "cveID": "CVE-2099-1234",
                "vendorProject": "Example",
                "product": "Example Browser",
                "vulnerabilityName": "Example Browser RCE",
                "requiredAction": "Apply updates per vendor instructions",
                "notes": "https://example.test/advisory",
            }
        ]
        matches = VulnerabilityCorrelator().match_inventory(inventory, kev_records=kev_records, nvd_records=[])
        self.assertEqual(matches[0].cve, "CVE-2099-1234")
        self.assertTrue(matches[0].kev)
        self.assertEqual(matches[0].confidence, "Medium")
        self.assertIn("Apply updates", matches[0].remediation)

    def test_kev_matching_uses_product_identity_not_install_paths(self):
        inventory = [
            InventoryObject(
                category_id="s",
                category_name="Installed Software",
                object_type="software",
                title="Kaspersky Password Manager",
                fields={"Publisher": "AO Kaspersky Lab", "UninstallString": r"C:\Windows\Installer\kpm.msi"},
                source="fixture",
            ),
            InventoryObject(
                category_id="o",
                category_name="Operating System",
                object_type="operating_system",
                title="Microsoft Windows 11 Pro",
                fields={"Manufacturer": "Microsoft Corporation", "Version": "10.0.26200"},
                source="fixture",
            ),
        ]
        kev_records = [
            {
                "cveID": "CVE-2002-0367",
                "vendorProject": "Microsoft",
                "product": "Windows",
                "requiredAction": "Apply updates per vendor instructions.",
            }
        ]

        matches = VulnerabilityCorrelator().match_inventory(inventory, kev_records=kev_records, nvd_records=[])

        self.assertEqual([match.affected_title for match in matches], ["Microsoft Windows 11 Pro"])

    def test_kev_matching_uses_vulnerability_name_when_product_is_generic_vendor(self):
        inventory = [
            InventoryObject(
                category_id="s",
                category_name="Installed Software",
                object_type="software",
                title="Microsoft .NET Runtime",
                fields={"Publisher": "Microsoft Corporation"},
                source="fixture",
            ),
            InventoryObject(
                category_id="s",
                category_name="Installed Software",
                object_type="software",
                title="Microsoft Exchange Server 2019",
                fields={"Publisher": "Microsoft Corporation"},
                source="fixture",
            ),
        ]
        kev_records = [
            {
                "cveID": "CVE-2099-5555",
                "vendorProject": "Microsoft",
                "product": "Microsoft",
                "vulnerabilityName": "Microsoft Exchange Server Cross-Site Scripting Vulnerability",
                "requiredAction": "Apply mitigations per vendor instructions.",
            }
        ]

        matches = VulnerabilityCorrelator().match_inventory(inventory, kev_records=kev_records, nvd_records=[])

        self.assertEqual([match.affected_title for match in matches], ["Microsoft Exchange Server 2019"])

    def test_matches_nvd_record_and_sets_severity(self):
        inventory = [
            InventoryObject(
                category_id="s",
                category_name="Installed Software",
                object_type="software",
                title="Widget Tool",
                fields={"Version": "2.5", "Vendor": "WidgetCo"},
                source="fixture",
            )
        ]
        nvd_records = [
            {
                "id": "CVE-2099-2222",
                "descriptions": [{"lang": "en", "value": "Widget Tool 2.5 allows local privilege escalation."}],
                "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 7.8, "baseSeverity": "HIGH"}}]},
                "references": {"referenceData": [{"url": "https://nvd.nist.gov/vuln/detail/CVE-2099-2222"}]},
            }
        ]
        matches = VulnerabilityCorrelator().match_inventory(inventory, kev_records=[], nvd_records=nvd_records)
        self.assertEqual(matches[0].severity, "HIGH")
        self.assertEqual(matches[0].cvss, 7.8)
        self.assertEqual(matches[0].confidence, "Medium")

    def test_nvd_api_20_reference_list_is_supported(self):
        inventory = [
            InventoryObject(
                category_id="s",
                category_name="Installed Software",
                object_type="software",
                title="Widget Tool",
                fields={"DisplayVersion": "2.5"},
                source="fixture",
            )
        ]
        nvd_records = [
            {
                "id": "CVE-2099-3333",
                "descriptions": [{"lang": "en", "value": "Widget Tool 2.5 has a vulnerability."}],
                "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 5.5, "baseSeverity": "MEDIUM"}}]},
                "references": [{"url": "https://vendor.example/security"}],
            }
        ]
        matches = VulnerabilityCorrelator().match_inventory(inventory, kev_records=[], nvd_records=nvd_records)
        self.assertEqual(matches[0].references, ["https://vendor.example/security"])

    def test_enrichment_matches_nvd_records_only_against_query_object(self):
        inventory = [
            InventoryObject("s", "Installed Software", "software", "Alpha Tool", {"DisplayVersion": "1.0"}, "fixture"),
            InventoryObject("s", "Installed Software", "software", "Tool", {"DisplayVersion": "1.0"}, "fixture"),
        ]

        class FakeClient:
            def fetch_cisa_kev(self):
                return [], []

            def fetch_nvd_keyword(self, keyword, limit=5):
                if keyword.startswith("Alpha Tool"):
                    return [
                        {
                            "id": "CVE-2099-4444",
                            "descriptions": [{"lang": "en", "value": "Tool 1.0 vulnerability affects Alpha Tool."}],
                            "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 6.0, "baseSeverity": "MEDIUM"}}]},
                            "references": [],
                        }
                    ], []
                return [], []

        matches, diagnostics = VulnerabilityCorrelator().enrich_from_sources(inventory, client=FakeClient())
        self.assertEqual([match.affected_title for match in matches], ["Alpha Tool"])

    def test_enrichment_checks_all_candidates_by_default(self):
        inventory = [
            InventoryObject("s", "Installed Software", "software", f"Tool {index}", {"DisplayVersion": "1.0"}, "fixture")
            for index in range(15)
        ]

        class CountingClient:
            def __init__(self):
                self.keywords = []

            def fetch_cisa_kev(self):
                return [], []

            def fetch_nvd_keyword(self, keyword, limit=2000):
                self.keywords.append(keyword)
                return [], []

        client = CountingClient()
        VulnerabilityCorrelator().enrich_from_sources(inventory, client=client)

        self.assertEqual(15, len(client.keywords))
        self.assertEqual("Tool 14 1.0", client.keywords[-1])

    def test_enrichment_skips_nvd_queries_for_unversioned_candidates(self):
        inventory = [
            InventoryObject("svc", "Services", "service", "Google Chrome Elevation Service", {"Name": "GoogleChromeElevationService"}, "fixture"),
        ]

        class CountingClient:
            def __init__(self):
                self.keywords = []

            def fetch_cisa_kev(self):
                return [], []

            def fetch_nvd_keyword(self, keyword, limit=2000):
                self.keywords.append(keyword)
                return [], []

        client = CountingClient()
        matches, diagnostics = VulnerabilityCorrelator().enrich_from_sources(inventory, client=client)

        self.assertEqual([], matches)
        self.assertEqual([], diagnostics)
        self.assertEqual([], client.keywords)

    def test_enrichment_merges_optional_fstec_online_matches(self):
        inventory = [
            InventoryObject("s", "Installed Software", "software", "Example Tool", {"Version": "2.0"}, "fixture")
        ]

        class EmptyInternationalClient:
            def fetch_cisa_kev(self):
                return [], []

            def fetch_nvd_keyword(self, keyword, limit=5):
                return [], []

        class FakeFstecClient:
            def match_inventory(self, items, progress=None, cancel_token=None):
                self.items = items
                return [
                    VulnerabilityMatch(
                        cve="BDU:2026-00001",
                        source="ФСТЭК БДУ",
                        severity="HIGH",
                        cvss=8.8,
                        kev=False,
                        affected_title="Example Tool",
                        evidence="FSTEC fixture match",
                        confidence="High",
                        remediation="Обновить ПО.",
                        references=["https://bdu.fstec.ru/vul/2026-00001"],
                    )
                ], [CollectorDiagnostic("fstec_bdu", "info", "ok", "fixture")]

        fstec = FakeFstecClient()
        matches, diagnostics = VulnerabilityCorrelator(fstec_client=fstec).enrich_from_sources(
            inventory,
            client=EmptyInternationalClient(),
        )

        self.assertEqual(["BDU:2026-00001"], [match.cve for match in matches])
        self.assertEqual(inventory, fstec.items)
        self.assertTrue(any(item.module == "fstec_bdu" for item in diagnostics))

    def test_enrichment_uses_local_vulnerability_database_for_hardware_and_exploit_links(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            nvd_payload = {
                "vulnerabilities": [
                    {
                        "cve": {
                            "id": "CVE-2099-9001",
                            "descriptions": [
                                {"lang": "en", "value": "Example BIOS before 2.0 allows code execution."}
                            ],
                            "metrics": {
                                "cvssMetricV31": [
                                    {"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}
                                ]
                            },
                            "references": [
                                {"url": "https://exploit.example/CVE-2099-9001", "tags": ["Exploit"]}
                            ],
                            "configurations": [
                                {
                                    "nodes": [
                                        {
                                            "cpeMatch": [
                                                {
                                                    "vulnerable": True,
                                                    "criteria": "cpe:2.3:h:example:example_bios:*:*:*:*:*:*:*:*",
                                                    "versionEndExcluding": "2.0",
                                                }
                                            ]
                                        }
                                    ]
                                }
                            ],
                        }
                    }
                ]
            }
            nvd_path = root / "nvdcve-2.0-2099.json.gz"
            nvd_path.write_bytes(gzip.compress(json.dumps(nvd_payload).encode("utf-8")))
            db_path = root / "vulnerability_sources.db"
            VulnerabilityDatabaseBuilder(root / "snapshots", db_path).build_database(
                [DownloadedSource("nvd", "2099", "https://nvd.test/2099", nvd_path)]
            )
            client = VulnerabilityDatabaseSourceClient(db_path)
            bios = InventoryObject(
                "b",
                "BIOS Version",
                "bios",
                "Example BIOS",
                {"Manufacturer": "Example", "SMBIOSBIOSVersion": "1.5"},
                "fixture",
            )

            matches, diagnostics = VulnerabilityCorrelator().enrich_from_sources(
                [bios],
                client=client,
            )

        self.assertEqual(["CVE-2099-9001"], [match.cve for match in matches])
        self.assertEqual("CRITICAL", matches[0].severity)
        self.assertEqual(bios.uid, matches[0].object_uid)
        self.assertIn("https://exploit.example/CVE-2099-9001", matches[0].references)
        self.assertFalse(any(item.severity == "warning" for item in diagnostics), diagnostics)


if __name__ == "__main__":
    unittest.main()
