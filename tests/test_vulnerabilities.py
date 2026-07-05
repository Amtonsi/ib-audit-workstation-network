import os
import gzip
import json
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, os.path.abspath("src"))

from ib_audit.cancellation import AuditCancelled, CancellationToken
from ib_audit.cpe import CpeName
from ib_audit.cpe_catalog import CpeCandidate
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

    def test_enrichment_fans_one_query_out_to_all_duplicate_product_objects(self):
        first = InventoryObject(
            "s",
            "Installed Software",
            "software",
            "SQL Server 2012 Common Files",
            {"Vendor": "Microsoft", "Version": "11.1.3000.0", "Software ID": "{ONE}"},
            "fixture",
        )
        second = InventoryObject(
            "s",
            "Installed Software",
            "software",
            "SQL Server 2012 Common Files",
            {"Vendor": "Microsoft", "Version": "11.1.3000.0", "Software ID": "{TWO}"},
            "fixture",
        )

        class OneRecordClient:
            def fetch_cisa_kev(self):
                return [], []

            def fetch_nvd_for_object(self, obj):
                return [
                    {
                        "id": "CVE-2099-1200",
                        "_ib_match_requires_configuration": True,
                        "configurations": [{"nodes": [{"cpeMatch": [{
                            "vulnerable": True,
                            "criteria": "cpe:2.3:a:microsoft:sql_server:*:*:*:*:*:*:*:*",
                            "versionEndExcluding": "11.2",
                        }]}]}],
                        "descriptions": [
                            {
                                "lang": "en",
                                "value": "Microsoft SQL Server before 11.2 is vulnerable.",
                            }
                        ],
                    }
                ], []

        matches, diagnostics = VulnerabilityCorrelator().enrich_from_sources(
            [first, second],
            client=OneRecordClient(),
        )

        self.assertEqual({first.uid, second.uid}, {item.object_uid for item in matches})

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

    def test_enrichment_uses_local_fstec_xlsx_records_for_software_versions(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            db_path = root / "vulnerability_sources.db"
            VulnerabilityDatabaseBuilder(root / "snapshots", db_path).build_database([])
            self._insert_fstec_fixture(
                db_path,
                code="BDA:2026-157",
                severity_text="Средний уровень опасности",
                cvss=5.3,
                product="PowerChute Serial Shutdown",
                version_expression="до 1.5",
            )
            software = InventoryObject(
                "s",
                "Installed Software",
                "software",
                "PowerChute Serial Shutdown",
                {"Name": "PowerChute Serial Shutdown", "Version": "1.4"},
                "fixture",
            )

            result = VulnerabilityCorrelator(
                source_client=VulnerabilityDatabaseSourceClient(db_path)
            ).enrich_from_sources([software])

        self.assertEqual(1, len(result.matches))
        match = result.matches[0]
        self.assertEqual("BDA:2026-157", match.cve)
        self.assertEqual("ФСТЭК БДУ", match.source)
        self.assertEqual("MEDIUM", match.severity)
        self.assertEqual(5.3, match.cvss)
        self.assertEqual("High", match.confidence)
        self.assertEqual("confirmed", match.applicability)
        self.assertEqual(software.uid, match.object_uid)

    def test_local_fstec_product_match_without_version_is_potential_not_high_confidence(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            db_path = root / "vulnerability_sources.db"
            VulnerabilityDatabaseBuilder(root / "snapshots", db_path).build_database([])
            self._insert_fstec_fixture(
                db_path,
                code="BDA:2026-158",
                severity_text="Высокий уровень опасности",
                cvss=8.1,
                product="PowerChute Serial Shutdown",
                version_expression="до 1.5",
            )
            software = InventoryObject(
                "s",
                "Installed Software",
                "software",
                "PowerChute Serial Shutdown",
                {"Name": "PowerChute Serial Shutdown"},
                "fixture",
            )

            result = VulnerabilityCorrelator(
                source_client=VulnerabilityDatabaseSourceClient(db_path)
            ).enrich_from_sources([software])

        self.assertEqual(1, len(result.matches))
        self.assertEqual("potential", result.matches[0].applicability)
        self.assertEqual("Medium", result.matches[0].confidence)

    def test_local_fstec_groups_duplicate_product_versions_into_one_query(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            db_path = root / "vulnerability_sources.db"
            VulnerabilityDatabaseBuilder(root / "snapshots", db_path).build_database([])
            self._insert_fstec_fixture(
                db_path,
                code="BDA:2026-159",
                severity_text="Высокий уровень опасности",
                cvss=8.1,
                product="PowerChute Serial Shutdown",
                version_expression="до 1.5",
            )
            first = InventoryObject(
                "s",
                "Installed Software",
                "software",
                "PowerChute Serial Shutdown",
                {"Name": "PowerChute Serial Shutdown", "Version": "1.4"},
                "fixture",
            )
            second = InventoryObject(
                "s",
                "Installed Software",
                "software",
                "PowerChute Serial Shutdown",
                {"Name": "PowerChute Serial Shutdown", "Version": "1.4"},
                "fixture",
            )
            client = VulnerabilityDatabaseSourceClient(db_path)

            with patch.object(
                client,
                "_query_fstec_products",
                wraps=client._query_fstec_products,
            ) as query:
                matches, _diagnostics = client.fetch_fstec_matches([first, second])

        self.assertEqual(1, query.call_count)
        self.assertEqual({first.uid, second.uid}, {match.object_uid for match in matches})

    def test_database_candidate_fetch_deduplicates_same_product_key(self):
        class FakeRow(dict):
            def __getitem__(self, key):
                return super().__getitem__(key)

        with tempfile.TemporaryDirectory() as temp:
            db_path = Path(temp) / "vulnerability_sources.db"
            VulnerabilityDatabaseBuilder(Path(temp) / "snapshots", db_path).build_database([])
            client = VulnerabilityDatabaseSourceClient(db_path)
            record = {"id": "CVE-2099-1010", "configurations": []}
            rows = [FakeRow(cve_id="CVE-2099-1010", raw_json=json.dumps(record))]
            candidates = (
                CpeCandidate(
                    CpeName.parse("cpe:2.3:a:microsoft:office:2010:*:*:*:*:*:*:*"),
                    "OFFICE-2010",
                    "Microsoft Office 2010",
                    90,
                    (),
                ),
                CpeCandidate(
                    CpeName.parse("cpe:2.3:a:microsoft:office:2013:*:*:*:*:*:*:*"),
                    "OFFICE-2013",
                    "Microsoft Office 2013",
                    90,
                    (),
                ),
            )

            with patch.object(client, "_fetch_rows", return_value=rows) as fetch_rows:
                records, _truncated, diagnostics = client.fetch_nvd_for_candidates(candidates)

        self.assertEqual(["CVE-2099-1010"], [item["id"] for item in records])
        self.assertEqual(1, fetch_rows.call_count)
        self.assertTrue(any("CPE candidates" in item.message for item in diagnostics))

    def test_database_candidate_fetch_reuses_same_product_key_across_calls(self):
        class FakeRow(dict):
            def __getitem__(self, key):
                return super().__getitem__(key)

        with tempfile.TemporaryDirectory() as temp:
            db_path = Path(temp) / "vulnerability_sources.db"
            VulnerabilityDatabaseBuilder(Path(temp) / "snapshots", db_path).build_database([])
            client = VulnerabilityDatabaseSourceClient(db_path)
            record = {"id": "CVE-2099-1011", "configurations": []}
            rows = [FakeRow(cve_id="CVE-2099-1011", raw_json=json.dumps(record))]
            first_candidates = (
                CpeCandidate(
                    CpeName.parse("cpe:2.3:a:microsoft:office:2010:*:*:*:*:*:*:*"),
                    "OFFICE-2010",
                    "Microsoft Office 2010",
                    90,
                    (),
                ),
            )
            second_candidates = (
                CpeCandidate(
                    CpeName.parse("cpe:2.3:a:microsoft:office:2013:*:*:*:*:*:*:*"),
                    "OFFICE-2013",
                    "Microsoft Office 2013",
                    90,
                    (),
                ),
            )

            with patch.object(client, "_fetch_rows", return_value=rows) as fetch_rows:
                first_records, _truncated, _diagnostics = client.fetch_nvd_for_candidates(first_candidates)
                second_records, _truncated, _diagnostics = client.fetch_nvd_for_candidates(second_candidates)

        self.assertEqual(["CVE-2099-1011"], [item["id"] for item in first_records])
        self.assertEqual(["CVE-2099-1011"], [item["id"] for item in second_records])
        self.assertEqual(1, fetch_rows.call_count)

    def test_cpe_correlation_returns_coverage_and_duplicate_uid_matches(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            db_path = self._build_cpe_enabled_database(
                root,
                cpes=[
                    ("SQL-1", "cpe:2.3:a:microsoft:sql_server:*:*:*:*:*:*:*:*", "Microsoft SQL Server"),
                ],
                cves=[
                    self._cve(
                        "CVE-2099-1200",
                        "cpe:2.3:a:microsoft:sql_server:*:*:*:*:*:*:*:*",
                        version_end_excluding="11.2",
                    )
                ],
            )
            first = InventoryObject(
                "s", "Installed Software", "software", "SQL Server 2012 Common Files",
                {"Vendor": "Microsoft", "Version": "11.1.3000.0", "Software ID": "{ONE}"},
                "fixture",
            )
            second = InventoryObject(
                "s", "Installed Software", "software", "SQL Server 2012 Common Files",
                {"Vendor": "Microsoft", "Version": "11.1.3000.0", "Software ID": "{TWO}"},
                "fixture",
            )

            result = VulnerabilityCorrelator(
                source_client=VulnerabilityDatabaseSourceClient(db_path)
            ).enrich_from_sources([first, second])

        self.assertEqual({first.uid, second.uid}, {item.object_uid for item in result.matches})
        self.assertEqual({"confirmed"}, {item.applicability for item in result.matches})
        self.assertEqual("complete", result.coverage[first.uid].state)
        self.assertEqual("resolved", result.coverage[first.uid].cpe_status)

    def test_cpe_correlation_reports_group_progress(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            db_path = self._build_cpe_enabled_database(
                root,
                cpes=[
                    ("SQL-1", "cpe:2.3:a:microsoft:sql_server:*:*:*:*:*:*:*:*", "Microsoft SQL Server"),
                ],
                cves=[],
            )
            software = InventoryObject(
                "s",
                "Installed Software",
                "software",
                "SQL Server 2012 Common Files",
                {"Vendor": "Microsoft", "Version": "11.1.3000.0"},
                "fixture",
            )
            progress: list[str] = []

            VulnerabilityCorrelator(
                source_client=VulnerabilityDatabaseSourceClient(db_path)
            ).enrich_from_sources([software], progress=progress.append)

        self.assertIn("Local NVD/CPE database: 1/1", progress)

    def test_cpe_correlation_marks_fixed_version_complete_without_match(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            db_path = self._build_cpe_enabled_database(
                root,
                cpes=[
                    ("SQL-1", "cpe:2.3:a:microsoft:sql_server:*:*:*:*:*:*:*:*", "Microsoft SQL Server"),
                ],
                cves=[
                    self._cve(
                        "CVE-2099-1200",
                        "cpe:2.3:a:microsoft:sql_server:*:*:*:*:*:*:*:*",
                        version_end_excluding="11.2",
                    )
                ],
            )
            fixed = InventoryObject(
                "s", "Installed Software", "software", "SQL Server 2012 Common Files",
                {"Vendor": "Microsoft", "Version": "11.2.0.0"},
                "fixture",
            )

            result = VulnerabilityCorrelator(
                source_client=VulnerabilityDatabaseSourceClient(db_path)
            ).enrich_from_sources([fixed])

        self.assertEqual([], result.matches)
        self.assertEqual("complete", result.coverage[fixed.uid].state)

    def test_cpe_correlation_marks_unknown_hardware_firmware_as_potential(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            db_path = self._build_cpe_enabled_database(
                root,
                cpes=[
                    ("CPU-1", "cpe:2.3:h:intel:xeon:e5620:*:*:*:*:*:*:*", "Intel Xeon E5620"),
                ],
                cves=[
                    {
                        "id": "CVE-2099-8800",
                        "descriptions": [{"lang": "en", "value": "Intel Xeon E5620 firmware before 2.0 is vulnerable."}],
                        "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 8.1, "baseSeverity": "HIGH"}}]},
                        "references": [{"url": "https://vendor.example/CVE-2099-8800"}],
                        "configurations": [
                            {
                                "operator": "AND",
                                "nodes": [
                                    {"cpeMatch": [{
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:h:intel:xeon:e5620:*:*:*:*:*:*:*",
                                    }]},
                                    {"cpeMatch": [{
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:o:intel:xeon_e5620_firmware:*:*:*:*:*:*:*:*",
                                        "versionEndExcluding": "2.0",
                                    }]},
                                ],
                            }
                        ],
                    }
                ],
            )
            processor = InventoryObject(
                "p", "Processors", "processor", "Intel(R) Xeon(R) CPU E5620 @ 2.40GHz",
                {"Manufacturer": "Intel(R) Corporation"},
                "fixture",
            )

            result = VulnerabilityCorrelator(
                source_client=VulnerabilityDatabaseSourceClient(db_path)
            ).enrich_from_sources([processor])

        self.assertEqual(["potential"], [item.applicability for item in result.matches])
        self.assertEqual("complete", result.coverage[processor.uid].state)

    def test_cpe_correlation_marks_unresolved_generic_processor_incomplete(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            db_path = self._build_cpe_enabled_database(root, cpes=[], cves=[])
            processor = InventoryObject(
                "p", "Processors", "processor", "Processor",
                {"Manufacturer": "Intel(R) Corporation"},
                "fixture",
            )

            result = VulnerabilityCorrelator(
                source_client=VulnerabilityDatabaseSourceClient(db_path)
            ).enrich_from_sources([processor])

        self.assertEqual([], result.matches)
        self.assertEqual("incomplete", result.coverage[processor.uid].state)
        self.assertEqual("not_found", result.coverage[processor.uid].cpe_status)

    def test_ambiguous_hardware_cpe_candidates_are_still_evaluated(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            cpe = "cpe:2.3:h:intel:xeon:e5620:*:*:*:*:*:*:*"
            db_path = self._build_cpe_enabled_database(
                root,
                cpes=[
                    ("CPU-1", cpe, "Intel Xeon E5620"),
                    ("CPU-2", "cpe:2.3:h:intel:xeon_processor:e5620:*:*:*:*:*:*:*", "Intel Xeon Processor E5620"),
                ],
                cves=[self._cve("CVE-2099-8801", cpe)],
            )
            processor = InventoryObject(
                "p", "Processors", "processor", "Intel(R) Xeon(R) CPU E5620 @ 2.40GHz",
                {"Manufacturer": "Intel(R) Corporation"},
                "fixture",
            )

            result = VulnerabilityCorrelator(
                source_client=VulnerabilityDatabaseSourceClient(db_path)
            ).enrich_from_sources([processor])

        self.assertEqual(["CVE-2099-8801"], [item.cve for item in result.matches])
        self.assertEqual("complete", result.coverage[processor.uid].state)
        self.assertEqual("ambiguous", result.coverage[processor.uid].cpe_status)
        self.assertGreaterEqual(result.coverage[processor.uid].candidate_count, 2)
        self.assertGreaterEqual(result.coverage[processor.uid].evaluated_count, 1)

    def test_ambiguous_software_cpe_candidates_are_still_evaluated(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            cpe = "cpe:2.3:a:example:backup:*:*:*:*:*:*:*:*"
            db_path = self._build_cpe_enabled_database(
                root,
                cpes=[
                    ("BACKUP-1", cpe, "Example Backup"),
                    ("BACKUP-2", "cpe:2.3:a:example:backup_agent:*:*:*:*:*:*:*:*", "Example Backup Agent"),
                ],
                cves=[
                    self._cve("CVE-2099-7701", cpe, version_end_excluding="2.0"),
                ],
            )
            software = InventoryObject(
                "s", "Installed Software", "software", "Example Backup",
                {"Vendor": "Example", "Version": "1.0"},
                "fixture",
            )

            result = VulnerabilityCorrelator(
                source_client=VulnerabilityDatabaseSourceClient(db_path)
            ).enrich_from_sources([software])

        self.assertEqual(["CVE-2099-7701"], [item.cve for item in result.matches])
        self.assertEqual("complete", result.coverage[software.uid].state)
        self.assertEqual("ambiguous", result.coverage[software.uid].cpe_status)
        self.assertGreaterEqual(result.coverage[software.uid].candidate_count, 2)
        self.assertGreaterEqual(result.coverage[software.uid].evaluated_count, 1)

    def test_acronis_backup_rebrand_candidates_are_evaluated(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            cyber_backup = "cpe:2.3:a:acronis:cyber_backup:*:*:*:*:*:*:*:*"
            db_path = self._build_cpe_enabled_database(
                root,
                cpes=[
                    ("ABR-1", "cpe:2.3:a:acronis:backup_\\&_recovery_agent:11.0.17217:*:*:*:*:*:*:*", "Acronis Backup & Recovery Agent 11.0.17217"),
                    ("ABR-2", "cpe:2.3:a:acronis:backup_\\&_recovery_agent:11.0.17318:*:*:*:*:*:*:*", "Acronis Backup & Recovery Agent 11.0.17318"),
                    ("ABR-3", "cpe:2.3:a:acronis:backup_\\&_recovery_agent_core:11.0.17217:*:*:*:*:*:*:*", "Acronis Backup & Recovery Agent Core 11.0.17217"),
                    ("ABR-4", "cpe:2.3:a:acronis:backup_\\&_recovery_agent_core:11.0.17318:*:*:*:*:*:*:*", "Acronis Backup & Recovery Agent Core 11.0.17318"),
                    ("ABR-5", "cpe:2.3:a:acronis:backup_\\&_recovery_management_console:11.0.17318:*:*:*:*:*:*:*", "Acronis Backup & Recovery Management Console 11.0.17318"),
                ],
                cves=[
                    self._cve("CVE-2099-9901", cyber_backup, version_end_excluding="12.5"),
                ],
            )
            software = InventoryObject(
                "s", "Installed Software", "software", "Acronis Backup 11.7 Agent Core",
                {"Vendor": "Acronis", "Version": "11.7.50058"},
                "fixture",
            )

            result = VulnerabilityCorrelator(
                source_client=VulnerabilityDatabaseSourceClient(db_path)
            ).enrich_from_sources([software])

        self.assertEqual(["CVE-2099-9901"], [item.cve for item in result.matches])
        self.assertEqual("confirmed", result.matches[0].applicability)
        self.assertEqual("complete", result.coverage[software.uid].state)

    @staticmethod
    def _insert_fstec_fixture(
        db_path: Path,
        *,
        code: str,
        severity_text: str,
        cvss: float,
        product: str,
        version_expression: str,
    ) -> None:
        con = sqlite3.connect(db_path)
        try:
            con.execute(
                """
                insert into fstec_vulnerabilities(
                    source,code,name,description,severity_text,cvss,exploit_status,
                    exploit_available,references_json,external_ids,remediation,
                    version_info,raw_json,imported_at
                ) values(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    "fstec-asutp",
                    code,
                    f"{product} vulnerability",
                    f"{product} {version_expression}",
                    severity_text,
                    cvss,
                    "Существует в открытом доступе",
                    1,
                    json.dumps(["https://vendor.example/advisory"]),
                    "",
                    "Обновление программного обеспечения",
                    f"{version_expression} ({product})",
                    "{}",
                    "2099-01-01T00:00:00+00:00",
                ),
            )
            normalized = product.casefold()
            con.execute(
                """
                insert into fstec_vulnerability_products(
                    source,code,product,vendor,version_expression,
                    normalized_product,normalized_vendor,search_text
                ) values(?,?,?,?,?,?,?,?)
                """,
                (
                    "fstec-asutp",
                    code,
                    product,
                    "",
                    version_expression,
                    normalized,
                    "",
                    f"{normalized} {version_expression.casefold()}",
                ),
            )
            con.commit()
        finally:
            con.close()

    def _build_cpe_enabled_database(
        self,
        root: Path,
        cpes: list[tuple[str, str, str]],
        cves: list[dict],
    ) -> Path:
        db_path = root / "vulnerability_sources.db"
        nvd_path = root / "nvdcve-2.0-2099.json.gz"
        nvd_path.write_bytes(
            gzip.compress(json.dumps({"vulnerabilities": [{"cve": item} for item in cves]}).encode("utf-8"))
        )
        VulnerabilityDatabaseBuilder(root / "snapshots", db_path).build_database(
            [DownloadedSource("nvd", "2099", "https://nvd.test/2099", nvd_path)]
        )
        con = sqlite3.connect(db_path)
        try:
            con.execute(
                "insert into cpe_catalog_generations(id,created_at,status) values(1,'2099-01-01T00:00:00+00:00','active')"
            )
            con.execute(
                """
                insert into source_sync_state(source,active_generation_id,sha256,size_bytes,updated_at)
                values('nvd-cpe-catalog',1,'fixture',0,'2099-01-01T00:00:00+00:00')
                """
            )
            for cpe_name_id, cpe_name, title in cpes:
                parts = cpe_name.split(":")
                con.execute(
                    """
                    insert into nvd_cpe_names(
                        generation_id,cpe_name_id,cpe_name,part,vendor,product,version,
                        update_value,deprecated,title
                    ) values(?,?,?,?,?,?,?,?,?,?)
                    """,
                    (1, cpe_name_id, cpe_name, parts[2], parts[3], parts[4], parts[5], parts[6], 0, title),
                )
            con.commit()
        finally:
            con.close()
        return db_path

    @staticmethod
    def _cve(
        cve_id: str,
        criteria: str,
        *,
        version_end_excluding: str = "",
    ) -> dict:
        cpe_match = {"vulnerable": True, "criteria": criteria}
        if version_end_excluding:
            cpe_match["versionEndExcluding"] = version_end_excluding
        return {
            "id": cve_id,
            "descriptions": [{"lang": "en", "value": f"{criteria} is vulnerable."}],
            "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 7.8, "baseSeverity": "HIGH"}}]},
            "references": [{"url": f"https://example.test/{cve_id}"}],
            "configurations": [{"nodes": [{"cpeMatch": [cpe_match]}]}],
        }


if __name__ == "__main__":
    unittest.main()
