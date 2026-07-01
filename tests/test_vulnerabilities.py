import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

sys.path.insert(0, os.path.abspath("src"))

from ib_audit.cancellation import AuditCancelled, CancellationToken
from ib_audit.models import CollectorDiagnostic, InventoryObject, VulnerabilityMatch
from ib_audit.source_cache import SnapshotCache
from ib_audit.vulnerabilities import VulnerabilityCorrelator, VulnerabilitySourceClient


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


if __name__ == "__main__":
    unittest.main()
