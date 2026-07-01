import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, os.path.abspath("src"))

from ib_audit.cancellation import AuditCancelled, CancellationToken
from ib_audit.fstec import FstecBduClient
from ib_audit.models import InventoryObject
from ib_audit.source_cache import SnapshotCache


SEARCH_HTML = """
<html><body>
<div id="vuls">
  <a class="confirm-vul" href="/vul/2026-00001">BDU:2026-00001</a>
  <div class="link-pager">
    <a href="/vul?search=Example&amp;ajax=vuls&amp;page=2">2</a>
  </div>
</div>
</body></html>
"""


def detail_html(version_expression="до 2.5 включительно"):
    model = {
        "vul_critu": "Высокий уровень опасности (базовая оценка CVSS 3.1 составляет 8,8)",
        "vul_desc": "Уязвимость Example Tool позволяет выполнить произвольный код.",
        "vul_elimination": 1,
        "vul_link": "https://vendor.example/security/notice",
        "vul_name": "Уязвимость Example Tool",
        "vul_vmer": "Обновить Example Tool до исправленной версии.",
        "versions": [
            {
                "ver_name": version_expression,
                "soft": {
                    "sft_name": "Example Tool",
                    "vendor": {"vnd_name": "Example Vendor"},
                },
            }
        ],
        "idvals": [
            'CVE: <a href="https://nvd.nist.gov/vuln/detail/CVE-2026-0001">CVE-2026-0001</a>'
        ],
    }
    return f"<html><script>const v_model = reactive({json.dumps(model, ensure_ascii=False)});</script></html>"


class FixtureTransport:
    def __init__(self, version_expression="до 2.5 включительно", fail=False):
        self.version_expression = version_expression
        self.fail = fail
        self.urls = []

    def __call__(self, url):
        self.urls.append(url)
        if self.fail:
            raise OSError("network unavailable")
        parsed = urlparse(url)
        if parsed.path == "/vul/2026-00001":
            return detail_html(self.version_expression)
        if parsed.path == "/vul" and parse_qs(parsed.query).get("search"):
            return SEARCH_HTML
        return "<html></html>"


def software(version):
    return InventoryObject(
        category_id="s",
        category_name="Installed Software",
        object_type="software",
        title=f"Example Tool {version}",
        fields={"Name": "Example Tool", "Version": version, "Vendor": "Example Vendor"},
        source="fixture",
    )


class FstecBduClientTests(unittest.TestCase):
    def test_cancellation_is_not_converted_to_source_warning(self):
        token = CancellationToken()
        token.cancel()
        client = FstecBduClient(transport=FixtureTransport(), max_queries=1)

        with self.assertRaises(AuditCancelled):
            client.match_inventory([software("2.0")], cancel_token=token)

    def test_default_query_limit_is_unlimited_for_full_document_audit(self):
        client = FstecBduClient(transport=FixtureTransport())
        self.assertIsNone(client.max_queries)
        self.assertGreaterEqual(client.max_pages, 3)
        self.assertGreaterEqual(client.max_details_per_query, 25)

    def test_curl_session_uses_hidden_subprocess_options(self):
        completed = subprocess.CompletedProcess(["curl"], 0, stdout=b"<html></html>", stderr=b"")
        with patch("ib_audit.fstec.shutil.which", return_value="curl.exe"), \
                patch("ib_audit.fstec.hidden_subprocess_kwargs", return_value={"creationflags": 9}), \
                patch("ib_audit.fstec.subprocess.run", return_value=completed) as run:
            session = FstecBduClient._curl_session("https://bdu.fstec.ru", 1024, 5)
            try:
                payload = session.get("https://bdu.fstec.ru/vul")
            finally:
                session.close()

        self.assertIn("<html>", payload)
        self.assertEqual(9, run.call_args.kwargs["creationflags"])

    def test_driver_is_in_candidate_inventory(self):
        driver = InventoryObject(
            "drivers", "Services and Drivers", "driver", "Example Driver",
            {"DriverProviderName": "Example", "DriverVersion": "1.5"}, "fixture",
        )
        self.assertEqual([driver], FstecBduClient._candidate_inventory([driver]))

    def test_candidate_inventory_prioritizes_high_value_objects(self):
        operating_system = InventoryObject("o", "Operating System", "operating_system", "Windows 11", {"Caption": "Windows 11"}, "fixture")
        driver = InventoryObject("d", "Drivers", "driver", "Example Driver", {"Name": "Example Driver"}, "fixture")
        service = InventoryObject("a", "Services", "service", "Example Service", {"Name": "Example Service"}, "fixture")
        device = InventoryObject("a", "Devices", "device", "Example Device", {"Name": "Example Device"}, "fixture")

        ordered = FstecBduClient._candidate_inventory([device, service, driver, software("2.0"), operating_system])

        self.assertEqual(
            ["operating_system", "software", "driver", "service", "device"],
            [item.object_type for item in ordered],
        )

    def test_matches_live_detail_and_maps_fstec_fields(self):
        transport = FixtureTransport()
        client = FstecBduClient(transport=transport, max_queries=1, max_pages=1, max_details_per_query=5)

        matches, diagnostics = client.match_inventory([software("2.0")])

        self.assertEqual(1, len(matches))
        match = matches[0]
        self.assertEqual("BDU:2026-00001", match.cve)
        self.assertEqual("ФСТЭК БДУ", match.source)
        self.assertEqual("HIGH", match.severity)
        self.assertEqual(8.8, match.cvss)
        self.assertEqual("High", match.confidence)
        self.assertIn("до 2.5", match.evidence)
        self.assertIn("Обновить Example Tool", match.remediation)
        self.assertIn("https://bdu.fstec.ru/vul/2026-00001", match.references)
        self.assertTrue(any(item.severity == "info" for item in diagnostics))
        self.assertFalse(any("page=2" in url for url in transport.urls))

    def test_duplicate_keywords_search_fstec_once_and_match_each_object(self):
        transport = FixtureTransport()
        client = FstecBduClient(transport=transport, max_pages=1, max_details_per_query=5)

        matches, diagnostics = client.match_inventory([software("2.0"), software("2.1")])

        search_urls = [
            url for url in transport.urls
            if urlparse(url).path == "/vul" and parse_qs(urlparse(url).query).get("search")
        ]
        self.assertEqual(1, len(search_urls))
        self.assertEqual(["Example Tool 2.0", "Example Tool 2.1"], sorted(match.affected_title for match in matches))
        self.assertTrue(any("queries=1" in item.message for item in diagnostics), diagnostics)

    def test_cached_fstec_html_is_used_after_online_error(self):
        with tempfile.TemporaryDirectory() as temp:
            cache = SnapshotCache(Path(temp))
            first_transport = FixtureTransport()
            first_client = FstecBduClient(
                transport=first_transport,
                cache=cache,
                max_queries=1,
                max_pages=1,
                max_details_per_query=5,
            )
            first_client.match_inventory([software("2.0")])

            failing_transport = FixtureTransport(fail=True)
            cached_client = FstecBduClient(
                transport=failing_transport,
                cache=cache,
                max_queries=1,
                max_pages=1,
                max_details_per_query=5,
            )

            matches, diagnostics = cached_client.match_inventory([software("2.0")])

        self.assertEqual(["BDU:2026-00001"], [match.cve for match in matches])
        self.assertTrue(any(item.severity == "info" for item in diagnostics), diagnostics)

    def test_rejects_confirmed_non_affected_version(self):
        client = FstecBduClient(
            transport=FixtureTransport(),
            max_queries=1,
            max_pages=1,
            max_details_per_query=5,
        )

        matches, _diagnostics = client.match_inventory([software("3.0")])

        self.assertEqual([], matches)

    def test_reports_live_source_failure_without_raising(self):
        client = FstecBduClient(transport=FixtureTransport(fail=True), max_queries=1)

        matches, diagnostics = client.match_inventory([software("2.0")])

        self.assertEqual([], matches)
        self.assertTrue(any(item.severity == "warning" and "unavailable" in item.message for item in diagnostics))

    def test_default_match_inventory_checks_every_unique_keyword(self):
        inventory = [software(f"2.{index}") for index in range(305)]
        transport = FixtureTransport()
        client = FstecBduClient(transport=transport, max_pages=1, max_details_per_query=1)

        _matches, diagnostics = client.match_inventory(inventory)

        self.assertTrue(any("queries=1" in item.message for item in diagnostics), diagnostics)


if __name__ == "__main__":
    unittest.main()
