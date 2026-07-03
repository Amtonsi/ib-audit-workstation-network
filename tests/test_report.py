import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath("src"))

from ib_audit.assessment import AssessmentBundle
from ib_audit.models import (
    AuditRun, CollectorDiagnostic, CoverageSummary, InventoryObject,
    ObjectAssessment, RuleResult, SourceSnapshot, VulnerabilityMatch, WindowsProfile,
)
from ib_audit.report import HtmlReportBuilder


class HtmlReportBuilderTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.temp_dir)

    def _assessment(self, inventory, results=None, vulnerabilities=None, snapshots=None):
        results = results or []
        statuses = {obj.uid: [] for obj in inventory}
        for result in results:
            statuses[result.object_uid].append(result.status)
        assessments = []
        for obj in inventory:
            values = statuses[obj.uid]
            status = "risk" if "risk" in values else "insufficient_data" if "insufficient_data" in values else "passed" if values else "not_applicable"
            assessments.append(ObjectAssessment(obj.uid, status, len(values), values.count("passed"), values.count("risk"), values.count("insufficient_data")))
        coverage = CoverageSummary(
            len(inventory), sum(x.status == "risk" for x in assessments),
            sum(x.status == "passed" for x in assessments),
            sum(x.status == "insufficient_data" for x in assessments),
            sum(x.status == "not_applicable" for x in assessments),
        )
        profile = WindowsProfile("windows-test-workstation", "Windows Test", "", "", "", "x64", "workstation", False)
        return AssessmentBundle(profile, vulnerabilities or [], results, assessments, coverage, [], snapshots or [])

    def test_complete_report_renders_all_categories_and_object_coverage(self):
        run = AuditRun.create("TEST-PC", True)
        obj = InventoryObject(
            "startup", "Startup Programs", "startup_program", "Agent",
            {"Command": r"C:\Users\Public\agent.exe"}, "fixture",
        )
        result = RuleResult(
            obj.uid, "EXP-AUTORUN-001", "1", "exposure", "risk", "high",
            "Unsafe autorun", obj.fields["Command"], "protected path",
            "Startup Programs / Agent / Command", "high", "Remove unsafe entry.",
        )
        assessment = self._assessment([obj], [result])
        html = HtmlReportBuilder().render(run, [obj], [], assessment)
        self.assertIn("OLE DB Drivers", html)
        self.assertIn("Данные недоступны", html)
        self.assertIn(f"id='object-{obj.uid}'", html)
        self.assertIn(f"href='#object-{obj.uid}'", html)
        self.assertIn("EXP-AUTORUN-001", html)
        self.assertIn("Недостаточно данных", html)

    def test_report_css_wraps_long_values_without_horizontal_page_overflow(self):
        run = AuditRun.create("TEST-PC", True)
        obj = InventoryObject(
            "startup",
            "Startup Programs",
            "startup_program",
            "VeryLongAutorun",
            {"Command": "C:/" + "very-long-segment-" * 80 + "agent.exe"},
            "fixture",
        )

        html = HtmlReportBuilder().render(run, [obj], [], self._assessment([obj]))

        self.assertIn("box-sizing:border-box", html)
        self.assertIn("table-layout:fixed", html)
        self.assertIn("overflow-wrap:anywhere", html)
        self.assertIn("min-width:0", html)

    def test_report_exposes_filters_for_findings_and_inventory_objects(self):
        run = AuditRun.create("TEST-PC", True)
        obj = InventoryObject(
            "startup",
            "Startup Programs",
            "startup_program",
            "Agent",
            {"Command": r"C:\Users\Public\agent.exe"},
            "fixture",
        )
        result = RuleResult(
            obj.uid, "EXP-AUTORUN-001", "1", "exposure", "risk", "high",
            "Unsafe autorun", obj.fields["Command"], "protected path",
            "Startup Programs / Agent / Command", "high", "Remove unsafe entry.",
        )

        html = HtmlReportBuilder().render(run, [obj], [], self._assessment([obj], [result]))

        self.assertIn("id='findingKindFilter'", html)
        self.assertIn("id='findingSeverityFilter'", html)
        self.assertIn("id='objectStatusFilter'", html)
        self.assertIn("id='objectSourceFilter'", html)
        self.assertIn("id='objectCategoryFilter'", html)
        self.assertIn("data-kind='exposure'", html)
        self.assertIn("data-severity='high'", html)
        self.assertIn("data-status='risk'", html)
        self.assertIn("data-source='fixture'", html)
        self.assertIn("data-category='Startup Programs'", html)
        self.assertIn("function applyFilters()", html)

    def test_report_shows_source_snapshot_freshness(self):
        run = AuditRun.create("TEST-PC", True)
        obj = InventoryObject("s", "Installed Software", "software", "Tool", {"Version": "1"}, "fixture")
        snapshot = SourceSnapshot("id", "CISA KEV", "catalog", "cache/kev.json", "a" * 64, "2026-06-29T00:00:00+00:00", "active")
        html = HtmlReportBuilder().render(run, [obj], [], self._assessment([obj], snapshots=[snapshot]))
        self.assertIn("CISA KEV", html)
        self.assertIn("2026-06-29", html)
        self.assertIn("aaaaaaaaaaaa", html)

    def test_report_labels_exploit_references(self):
        run = AuditRun.create("TEST-PC", True)
        obj = InventoryObject("b", "BIOS Version", "bios", "Example BIOS", {"Version": "1.5"}, "fixture")
        result = RuleResult(
            obj.uid,
            "CVE-2099-9001",
            "NVD",
            "vulnerability",
            "risk",
            "critical",
            "CVE-2099-9001: Example BIOS",
            "NVD CPE matched Example BIOS",
            "vendor fixed version",
            "hardware firmware finding",
            "high",
            "Apply firmware update.",
            [
                "https://exploit.example/CVE-2099-9001",
                "http://packetstormsecurity.com/files/131189/example.html",
                "http://www.securityfocus.com/bid/46680",
            ],
        )

        html = HtmlReportBuilder().render(run, [obj], [], self._assessment([obj], [result]))

        self.assertIn("Эксплойт", html)
        self.assertIn("https://exploit.example/CVE-2099-9001", html)
        self.assertIn("packetstormsecurity.com", html)
        self.assertIn("securityfocus.com/bid/46680", html)

    def test_report_explains_confirmed_and_potential_cpe_evidence(self):
        run = AuditRun.create("TEST-PC", True)
        software = InventoryObject(
            "s",
            "Installed Software",
            "software",
            "SQL Server 2012 Common Files",
            {"Vendor": "Microsoft", "Version": "11.1.3000.0"},
            "fixture",
        )
        processor = InventoryObject(
            "p",
            "Processors",
            "processor",
            "Intel(R) Xeon(R) CPU E5620 @ 2.40GHz",
            {"Manufacturer": "Intel", "Processor Description": "Intel Xeon E5620"},
            "fixture",
        )
        confirmed = VulnerabilityMatch(
            cve="CVE-2099-1200",
            source="NVD",
            severity="CRITICAL",
            cvss=9.8,
            kev=False,
            affected_title=software.title,
            evidence="NVD applicability confirmed: installed version is below fixed release",
            confidence="High",
            remediation="Install SQL Server update.",
            references=["https://example.test/CVE-2099-1200"],
            object_uid=software.uid,
            applicability="confirmed",
            cpe="cpe:2.3:a:microsoft:sql_server:11.1.3000.0:*:*:*:*:*:*:*",
        )
        potential = VulnerabilityMatch(
            cve="CVE-2099-5600",
            source="NVD",
            severity="HIGH",
            cvss=8.1,
            kev=False,
            affected_title=processor.title,
            evidence="NVD applicability potential: hardware matched; firmware version is unknown",
            confidence="Medium",
            remediation="Check firmware advisory and apply vendor update if affected.",
            references=["https://example.test/CVE-2099-5600"],
            object_uid=processor.uid,
            applicability="potential",
            cpe="cpe:2.3:o:intel:xeon_e5620_firmware:*:*:*:*:*:*:*:*",
        )
        results = [
            RuleResult(
                confirmed.object_uid,
                confirmed.cve,
                confirmed.source,
                "vulnerability",
                "risk",
                confirmed.severity,
                f"{confirmed.cve}: {confirmed.affected_title}",
                confirmed.evidence,
                "vendor fixed version",
                confirmed.evidence,
                confirmed.confidence,
                confirmed.remediation,
                confirmed.references,
            ),
            RuleResult(
                potential.object_uid,
                potential.cve,
                potential.source,
                "vulnerability",
                "risk",
                potential.severity,
                f"{potential.cve}: {potential.affected_title}",
                potential.evidence,
                "vendor fixed firmware",
                potential.evidence,
                potential.confidence,
                potential.remediation,
                potential.references,
            ),
        ]

        html = HtmlReportBuilder().render(
            run,
            [software, processor],
            [],
            self._assessment([software, processor], results, [confirmed, potential]),
        )

        self.assertIn("Подтверждено", html)
        self.assertIn("Потенциальный риск", html)
        self.assertIn("Версия прошивки не подтверждена", html)
        self.assertIn("Установленная версия", html)
        self.assertIn("11.1.3000.0", html)
        self.assertIn("не определена", html)
        self.assertIn("cpe:2.3:a:microsoft:sql_server:11.1.3000.0", html)
        self.assertIn("cpe:2.3:o:intel:xeon_e5620_firmware", html)
        self.assertIn(".vulnerability-evidence", html)
        self.assertIn("overflow-wrap:anywhere", html)

    def test_summary_separates_document_coverage_from_rule_checked_depth(self):
        run = AuditRun.create("TEST-PC", True)
        risk = InventoryObject("x", "Security", "uac_setting", "UAC", {"EnableLUA": "0"}, "fixture")
        manual = InventoryObject("z", "Devices", "device", "Keyboard", {"Name": "Keyboard"}, "fixture")
        informational = InventoryObject("m", "Memory", "memory_module", "DIMM", {"Capacity": "8 GB"}, "fixture")
        result_risk = RuleResult(
            risk.uid, "CFG-UAC-001", "1", "configuration", "risk", "high",
            "UAC disabled", "0", "1", "Security / UAC / EnableLUA=0", "high", "Enable UAC.",
        )
        result_manual = RuleResult(
            manual.uid, "VULN-COVERAGE", "1", "vulnerability", "insufficient_data", "info",
            "Known-vulnerability coverage", "missing product version", "complete product identity",
            "Devices / Keyboard", "low", "Verify manually.",
        )

        html = HtmlReportBuilder().render(
            run,
            [risk, manual, informational],
            [],
            self._assessment([risk, manual, informational], [result_risk, result_manual]),
        )

        self.assertIn("100%", html)
        self.assertIn("объектов обработано", html)
        self.assertIn("33%", html)
        self.assertIn("проверено правилами", html)

    def test_report_contains_navigation_vulnerabilities_and_inventory_cards(self):
        run = AuditRun.create(hostname="TEST-PC", is_admin=True)
        inventory = [
            InventoryObject(
                category_id="t",
                category_name="Network TCP/IP",
                object_type="network_adapter",
                title="Ethernet",
                fields={"IP-адрес": "192.168.1.10", "DNS-серверы": "1.1.1.1"},
                source="fixture",
            )
        ]
        vulnerabilities = [
            VulnerabilityMatch(
                cve="CVE-2099-0001",
                source="CISA KEV",
                severity="CRITICAL",
                cvss=9.8,
                kev=True,
                affected_title="Example App",
                evidence="Matched Example App",
                confidence="High",
                remediation="Install vendor update",
                references=["https://example.test"],
            )
        ]
        diagnostics = [CollectorDiagnostic(module="network", severity="info", message="ok", source="fixture")]
        path = HtmlReportBuilder().build(self.temp_dir, run, inventory, diagnostics, vulnerabilities)
        with open(path, "r", encoding="utf-8") as handle:
            html = handle.read()

        self.assertIn("Сводка рисков", html)
        self.assertIn("Уязвимости", html)
        self.assertIn("CVE-2099-0001", html)
        self.assertIn("Install vendor update", html)
        self.assertIn("Network TCP/IP", html)
        self.assertIn("IP-адрес", html)
        self.assertIn("Диагностика сбора", html)

    def test_report_uses_winaudit_order_item_value_rows_and_record_cap(self):
        run = AuditRun.create(hostname="TEST-PC", is_admin=False)
        inventory = [
            InventoryObject("A", "Services and Drivers", "service", "Service 1", {"State": "Running"}, "fixture"),
            InventoryObject("s", "Active Setup", "active_setup", "Active Component", {"Version": "1"}, "fixture"),
            *[
                InventoryObject("t", "Open Ports", "open_port", f"TCP 127.0.0.1:{idx}", {"Local Port": str(idx)}, "fixture")
                for idx in range(105)
            ],
        ]
        rendered = HtmlReportBuilder(report_max_records=3).render(run, inventory, [], [])

        self.assertLess(rendered.index("Active Setup"), rendered.index("Services and Drivers"))
        self.assertIn("<th>Item</th><th>Value</th>", rendered)
        self.assertIn("Показаны первые 3 из 105", rendered)
        self.assertIn("TCP 127.0.0.1:0", rendered)
        self.assertNotIn("TCP 127.0.0.1:104", rendered)

    def test_default_report_renders_all_inventory_objects(self):
        run = AuditRun.create(hostname="TEST-PC", is_admin=False)
        inventory = [
            InventoryObject(
                "r",
                "Running Programs",
                "process",
                f"Process {index:03d}",
                {"ProcessId": str(index)},
                "fixture",
            )
            for index in range(105)
        ]

        rendered = HtmlReportBuilder().render(run, inventory, [], [])

        self.assertIn("Process 000", rendered)
        self.assertIn("Process 104", rendered)
        self.assertNotIn("<p class='limit-note'>", rendered)


if __name__ == "__main__":
    unittest.main()
