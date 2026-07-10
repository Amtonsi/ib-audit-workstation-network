import os
import json
import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, os.path.abspath("src"))

from ib_audit.assessment import AssessmentBundle
from ib_audit.batch import (
    BatchAssessment,
    BatchDocumentFailure,
    BatchDocumentResult,
)
from ib_audit.batch_report import BatchHtmlReportBuilder
from ib_audit.models import (
    AuditRun,
    CollectorDiagnostic,
    CoverageSummary,
    InventoryObject,
    ObjectAssessment,
    RuleResult,
    VulnerabilityMatch,
    WindowsProfile,
)


def make_result(
    hostname: str,
    severity: str = "high",
    references: list[str] | None = None,
) -> BatchDocumentResult:
    run = AuditRun.create(hostname, False)
    obj = InventoryObject(
        "software",
        "Installed Software",
        "software",
        "Example Tool",
        {"Version": "1.0", "Vendor": "Example"},
        "fixture",
    )
    rule = RuleResult(
        obj.uid,
        "CVE-2099-0001",
        "fixture",
        "vulnerability",
        "risk",
        severity,
        "Уязвимая версия",
        "1.0",
        "2.0",
        "Example Tool 1.0",
        "high",
        "Обновить Example Tool.",
        references or [],
    )
    assessment = AssessmentBundle(
        WindowsProfile(
            "test", "Windows", "", "", "", "x64", "workstation", False
        ),
        [],
        [rule],
        [ObjectAssessment(obj.uid, "risk", 1, 0, 1, 0)],
        CoverageSummary(1, 1, 0, 0, 0),
        [],
        [],
    )
    return BatchDocumentResult(
        Path(f"{hostname}.html"),
        "winaudit-html",
        run,
        [obj],
        [CollectorDiagnostic("import", "info", "ok", "fixture")],
        assessment,
    )


class BatchHtmlReportBuilderTests(unittest.TestCase):
    def test_aggregate_report_contains_visual_summary_and_host_details(self):
        batch = BatchAssessment.create(
            [Path("PC-A.html"), Path("PC-B.html")],
            [make_result("PC-A", "critical"), make_result("PC-B", "high")],
            [],
            "completed",
        )

        rendered = BatchHtmlReportBuilder().render(batch)

        self.assertIn("Сводный отчёт", rendered)
        self.assertIn("Компьютеры по приоритету", rendered)
        self.assertIn("Общие проблемы", rendered)
        self.assertIn("PC-A", rendered)
        self.assertIn("PC-B", rendered)
        self.assertIn("data-host='PC-A'", rendered)
        self.assertIn("Уязвимая версия", rendered)
        self.assertIn("Installed Software", rendered)
        self.assertIn("Диагностика", rendered)
        self.assertNotIn("<script src=", rendered.casefold())
        self.assertNotIn("<link href=", rendered.casefold())

    def test_cancelled_report_labels_partial_metrics(self):
        batch = BatchAssessment.create(
            [Path("PC-A.html"), Path("PC-B.html")],
            [make_result("PC-A")],
            [],
            "cancelled",
        )

        rendered = BatchHtmlReportBuilder().render(batch)

        self.assertIn("Проверка отменена", rendered)
        self.assertIn("1 из 2", rendered)
        self.assertIn("не включены в показатели", rendered)

    def test_failure_section_escapes_file_and_error_text(self):
        batch = BatchAssessment.create(
            [Path("<bad>.html")],
            [],
            [BatchDocumentFailure(Path("<bad>.html"), "<script>alert(1)</script>")],
            "completed_with_errors",
        )

        rendered = BatchHtmlReportBuilder().render(batch)

        self.assertIn("&lt;bad&gt;.html", rendered)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", rendered)
        self.assertNotIn("<script>alert(1)</script>", rendered)

    def test_reference_links_wrap_inside_common_finding_cards(self):
        long_reference = (
            "https://msrc.microsoft.com/update-guide/vulnerability/"
            "CVE-2024-0057-with-a-very-long-reference-path-that-must-not-overlap-neighbor-cards"
        )
        batch = BatchAssessment.create(
            [Path("PC-A.html")],
            [make_result("PC-A", "critical", references=[long_reference])],
            [],
            "completed",
        )

        rendered = BatchHtmlReportBuilder().render(batch)
        reference_css = rendered.split(".reference-list", 1)[1].split(".coverage-bar", 1)[0]

        self.assertIn(long_reference, rendered)
        self.assertIn("class='reference-link'", rendered)
        self.assertIn("display:flex", reference_css)
        self.assertIn("max-width:100%", reference_css)
        self.assertIn("overflow-wrap:anywhere", reference_css)
        self.assertIn("word-break:break-word", reference_css)

    def test_batch_report_explains_cpe_applicability_in_common_and_host_cards(self):
        result = make_result("PC-A", "critical")
        rule = result.assessment.rule_results[0]
        vulnerability = VulnerabilityMatch(
            cve=rule.rule_id,
            source="NVD",
            severity="CRITICAL",
            cvss=9.8,
            kev=False,
            affected_title="Example Tool",
            evidence="NVD applicability potential: hardware matched; firmware version is unknown",
            confidence="Medium",
            remediation=rule.remediation,
            references=rule.references,
            object_uid=rule.object_uid,
            applicability="potential",
            cpe=(
                "cpe:2.3:o:intel:xeon_e5620_firmware:"
                "very-long-version-component-that-must-wrap-inside-cards:*:*:*:*:*:*:*"
            ),
        )
        rule.evidence = vulnerability.evidence
        rule.actual = vulnerability.evidence
        result.assessment.vulnerabilities.append(vulnerability)
        batch = BatchAssessment.create([Path("PC-A.html")], [result], [], "completed")

        rendered = BatchHtmlReportBuilder().render(batch)

        self.assertIn("Потенциальный риск", rendered)
        self.assertIn("Версия прошивки не подтверждена", rendered)
        self.assertIn("Установленная версия", rendered)
        self.assertIn("1.0", rendered)
        self.assertIn("cpe:2.3:o:intel:xeon_e5620_firmware", rendered)
        self.assertIn("class='vulnerability-evidence'", rendered)
        evidence_css = rendered.split(".vulnerability-evidence", 1)[1].split(".coverage-bar", 1)[0]
        self.assertIn("min-width:0", evidence_css)
        self.assertIn("overflow-wrap:anywhere", evidence_css)
        self.assertIn("word-break:break-word", evidence_css)

    def test_host_navigation_opens_document_and_links_risks_to_inventory(self):
        result = make_result("INTEGRA-2", "critical")
        batch = BatchAssessment.create([Path("INTEGRA-2.html")], [result], [], "completed")
        anchor = BatchHtmlReportBuilder._document_anchor(result)

        rendered = BatchHtmlReportBuilder().render(batch)

        self.assertIn(f"href='#{anchor}-risks'", rendered)
        self.assertIn(f"onclick=\"return openComputerSection('{anchor}','risks')\"", rendered)
        self.assertIn(f"id='{anchor}-risks'", rendered)
        self.assertIn(f"id='{anchor}-inventory'", rendered)
        self.assertIn(f"onclick=\"return openComputerSection('{anchor}','inventory')\"", rendered)
        self.assertIn("function openComputerSection", rendered)
        self.assertIn("window.addEventListener('hashchange', openSectionForHash)", rendered)
        self.assertNotIn("<details open>", rendered)

    def test_inventory_object_risk_is_a_compact_link_to_exact_finding(self):
        result = make_result("PC-A", "critical")
        batch = BatchAssessment.create(
            [Path("PC-A.html")],
            [result],
            [],
            "completed",
        )
        anchor = BatchHtmlReportBuilder._document_anchor(result)

        rendered = BatchHtmlReportBuilder().render(batch)
        object_card = rendered.split("class='object-card'", 1)[1].split("</article>", 1)[0]

        self.assertIn("class='object-risk-links'", object_card)
        self.assertIn("CVE-2099-0001", object_card)
        self.assertIn(f"href='#{anchor}-finding-cve-2099-0001-1'", object_card)
        self.assertIn(
            f"onclick=\"return openComputerFinding('{anchor}',"
            f"'{anchor}-finding-cve-2099-0001-1')\"",
            object_card,
        )
        self.assertNotIn("Example Tool 1.0", object_card)
        self.assertIn(
            f"id='{anchor}-finding-cve-2099-0001-1' class='host-finding critical'",
            rendered,
        )

    def test_duplicate_rule_ids_receive_unique_finding_targets(self):
        result = make_result("PC-A", "critical")
        original = result.assessment.rule_results[0]
        result.assessment.rule_results.append(
            RuleResult(
                original.object_uid,
                original.rule_id,
                original.rule_version,
                original.kind,
                original.status,
                original.severity,
                "Вторая уязвимость",
                original.actual,
                original.expected,
                "Второе подтверждение",
                original.confidence,
                original.remediation,
                original.references,
            )
        )
        batch = BatchAssessment.create(
            [Path("PC-A.html")],
            [result],
            [],
            "completed",
        )

        rendered = BatchHtmlReportBuilder().render(batch)
        targets = re.findall(
            r"id='([^']+-finding-cve-2099-0001-\d+)' class='host-finding",
            rendered,
        )

        self.assertEqual(2, len(targets))
        self.assertEqual(2, len(set(targets)))
        for target in targets:
            self.assertIn(f"href='#{target}'", rendered)

    def test_inventory_object_without_risk_has_no_risk_link_row(self):
        result = make_result("PC-A")
        result.assessment.rule_results.clear()
        batch = BatchAssessment.create(
            [Path("PC-A.html")],
            [result],
            [],
            "completed",
        )

        rendered = BatchHtmlReportBuilder().render(batch)
        object_card = rendered.split("class='object-card'", 1)[1].split("</article>", 1)[0]

        self.assertNotIn("object-risk-links", object_card)

    def test_batch_report_renders_wireshark_packet_rows_for_network_capture(self):
        result = make_result("PC-A")
        packet_flow = InventoryObject(
            "N",
            "Network Traffic Capture",
            "network_capture",
            "192.168.1.10:51516 -> 93.184.216.34:80 (HTTP)",
            {
                "Source": "192.168.1.10",
                "Destination": "93.184.216.34",
                "Protocol": "HTTP",
                "Source Port": "51516",
                "Destination Port": "80",
                "Packets": "1",
                "Bytes": "140",
                "Traffic Severity": "high",
                "Traffic Findings": "Clear-text HTTP request observed",
                "Packet Rows JSON": json.dumps([
                    {
                        "No.": "7",
                        "Time": "10.125",
                        "Source": "192.168.1.10:51516",
                        "Destination": "93.184.216.34:80",
                        "Protocol": "HTTP",
                        "Length": "140",
                        "Info": "GET /login HTTP/1.1",
                        "Risk": "high",
                        "Details": "Frame 7: 140 bytes",
                        "Bytes Hex": "00 01 02 0a 0b 0c",
                    }
                ]),
            },
            "tshark",
        )
        result.inventory.append(packet_flow)
        batch = BatchAssessment.create([Path("PC-A.html")], [result], [], "completed")

        rendered = BatchHtmlReportBuilder().render(batch)

        self.assertIn("Обобщенное описание трафика", rendered)
        self.assertIn("Схема сети и узлы", rendered)
        self.assertIn("network-map-svg", rendered)
        self.assertIn("packet-list-collapsed", rendered)
        self.assertIn("protocol-badge protocol-http", rendered)
        self.assertIn("Wireshark packet list", rendered)
        self.assertIn("packet-list", rendered)
        self.assertIn("GET /login HTTP/1.1", rendered)
        self.assertIn("00 01 02 0a 0b 0c", rendered)

    def test_exact_risk_navigation_opens_host_and_highlights_target(self):
        rendered = BatchHtmlReportBuilder().render(
            BatchAssessment.create(
                [Path("PC-A.html")],
                [make_result("PC-A", "critical")],
                [],
                "completed",
            )
        )

        self.assertIn("function openComputerFinding(anchor,targetId)", rendered)
        self.assertIn("node.classList.add('risk-target')", rendered)
        self.assertIn("node.classList.remove('risk-target');},5000)", rendered)
        self.assertIn("node.closest('.document-section')", rendered)
        self.assertIn(".object-risk-links{display:flex", rendered)
        self.assertIn("flex-wrap:wrap", rendered)
        self.assertIn(".host-finding.risk-target", rendered)


if __name__ == "__main__":
    unittest.main()
