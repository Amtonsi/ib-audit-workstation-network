import os
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

    def test_inventory_object_with_risk_shows_specific_risk_below_fields(self):
        batch = BatchAssessment.create(
            [Path("PC-A.html")],
            [make_result("PC-A", "critical")],
            [],
            "completed",
        )

        rendered = BatchHtmlReportBuilder().render(batch)
        object_risk_section = rendered.split("class='object-risk-list'", 1)[1].split("</article>", 1)[0]

        self.assertIn("CVE-2099-0001", object_risk_section)
        self.assertIn("Example Tool 1.0", object_risk_section)
        self.assertIn("critical", object_risk_section)


if __name__ == "__main__":
    unittest.main()
