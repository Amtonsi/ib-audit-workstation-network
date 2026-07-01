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
    BatchProgress,
    normalize_report_paths,
)
from ib_audit.models import (
    AuditRun,
    CoverageSummary,
    RuleResult,
    WindowsProfile,
)


def document_result(hostname: str, risk_count: int, total: int) -> BatchDocumentResult:
    run = AuditRun.create(hostname, False)
    rules = []
    if risk_count:
        rules.append(
            RuleResult(
                hostname,
                "CVE-2099-0001",
                "fixture",
                "vulnerability",
                "risk",
                "high",
                "Example issue",
                "affected",
                "fixed",
                "evidence",
                "high",
                "Update.",
            )
        )
    assessment = AssessmentBundle(
        WindowsProfile(
            "test", "Windows", "", "", "", "x64", "workstation", False
        ),
        [],
        rules,
        [],
        CoverageSummary(total, risk_count, total - risk_count, 0, 0),
        [],
        [],
    )
    return BatchDocumentResult(
        Path(f"{hostname}.html"),
        "winaudit-html",
        run,
        [],
        [],
        assessment,
    )


class BatchModelTests(unittest.TestCase):
    def test_paths_are_deduplicated_in_selection_order(self):
        paths = normalize_report_paths(["a.html", "b.html", "./a.html"])

        self.assertEqual([Path("a.html"), Path("b.html")], paths)

    def test_weighted_coverage_and_common_findings_use_completed_documents(self):
        batch = BatchAssessment.create(
            selected_paths=[Path("A.html"), Path("B.html"), Path("bad.html")],
            completed=[
                document_result("A", 1, 10),
                document_result("B", 0, 30),
            ],
            failures=[BatchDocumentFailure(Path("bad.html"), "unsupported")],
            status="completed_with_errors",
        )

        self.assertEqual(3, batch.selected_count)
        self.assertEqual(2, batch.processed_count)
        self.assertEqual(1, batch.failed_count)
        self.assertEqual(40, batch.coverage.total_objects)
        self.assertEqual(1, batch.coverage.risk)
        self.assertEqual(1, batch.severity_counts["high"])
        self.assertEqual(["A"], batch.common_findings[0].hostnames)

    def test_common_findings_group_same_rule_across_hosts(self):
        first = document_result("A", 1, 10)
        second = document_result("B", 1, 20)

        batch = BatchAssessment.create(
            [Path("A.html"), Path("B.html")],
            [first, second],
            [],
            "completed",
        )

        self.assertEqual(1, len(batch.common_findings))
        self.assertEqual(["A", "B"], batch.common_findings[0].hostnames)

    def test_batch_progress_exposes_non_localized_fields(self):
        event = BatchProgress(2, 4, "assessment", Path("pc-02.html"), "PC-02")

        self.assertEqual((2, 4, "assessment"), (event.index, event.total, event.stage))
        self.assertEqual("PC-02", event.hostname)


if __name__ == "__main__":
    unittest.main()
