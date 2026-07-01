import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, os.path.abspath("src"))

from ib_audit.app import _create_vulnerability_correlator, analyze_report, analyze_reports
from ib_audit.batch import BatchProgress
from ib_audit.cancellation import CancellationToken
from ib_audit.models import CollectorDiagnostic, VulnerabilityMatch
from ib_audit.repository import SQLiteRepository
from ib_audit.source_cache import SnapshotCache
from tests.test_report_import import IB_AUDIT_HTML


class FakeCorrelator:
    def enrich_from_sources(self, inventory, progress=None, cancel_token=None):
        self.inventory = inventory
        return [
            VulnerabilityMatch(
                cve="CVE-2099-4242",
                source="fixture",
                severity="HIGH",
                cvss=8.1,
                kev=False,
                affected_title="Example Tool",
                evidence="Matched imported software name and version.",
                confidence="High",
                remediation="Install the fixed vendor release.",
                references=["https://example.test/CVE-2099-4242"],
            )
        ], [
            CollectorDiagnostic(
                module="vulnerability_sources",
                severity="info",
                message="Fixture source used",
                source="fixture",
            )
        ]


class FakeBatchReportBuilder:
    def build(self, output_dir, batch):
        path = Path(output_dir) / "batch-report.html"
        path.write_text(
            f"{batch.status}:{batch.processed_count}/{batch.selected_count}",
            encoding="utf-8",
        )
        return str(path)


class ReportAnalysisTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.temp_dir)

    def test_analyzes_imported_report_and_persists_bundle(self):
        source = self.temp_dir / "source.html"
        source.write_text(IB_AUDIT_HTML, encoding="utf-8")
        output = self.temp_dir / "outputs"
        database = output / "ib_audit.db"
        correlator = FakeCorrelator()

        result = analyze_report(
            source,
            db_path=database,
            output_dir=output,
            correlator=correlator,
        )

        self.assertEqual("ib-audit-html", result["source_format"])
        self.assertEqual(3, result["inventory_count"])
        self.assertEqual(1, result["vulnerability_count"])
        self.assertEqual(3, len(correlator.inventory))
        report_path = Path(result["report_path"])
        self.assertTrue(report_path.exists())
        self.assertIn("CVE-2099-4242", report_path.read_text(encoding="utf-8"))

        repository = SQLiteRepository(database)
        run = repository.latest_run()
        self.assertIsNotNone(run)
        self.assertEqual("completed", run.status)
        self.assertEqual("ib-audit-html", run.summary["source_format"])
        bundle = repository.load_run_bundle(run.id)
        self.assertEqual(3, len(bundle["inventory"]))
        self.assertEqual(2, len(bundle["diagnostics"]))
        self.assertEqual(1, len(bundle["vulnerabilities"]))
        self.assertEqual(1, len(bundle["reports"]))

    def test_batch_continues_after_invalid_document(self):
        first = self.temp_dir / "first.html"
        bad = self.temp_dir / "bad.html"
        second = self.temp_dir / "second.html"
        first.write_text(IB_AUDIT_HTML, encoding="utf-8")
        bad.write_text("<html>unsupported</html>", encoding="utf-8")
        second.write_text(
            IB_AUDIT_HTML.replace("LOCAL-PC", "LOCAL-PC-2"),
            encoding="utf-8",
        )

        result = analyze_reports(
            [first, bad, second],
            db_path=self.temp_dir / "batch.db",
            output_dir=self.temp_dir / "out",
            online_sources=False,
            report_builder=FakeBatchReportBuilder(),
        )

        self.assertEqual("completed_with_errors", result["status"])
        self.assertEqual(2, result["processed_count"])
        self.assertEqual(1, result["failed_count"])
        self.assertEqual(["LOCAL-PC", "LOCAL-PC-2"], result["hostnames"])
        self.assertTrue(Path(result["report_path"]).exists())

    def test_batch_cancellation_keeps_only_completed_documents(self):
        token = CancellationToken()
        first = self.temp_dir / "one.html"
        second = self.temp_dir / "two.html"
        first.write_text(IB_AUDIT_HTML, encoding="utf-8")
        second.write_text(
            IB_AUDIT_HTML.replace("LOCAL-PC", "LOCAL-PC-2"),
            encoding="utf-8",
        )

        def cancel_after_first_completed(event):
            if isinstance(event, BatchProgress) and event.stage == "completed":
                token.cancel()

        result = analyze_reports(
            [first, second],
            output_dir=self.temp_dir / "out",
            db_path=self.temp_dir / "batch.db",
            progress=cancel_after_first_completed,
            online_sources=False,
            cancel_token=token,
            report_builder=FakeBatchReportBuilder(),
        )

        self.assertEqual("cancelled", result["status"])
        self.assertEqual(1, result["processed_count"])
        self.assertEqual(2, result["selected_count"])
        self.assertEqual(["LOCAL-PC"], result["hostnames"])
        self.assertIn("cancelled:1/2", Path(result["report_path"]).read_text(encoding="utf-8"))

    @patch("ib_audit.app.VulnerabilityCorrelator")
    @patch("ib_audit.app.FstecBduClient")
    def test_default_correlator_includes_live_fstec_client(self, fstec_class, correlator_class):
        fstec_client = fstec_class.return_value

        result = _create_vulnerability_correlator()

        fstec_class.assert_called_once_with()
        correlator_class.assert_called_once_with(fstec_client=fstec_client)
        self.assertEqual(correlator_class.return_value, result)

    @patch("ib_audit.app.VulnerabilityCorrelator")
    @patch("ib_audit.app.FstecBduClient")
    def test_full_mode_passes_cache_to_live_fstec_client(self, fstec_class, correlator_class):
        cache = SnapshotCache(self.temp_dir / "cache")

        _create_vulnerability_correlator(cache=cache, online_sources=True, vulnerability_mode="full")

        fstec_class.assert_called_once_with(cache=cache, online=True)
        source_client = correlator_class.call_args.kwargs["source_client"]
        self.assertTrue(source_client.online)

    @patch("ib_audit.app.VulnerabilityCorrelator")
    @patch("ib_audit.app.FstecBduClient")
    def test_fast_mode_uses_cache_only_sources_and_skips_live_fstec(self, fstec_class, correlator_class):
        cache = SnapshotCache(self.temp_dir / "cache")

        _create_vulnerability_correlator(cache=cache, online_sources=True, vulnerability_mode="fast")

        fstec_class.assert_not_called()
        source_client = correlator_class.call_args.kwargs["source_client"]
        self.assertFalse(source_client.online)


if __name__ == "__main__":
    unittest.main()
