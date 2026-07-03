import os
import shutil
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.abspath("src"))

from ib_audit.models import (
    AuditRun,
    CollectorDiagnostic,
    CoverageSummary,
    InventoryObject,
    ObjectAssessment,
    ReportRecord,
    RuleResult,
    SourceDocument,
    VulnerabilityCoverage,
    VulnerabilityMatch,
)
from ib_audit.repository import SQLiteRepository


class SQLiteRepositoryTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.temp_dir, "audit.db")

    def tearDown(self):
        shutil.rmtree(self.temp_dir)

    def test_saves_and_loads_audit_bundle(self):
        repo = SQLiteRepository(self.db_path)
        run = AuditRun.create(hostname="TEST-PC", is_admin=True)
        repo.save_run(run)
        repo.save_inventory_objects(
            run.id,
            [
                InventoryObject(
                    category_id="s",
                    category_name="Installed Software",
                    object_type="software",
                    title="Example App",
                    fields={"Version": "1.0", "Vendor": "Example"},
                    source="fixture",
                    confidence="high",
                )
            ],
        )
        repo.save_diagnostics(
            run.id,
            [CollectorDiagnostic(module="software", severity="info", message="ok", source="fixture")],
        )
        repo.save_vulnerability_matches(
            run.id,
            [
                VulnerabilityMatch(
                    cve="CVE-2099-0001",
                    source="NVD",
                    severity="HIGH",
                    cvss=8.8,
                    kev=False,
                    affected_title="Example App",
                    evidence="Example App 1.0",
                    confidence="Medium",
                    remediation="Update Example App",
                    references=["https://nvd.nist.gov/vuln/detail/CVE-2099-0001"],
                )
            ],
        )
        repo.save_report(
            ReportRecord(run_id=run.id, path=os.path.join(self.temp_dir, "report.html"), report_type="html")
        )

        reopened = SQLiteRepository(self.db_path)
        bundle = reopened.load_run_bundle(run.id)

        self.assertEqual(bundle["run"].hostname, "TEST-PC")
        self.assertEqual(bundle["inventory"][0].title, "Example App")
        self.assertEqual(bundle["diagnostics"][0].message, "ok")
        self.assertEqual(bundle["vulnerabilities"][0].cve, "CVE-2099-0001")
        self.assertEqual(bundle["reports"][0].report_type, "html")

    def test_saves_source_document_assessments_and_coverage(self):
        repo = SQLiteRepository(self.db_path)
        run = AuditRun.create("host", False)
        obj = InventoryObject("s", "Installed Software", "software", "Tool", {"Version": "1.0"}, "fixture")
        document = SourceDocument.create(
            report_format="winaudit-html",
            title="WinAudit Computer Audit",
            path="C:/reports/audit.html",
            size_bytes=123,
            sha256="a" * 64,
        )
        result = RuleResult(
            object_uid=obj.uid,
            rule_id="VULN-IDENTITY",
            rule_version="1",
            kind="vulnerability",
            status="passed",
            severity="info",
            title="Product identity available",
            actual="Tool 1.0",
            expected="name and version",
            evidence="Installed Software / Tool",
            confidence="high",
            remediation="No action required.",
        )
        assessment = ObjectAssessment(obj.uid, "passed", 1, 1, 0, 0)
        coverage = CoverageSummary(1, 0, 1, 0, 0)

        repo.save_run(run)
        repo.save_source_document(run.id, document)
        repo.save_inventory_objects(run.id, [obj])
        repo.save_assessment_bundle(run.id, [result], [assessment], coverage)

        bundle = repo.load_run_bundle(run.id)
        self.assertEqual(document.sha256, bundle["source_documents"][0].sha256)
        self.assertEqual(obj.uid, bundle["inventory"][0].uid)
        self.assertEqual("VULN-IDENTITY", bundle["rule_results"][0].rule_id)
        self.assertEqual("passed", bundle["assessments"][0].status)
        self.assertEqual(1, bundle["coverage"].total_objects)

    def test_saves_vulnerability_applicability_and_coverage_trace(self):
        repo = SQLiteRepository(self.db_path)
        run = AuditRun.create("host", False)
        obj = InventoryObject("p", "Processors", "processor", "Intel Xeon E5620", {}, "fixture")
        match = VulnerabilityMatch(
            cve="CVE-2099-8800",
            source="NVD",
            severity="HIGH",
            cvss=8.1,
            kev=False,
            affected_title=obj.title,
            evidence="hardware matched; firmware version is unknown",
            confidence="Medium",
            remediation="Apply vendor security updates.",
            references=["https://vendor.example/CVE-2099-8800"],
            object_uid=obj.uid,
            applicability="potential",
            cpe="cpe:2.3:o:intel:xeon_e5620_firmware:*:*:*:*:*:*:*:*",
        )
        coverage = {
            obj.uid: VulnerabilityCoverage(
                object_uid=obj.uid,
                state="complete",
                cpe_status="resolved",
                sources_checked=("NVD",),
                candidate_count=1,
                evaluated_count=1,
                truncated=False,
                reason="CPE candidates evaluated",
                trace={"candidates": ["cpe:2.3:h:intel:xeon:e5620:*:*:*:*:*:*:*"]},
            )
        }

        repo.save_run(run)
        repo.save_inventory_objects(run.id, [obj])
        repo.save_vulnerability_matches(run.id, [match])
        repo.save_vulnerability_coverage(run.id, coverage)

        bundle = repo.load_run_bundle(run.id)

        self.assertEqual("potential", bundle["vulnerabilities"][0].applicability)
        self.assertEqual(match.cpe, bundle["vulnerabilities"][0].cpe)
        self.assertEqual("resolved", bundle["vulnerability_coverage"][obj.uid].cpe_status)
        self.assertEqual(
            ["cpe:2.3:h:intel:xeon:e5620:*:*:*:*:*:*:*"],
            bundle["vulnerability_coverage"][obj.uid].trace["candidates"],
        )

    def test_migrates_legacy_inventory_table_without_losing_rows(self):
        legacy = Path(self.temp_dir) / "legacy.db"
        conn = sqlite3.connect(legacy)
        try:
            conn.executescript(
                """
                CREATE TABLE inventory_objects (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id TEXT NOT NULL,
                    category_id TEXT NOT NULL,
                    category_name TEXT NOT NULL,
                    object_type TEXT NOT NULL,
                    title TEXT NOT NULL,
                    fields_json TEXT NOT NULL,
                    source TEXT NOT NULL,
                    confidence TEXT NOT NULL,
                    raw_json TEXT NOT NULL,
                    collected_at TEXT NOT NULL
                );
                INSERT INTO inventory_objects
                (run_id, category_id, category_name, object_type, title, fields_json,
                 source, confidence, raw_json, collected_at)
                VALUES ('old', 's', 'Installed Software', 'software', 'Legacy',
                        '{}', 'fixture', 'high', '{}', '2026-06-29T00:00:00+00:00');
                """
            )
            conn.commit()
        finally:
            conn.close()
        repo = SQLiteRepository(legacy)
        with repo._connection() as conn:
            columns = {row["name"] for row in conn.execute("PRAGMA table_info(inventory_objects)")}
            count = conn.execute("SELECT COUNT(*) FROM inventory_objects").fetchone()[0]
        self.assertIn("object_uid", columns)
        self.assertEqual(1, count)


if __name__ == "__main__":
    unittest.main()
