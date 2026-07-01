import html
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.abspath("src"))

from ib_audit.app import analyze_report, analyze_reports
from ib_audit.category_catalog import WINAUDIT_CATEGORY_ORDER
from ib_audit.report_import import import_audit_report
from ib_audit.repository import SQLiteRepository


def synthetic_winaudit() -> str:
    sections = []
    for index, category in enumerate(WINAUDIT_CATEGORY_ORDER, 1):
        fields = [("Name", f"Synthetic {category}")]
        if category == "Operating System":
            fields.extend([("Caption", "Microsoft Windows 11 Pro"), ("Version", "10.0.26100")])
        elif category == "Installed Software":
            fields.extend([("Vendor", "Example Vendor"), ("Version", "1.0")])
        elif category == "Services and Drivers":
            fields.extend([("DriverProviderName", "Example Vendor"), ("DriverVersion", "1.0"), ("IsSigned", "True")])
        rows = "".join(f"<tr><td>{html.escape(key)}</td><td>{html.escape(value)}</td></tr>" for key, value in fields)
        sections.append(
            f"<center><b>{index}) {html.escape(category)}</b></center>"
            f"<b>Synthetic {html.escape(category)}</b><table>"
            "<tr><td>Item</td><td>Value</td></tr>"
            f"{rows}</table>"
        )
    return (
        "<html><head><title>WinAudit Computer Audit</title></head><body>"
        "<center><b>Computer Audit for SYNTHETIC-PC</b></center>"
        + "".join(sections) + "</body></html>"
    )


class FullReportIntegrationTests(unittest.TestCase):
    def test_two_documents_produce_one_self_contained_batch_report(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            first = root / "first.html"
            second = root / "second.html"
            first.write_text(synthetic_winaudit(), encoding="utf-8")
            second.write_text(
                synthetic_winaudit().replace("SYNTHETIC-PC", "SYNTHETIC-PC-2"),
                encoding="utf-8",
            )

            result = analyze_reports(
                [first, second],
                db_path=root / "audit.db",
                output_dir=root,
                online_sources=False,
            )
            rendered = Path(result["report_path"]).read_text(encoding="utf-8")

        self.assertEqual("completed", result["status"])
        self.assertEqual(2, result["processed_count"])
        self.assertEqual(["SYNTHETIC-PC", "SYNTHETIC-PC-2"], result["hostnames"])
        self.assertIn("Сводный отчёт", rendered)
        self.assertIn("SYNTHETIC-PC", rendered)
        self.assertIn("SYNTHETIC-PC-2", rendered)
        self.assertNotIn("<script src=", rendered.casefold())
        self.assertNotIn("<link href=", rendered.casefold())

    def test_full_document_loses_no_object_and_covers_each_one(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "full.html"
            source.write_text(synthetic_winaudit(), encoding="utf-8")
            imported = import_audit_report(source)
            result = analyze_report(
                source, db_path=root / "audit.db", output_dir=root,
                online_sources=False,
            )
            bundle = SQLiteRepository(root / "audit.db").load_run_bundle(result["run"].id)
            rendered = Path(result["report_path"]).read_text(encoding="utf-8")
        self.assertEqual(46, len(imported.inventory))
        self.assertEqual(len(imported.inventory), len(bundle["inventory"]))
        self.assertEqual(len(bundle["inventory"]), len(bundle["assessments"]))
        self.assertEqual(
            {item.uid for item in bundle["inventory"]},
            {item.object_uid for item in bundle["assessments"]},
        )
        for category in WINAUDIT_CATEGORY_ORDER:
            self.assertIn(category, rendered)
        self.assertIn("data-status=", rendered)
        self.assertNotIn("<script src=", rendered.casefold())
        self.assertNotIn("<link href=", rendered.casefold())
