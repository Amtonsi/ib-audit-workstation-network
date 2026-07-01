import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.abspath("src"))

from ib_audit.report_import import ReportImportError, import_audit_report


WINAUDIT_HTML = """<!doctype html>
<html>
<head><title>WinAudit Computer Audit</title></head>
<body>
<center><b>Computer Audit for LEGACY-PC</b></center>
<a name="anchor1"></a><center><b>1) Обзор системы</b></center>
<table>
<tr><td><b>Item</b></td><td><b>Value</b></td></tr>
<tr><td>Operating System</td><td>Microsoft Windows 10 Pro 64-Bit</td></tr>
</table>
<a name="anchor4"></a><center><b>4) Installed Programs</b></center>
<a name="anchor5"></a><b>5) 7-Zip 24.09 (x64)</b>
<table>
<tr><td><b>Item</b></td><td><b>Value</b></td></tr>
<tr><td>Name</td><td>7-Zip 24.09 (x64)</td></tr>
<tr><td>Vendor</td><td>Igor Pavlov</td></tr>
<tr><td>Version</td><td>24.09</td></tr>
</table>
<a name="anchor6"></a><center><b>6) Службы и драйвера</b></center>
<a name="anchor7"></a><b>7) Example Service</b>
<table>
<tr><td><b>Item</b></td><td><b>Value</b></td></tr>
<tr><td>Name</td><td>Example Service</td></tr>
<tr><td>State</td><td>Running</td></tr>
<tr><td>Path Name</td><td>C:\\Example\\service.exe</td></tr>
</table>
</body>
</html>
"""


IB_AUDIT_HTML = """<!doctype html>
<html lang="ru">
<head><meta charset="utf-8"><title>ИБ-аудит LOCAL-PC</title></head>
<body>
<section id="s-installed-software"><h2>Installed Software</h2>
<div class="card"><h3>Example Tool</h3>
<table class="item-value"><tr><th>Item</th><th>Value</th></tr>
<tr><td>Name</td><td>Example Tool</td></tr>
<tr><td>Version</td><td>2.5</td></tr>
<tr><td>Vendor</td><td>Example Vendor</td></tr>
</table></div></section>
<section id="s-operating-system"><h2>Operating System</h2>
<div class="card"><h3>Microsoft Windows 11 Pro</h3>
<table class="item-value"><tr><th>Item</th><th>Value</th></tr>
<tr><td>Caption</td><td>Microsoft Windows 11 Pro</td></tr>
<tr><td>Version</td><td>10.0.26100</td></tr>
</table></div></section>
<section id="s-services-and-drivers"><h2>Services and Drivers</h2>
<div class="card"><h3>Example Agent</h3>
<table class="item-value"><tr><th>Item</th><th>Value</th></tr>
<tr><td>Name</td><td>Example Agent</td></tr>
<tr><td>State</td><td>Running</td></tr>
</table></div></section>
</body>
</html>
"""


class ReportImportTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.temp_dir)

    def _write(self, name, content):
        path = self.temp_dir / name
        path.write_text(content, encoding="utf-8")
        return path

    def test_imports_winaudit_inventory_for_vulnerability_analysis(self):
        imported = import_audit_report(self._write("winaudit.html", WINAUDIT_HTML))

        self.assertEqual("winaudit-html", imported.report_format)
        self.assertEqual("LEGACY-PC", imported.hostname)
        self.assertEqual(3, len(imported.inventory))
        software = next(item for item in imported.inventory if item.object_type == "software")
        operating_system = next(item for item in imported.inventory if item.object_type == "operating_system")
        service = next(item for item in imported.inventory if item.object_type == "service")
        self.assertEqual("7-Zip 24.09 (x64)", software.title)
        self.assertEqual("24.09", software.fields["Version"])
        self.assertEqual("Igor Pavlov", software.fields["Vendor"])
        self.assertEqual("Microsoft Windows 10 Pro 64-Bit", operating_system.title)
        self.assertEqual("Running", service.fields["State"])

    def test_imports_ib_audit_inventory_for_vulnerability_analysis(self):
        imported = import_audit_report(self._write("ib-audit.html", IB_AUDIT_HTML))

        self.assertEqual("ib-audit-html", imported.report_format)
        self.assertEqual("LOCAL-PC", imported.hostname)
        self.assertEqual(3, len(imported.inventory))
        software = next(item for item in imported.inventory if item.object_type == "software")
        operating_system = next(item for item in imported.inventory if item.object_type == "operating_system")
        self.assertEqual("Example Tool", software.title)
        self.assertEqual("Example Vendor", software.fields["Vendor"])
        self.assertEqual("Microsoft Windows 11 Pro", operating_system.title)

    def test_rejects_unrecognized_html(self):
        path = self._write("unknown.html", "<html><head><title>Other report</title></head><body></body></html>")

        with self.assertRaisesRegex(ReportImportError, "Unsupported"):
            import_audit_report(path)

    def test_rejects_empty_report(self):
        path = self._write("empty.html", "")

        with self.assertRaisesRegex(ReportImportError, "empty"):
            import_audit_report(path)

    def test_imports_every_winaudit_table_and_unknown_group(self):
        path = self._write(
            "full.html",
            """<html><head><title>WinAudit Computer Audit</title></head><body>
            <center><b>Computer Audit for FULLHOST</b></center>
            <center><b>1) System Overview</b></center>
            <b>Computer</b><table><tr><td>Item</td><td>Value</td></tr>
            <tr><td>Operating System</td><td>Windows 11</td></tr></table>
            <center><b>2) Startup Programs</b></center>
            <b>Agent</b><table><tr><td>Item</td><td>Value</td></tr>
            <tr><td>Command</td><td>C:\\Users\\Public\\agent.exe</td></tr></table>
            <center><b>3) Vendor Extension</b></center>
            <b>Custom row</b><table><tr><td>Item</td><td>Value</td></tr>
            <tr><td>Enabled</td><td>Yes</td></tr></table>
            </body></html>""",
        )
        imported = import_audit_report(path)
        self.assertEqual(3, len(imported.inventory))
        self.assertEqual(
            ["System Overview", "Startup Programs", "Vendor Extension"],
            [item.category_name for item in imported.inventory],
        )
        self.assertTrue(all(item.source_document_id == imported.document.id for item in imported.inventory))

    def test_imports_every_ib_audit_card_not_only_vulnerability_candidates(self):
        path = self._write(
            "ib.html",
            """<html><head><title>ИБ-аудит HOST</title></head><body>
            <section><h2>Memory</h2><div class="card"><h3>DIMM 0</h3>
            <table><tr><th>Item</th><th>Value</th></tr><tr><td>Capacity</td><td>8 GB</td></tr></table>
            </div></section>
            <section><h2>Startup Programs</h2><div class="card"><h3>Agent</h3>
            <table><tr><th>Item</th><th>Value</th></tr><tr><td>Command</td><td>agent.exe</td></tr></table>
            </div></section></body></html>""",
        )
        imported = import_audit_report(path)
        self.assertEqual(["Memory", "Startup Programs"], [item.category_name for item in imported.inventory])


if __name__ == "__main__":
    unittest.main()
