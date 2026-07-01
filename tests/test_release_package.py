import os
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, os.path.abspath("."))

from scripts.build_release_package import build_release_zip


class ReleasePackageTests(unittest.TestCase):
    def test_pyinstaller_spec_includes_rulepack_json_files(self):
        spec = Path("build/pyinstaller/IBAuditWorkstation.spec").read_text(
            encoding="utf-8"
        ).replace("\\", "/")

        self.assertIn("src/ib_audit/rulepacks/*.json", spec)
        self.assertIn("'ib_audit/rulepacks'", spec)

    def test_release_zip_includes_license_file(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            app_dir = root / "app"
            app_dir.mkdir()
            (app_dir / "IBAuditWorkstation.exe").write_bytes(b"exe")
            vuln_dir = root / "vulnerability-database"
            vuln_dir.mkdir()
            (vuln_dir / "vulnerability_sources.db").write_bytes(b"db")
            guide = root / "guide.pdf"
            guide.write_bytes(b"pdf")
            license_file = root / "LICENSE"
            license_file.write_text("MIT License\n", encoding="utf-8")
            output = root / "release.zip"

            build_release_zip(output, app_dir, vuln_dir, guide, license_file=license_file)

            with zipfile.ZipFile(output) as archive:
                self.assertIn("LICENSE", archive.namelist())
                self.assertEqual("MIT License\n", archive.read("LICENSE").decode("utf-8").replace("\r\n", "\n"))


if __name__ == "__main__":
    unittest.main()
