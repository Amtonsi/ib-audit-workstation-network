import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, os.path.abspath("src"))

from ib_audit.commands import CommandResult
from ib_audit.npcap import (
    NPCAP_DOWNLOAD_URL,
    launch_npcap_installer,
    query_npcap_status,
    resolve_npcap_installer,
)


class NpcapSupportTests(unittest.TestCase):
    def test_query_npcap_status_reports_running_service_as_installed(self):
        output = """
SERVICE_NAME: npcap
        TYPE               : 1  KERNEL_DRIVER
        STATE              : 4  RUNNING
"""

        with patch("ib_audit.npcap.os.name", "nt"), \
                patch("ib_audit.npcap.run_command", return_value=CommandResult(["sc"], 0, output, "")):
            status = query_npcap_status()

        self.assertTrue(status.installed)
        self.assertFalse(status.install_required)
        self.assertIn("RUNNING", status.detail)

    def test_query_npcap_status_reports_missing_service_as_install_required(self):
        result = CommandResult(["sc"], 1060, "", "The specified service does not exist as an installed service.")

        with patch("ib_audit.npcap.os.name", "nt"), \
                patch("ib_audit.npcap.run_command", return_value=result):
            status = query_npcap_status()

        self.assertFalse(status.installed)
        self.assertTrue(status.install_required)
        self.assertIn("Npcap", status.message)

    def test_resolve_npcap_installer_copies_meipass_installer_to_persistent_cache(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            meipass = temp_path / "bundle"
            source_dir = meipass / "tools" / "npcap"
            source_dir.mkdir(parents=True)
            source = source_dir / "npcap-oem.exe"
            source.write_text("fake installer", encoding="utf-8")
            local_app_data = temp_path / "local-app-data"

            with patch.object(sys, "_MEIPASS", str(meipass), create=True), \
                    patch.dict(os.environ, {"LOCALAPPDATA": str(local_app_data)}, clear=False):
                resolved = resolve_npcap_installer()

            expected = local_app_data / "IBAuditWorkstation" / "installers" / "npcap" / "npcap-oem.exe"
            self.assertEqual(expected, resolved)
            self.assertTrue(resolved.exists())
            self.assertEqual("fake installer", resolved.read_text(encoding="utf-8"))

    def test_launch_npcap_installer_uses_uac_shell_execute(self):
        calls = []

        def fake_shell_execute(hwnd, verb, file_name, parameters, directory, show):
            calls.append((hwnd, verb, file_name, parameters, directory, show))
            return 33

        with tempfile.TemporaryDirectory() as temp_dir:
            installer = Path(temp_dir) / "npcap-oem.exe"
            installer.write_text("fake installer", encoding="utf-8")

            with patch("ib_audit.npcap.os.name", "nt"):
                result = launch_npcap_installer(installer, shell_execute=fake_shell_execute)

        self.assertTrue(result.ok)
        self.assertEqual("runas", calls[0][1])
        self.assertEqual(str(installer), calls[0][2])
        self.assertEqual(NPCAP_DOWNLOAD_URL, result.download_url)


if __name__ == "__main__":
    unittest.main()
