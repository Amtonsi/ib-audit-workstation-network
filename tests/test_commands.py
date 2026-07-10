import os
import contextlib
import importlib.util
import io
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, os.path.abspath("src"))

from ib_audit.commands import hidden_subprocess_kwargs, resolve_tool_command, run_command


class CommandRunnerTests(unittest.TestCase):
    def test_hidden_subprocess_kwargs_hide_windows_console(self):
        fake_startupinfo = Mock()
        fake_startupinfo.dwFlags = 0
        fake_subprocess = Mock(
            CREATE_NO_WINDOW=0x08000000,
            STARTF_USESHOWWINDOW=1,
            SW_HIDE=0,
            STARTUPINFO=Mock(return_value=fake_startupinfo),
        )

        with patch("ib_audit.commands.os.name", "nt"), patch("ib_audit.commands.subprocess", fake_subprocess):
            kwargs = hidden_subprocess_kwargs()

        self.assertEqual(0x08000000, kwargs["creationflags"])
        self.assertIs(fake_startupinfo, kwargs["startupinfo"])
        self.assertEqual(1, fake_startupinfo.dwFlags)
        self.assertEqual(0, fake_startupinfo.wShowWindow)

    def test_run_command_passes_hidden_subprocess_options(self):
        completed = Mock(returncode=0, stdout=b"ok", stderr=b"")
        with patch("ib_audit.commands.hidden_subprocess_kwargs", return_value={"creationflags": 7}), \
                patch("ib_audit.commands.subprocess.run", return_value=completed) as run:
            result = run_command(["tool.exe", "/quiet"], timeout=12)

        self.assertEqual("ok", result.stdout)
        run.assert_called_once_with(
            ["tool.exe", "/quiet"],
            capture_output=True,
            text=False,
            timeout=12,
            shell=False,
            creationflags=7,
        )

    def test_run_command_decodes_windows_oem_output_without_replacement_characters(self):
        cp866_bytes = "\u041c\u0430\u0439\u043a\u0440\u043e\u0441\u043e\u0444\u0442".encode("cp866")
        command = [
            sys.executable,
            "-c",
            f"import sys; sys.stdout.buffer.write(bytes.fromhex('{cp866_bytes.hex()}'))",
        ]

        result = run_command(command)

        self.assertEqual(result.stdout, "\u041c\u0430\u0439\u043a\u0440\u043e\u0441\u043e\u0444\u0442")
        self.assertNotIn("\ufffd", result.stdout)

    def test_run_command_decodes_windows_ansi_output_without_mojibake(self):
        cp1251_bytes = "\u0411\u0435\u0441\u043f\u0440\u043e\u0432\u043e\u0434\u043d\u0430\u044f \u0441\u0435\u0442\u044c".encode("cp1251")
        command = [
            sys.executable,
            "-c",
            f"import sys; sys.stdout.buffer.write(bytes.fromhex('{cp1251_bytes.hex()}'))",
        ]

        result = run_command(command)

        self.assertEqual(result.stdout, "\u0411\u0435\u0441\u043f\u0440\u043e\u0432\u043e\u0434\u043d\u0430\u044f \u0441\u0435\u0442\u044c")
        self.assertNotIn("\ufffd", result.stdout)
        self.assertNotIn("\u2500", result.stdout)

    def test_run_command_keeps_utf8_output(self):
        utf8_bytes = "\u0422\u0435\u0441\u0442 UTF-8".encode("utf-8")
        command = [
            sys.executable,
            "-c",
            f"import sys; sys.stdout.buffer.write(bytes.fromhex('{utf8_bytes.hex()}'))",
        ]

        result = run_command(command)

        self.assertEqual(result.stdout, "\u0422\u0435\u0441\u0442 UTF-8")

    def test_resolve_tool_command_copies_pyinstaller_tool_to_persistent_cache(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            meipass = temp_path / "bundle"
            source_dir = meipass / "tools" / "nmap"
            source_dir.mkdir(parents=True)
            source_executable = source_dir / "nmap.exe"
            source_executable.write_text("fake nmap", encoding="utf-8")
            local_app_data = temp_path / "local-app-data"

            with patch.object(sys, "_MEIPASS", str(meipass), create=True), \
                    patch.dict(os.environ, {"LOCALAPPDATA": str(local_app_data)}, clear=False), \
                    patch("ib_audit.commands.shutil.which", return_value=None):
                resolved = Path(resolve_tool_command("nmap"))

            expected = local_app_data / "IBAuditWorkstation" / "bundled-tools" / "nmap" / "nmap.exe"
            self.assertEqual(expected, resolved)
            self.assertTrue(resolved.exists())
            self.assertEqual("fake nmap", resolved.read_text(encoding="utf-8"))

    def test_resolve_tool_command_extracts_pyinstaller_tool_zip_to_persistent_cache(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            meipass = temp_path / "bundle"
            bundle_dir = meipass / "tools-bundles"
            bundle_dir.mkdir(parents=True)
            with zipfile.ZipFile(bundle_dir / "wireshark.zip", "w") as archive:
                archive.writestr("tshark.exe", "fake tshark")
            local_app_data = temp_path / "local-app-data"

            with patch.object(sys, "_MEIPASS", str(meipass), create=True), \
                    patch.dict(os.environ, {"LOCALAPPDATA": str(local_app_data)}, clear=False), \
                    patch("ib_audit.commands.shutil.which", return_value=None):
                resolved = Path(resolve_tool_command("tshark"))

            expected = local_app_data / "IBAuditWorkstation" / "bundled-tools" / "wireshark" / "tshark.exe"
            self.assertEqual(expected, resolved)
            self.assertTrue(resolved.exists())
            self.assertEqual("fake tshark", resolved.read_text(encoding="utf-8"))

    def test_update_database_script_enables_cpe_and_prints_stats(self):
        module = self._load_update_database_script()
        result = {
            "db_path": Path("C:/outputs/vulnerability_sources.db"),
            "snapshot_dir": Path("C:/outputs/snapshots"),
            "stats": {
                "mode": "incremental",
                "reused_sources": 1,
                "updated_sources": 2,
                "source_files": 3,
                "cpe_names": 4,
                "cpe_match_criteria": 5,
                "active_cpe_generation": 6,
            },
        }
        stdout = io.StringIO()
        argv = ["update_vulnerability_database.py", "--output", "C:/outputs"]

        with patch.object(module, "update_vulnerability_database", return_value=result) as update_database, \
                patch.object(sys, "argv", argv), \
                contextlib.redirect_stdout(stdout):
            exit_code = module.main()

        self.assertEqual(0, exit_code)
        self.assertTrue(update_database.call_args.kwargs["include_cpe"])
        self.assertFalse(update_database.call_args.kwargs["include_cpe_match"])
        output = stdout.getvalue()
        self.assertIn("CPE Dictionary: 4", output)
        self.assertIn("CPE Match: 5", output)
        self.assertIn("Active CPE generation: 6", output)

    def test_update_database_script_enables_full_cpe_match_when_requested(self):
        module = self._load_update_database_script()
        result = {
            "db_path": Path("C:/outputs/vulnerability_sources.db"),
            "snapshot_dir": Path("C:/outputs/snapshots"),
            "stats": {
                "mode": "incremental",
                "reused_sources": 0,
                "updated_sources": 0,
                "source_files": 0,
                "cpe_names": 0,
                "cpe_match_criteria": 0,
                "active_cpe_generation": 0,
            },
        }
        argv = ["update_vulnerability_database.py", "--output", "C:/outputs", "--with-cpe-match"]

        with patch.object(module, "update_vulnerability_database", return_value=result) as update_database, \
                patch.object(sys, "argv", argv), \
                contextlib.redirect_stdout(io.StringIO()):
            exit_code = module.main()

        self.assertEqual(0, exit_code)
        self.assertTrue(update_database.call_args.kwargs["include_cpe_match"])

    def test_update_database_script_passes_fstec_xlsx_sources(self):
        module = self._load_update_database_script()
        result = {
            "db_path": Path("C:/outputs/vulnerability_sources.db"),
            "snapshot_dir": Path("C:/outputs/snapshots"),
            "stats": {
                "mode": "incremental",
                "reused_sources": 0,
                "updated_sources": 1,
                "source_files": 1,
                "cpe_names": 0,
                "cpe_match_criteria": 0,
                "active_cpe_generation": 0,
                "fstec_vulnerabilities": 7,
                "fstec_products": 9,
                "fstec_import_errors": 2,
                "fstec_download_errors": 3,
            },
        }
        argv = [
            "update_vulnerability_database.py",
            "--output",
            "C:/outputs",
            "--fstec-asutp-xlsx",
            "J:/asutp.xlsx",
            "--fstec-xlsx",
            "C:/downloads/vullist.xlsx",
        ]
        stdout = io.StringIO()

        with patch.object(module, "update_vulnerability_database", return_value=result) as update_database, \
                patch.object(sys, "argv", argv), \
                contextlib.redirect_stdout(stdout):
            exit_code = module.main()

        self.assertEqual(0, exit_code)
        self.assertEqual(
            [("fstec-asutp", Path("J:/asutp.xlsx")), ("fstec-bdu", Path("C:/downloads/vullist.xlsx"))],
            update_database.call_args.kwargs["fstec_xlsx_paths"],
        )
        output = stdout.getvalue()
        self.assertIn("FSTEC vulnerabilities: 7", output)
        self.assertIn("FSTEC products: 9", output)
        self.assertIn("FSTEC XLSX import errors: 2", output)
        self.assertIn("FSTEC XLSX download errors: 3", output)

    @staticmethod
    def _load_update_database_script():
        script = Path("scripts/update_vulnerability_database.py").resolve()
        spec = importlib.util.spec_from_file_location("update_vulnerability_database_script", script)
        module = importlib.util.module_from_spec(spec)
        assert spec is not None and spec.loader is not None
        spec.loader.exec_module(module)
        return module


if __name__ == "__main__":
    unittest.main()
