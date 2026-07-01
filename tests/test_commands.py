import os
import sys
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, os.path.abspath("src"))

from ib_audit.commands import hidden_subprocess_kwargs, run_command


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

    def test_run_command_keeps_utf8_output(self):
        utf8_bytes = "\u0422\u0435\u0441\u0442 UTF-8".encode("utf-8")
        command = [
            sys.executable,
            "-c",
            f"import sys; sys.stdout.buffer.write(bytes.fromhex('{utf8_bytes.hex()}'))",
        ]

        result = run_command(command)

        self.assertEqual(result.stdout, "\u0422\u0435\u0441\u0442 UTF-8")


if __name__ == "__main__":
    unittest.main()
