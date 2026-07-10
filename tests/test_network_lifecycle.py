import sys
import subprocess
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from ib_audit.commands import (
    register_network_tool_process,
    run_command,
    terminate_network_tool_processes,
)
from ib_audit.network_scan import (
    DEFAULT_LOCAL_NMAP_PORTS,
    DEFAULT_LOCAL_NMAP_TARGETS,
    NetworkScanConfig,
    local_machine_nmap_targets,
)


class LocalNmapProfileTests(unittest.TestCase):
    def test_default_profile_is_fast_and_local(self) -> None:
        config = NetworkScanConfig()

        self.assertEqual(DEFAULT_LOCAL_NMAP_TARGETS, config.targets)
        self.assertEqual(DEFAULT_LOCAL_NMAP_PORTS, config.ports)
        self.assertEqual(120, config.nmap_timeout)
        self.assertEqual("T3", config.nmap_timing)

    def test_local_targets_contain_hosts_but_never_network_ranges(self) -> None:
        fake_addresses = [
            (2, 1, 6, "", ("192.168.50.12", 0)),
            (2, 1, 6, "", ("192.168.50.12", 0)),
        ]
        with patch("ib_audit.network_scan.socket.gethostname", return_value="audit-laptop"), patch(
            "ib_audit.network_scan.socket.getaddrinfo", return_value=fake_addresses
        ):
            targets = local_machine_nmap_targets()

        self.assertEqual(("127.0.0.1", "192.168.50.12"), targets)
        self.assertTrue(all("/" not in target for target in targets))


class NetworkToolLifecycleTests(unittest.TestCase):
    def tearDown(self) -> None:
        terminate_network_tool_processes()

    def test_shutdown_terminates_each_registered_process_once(self) -> None:
        process = Mock(pid=4242)
        register_network_tool_process(process, ["tshark.exe", "-i", "1"])

        with patch("ib_audit.commands._terminate_process_tree") as terminate:
            terminate_network_tool_processes()
            terminate_network_tool_processes()

        terminate.assert_called_once_with(process)

    def test_nmap_run_is_tracked_and_unregistered_after_completion(self) -> None:
        process = Mock(pid=4243, returncode=0)
        process.communicate.return_value = (b"nmap-ok", b"")
        with patch("ib_audit.commands.hidden_subprocess_kwargs", return_value={}), patch(
            "ib_audit.commands.subprocess.Popen", return_value=process
        ) as popen:
            result = run_command(["nmap.exe", "-V"], timeout=15)

        self.assertEqual(0, result.returncode)
        self.assertEqual("nmap-ok", result.stdout)
        popen.assert_called_once_with(
            ["nmap.exe", "-V"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL,
            shell=False,
        )
        with patch("ib_audit.commands._terminate_process_tree") as terminate:
            terminate_network_tool_processes()
        terminate.assert_not_called()


if __name__ == "__main__":
    unittest.main()
