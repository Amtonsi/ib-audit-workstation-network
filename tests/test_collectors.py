import os
import sys
import unittest
from datetime import date
from unittest.mock import patch

sys.path.insert(0, os.path.abspath("src"))

from ib_audit.commands import CommandResult
from ib_audit.collectors import (
    annotate_user_password_age,
    collect_events_environment,
    collect_network_resources,
    collect_software_execution,
    parse_ipconfig_all,
    parse_csv_table,
    parse_net_user_detail,
    parse_netstat_ano,
    parse_reg_query_values,
    parse_route_print,
    parse_wmic_list,
    safe_title,
)
from ib_audit.models import InventoryObject


class CollectorParserTests(unittest.TestCase):
    def test_parse_wmic_list_groups_key_value_blocks(self):
        text = "Name=Windows 11 Pro\r\nVersion=10.0.22631\r\n\r\nName=Other\r\nVersion=1\r\n"
        self.assertEqual(
            parse_wmic_list(text),
            [{"Name": "Windows 11 Pro", "Version": "10.0.22631"}, {"Name": "Other", "Version": "1"}],
        )

    def test_parse_wmic_list_keeps_single_blank_lines_inside_record(self):
        text = "\r\n\r\nName=Service A\r\n\r\nDisplayName=Service A\r\n\r\nState=Running\r\n\r\n\r\nName=Service B\r\n\r\nDisplayName=Service B\r\n\r\nState=Stopped\r\n"
        self.assertEqual(
            parse_wmic_list(text),
            [
                {"Name": "Service A", "DisplayName": "Service A", "State": "Running"},
                {"Name": "Service B", "DisplayName": "Service B", "State": "Stopped"},
            ],
        )

    def test_parse_net_user_detail_extracts_logon_and_password_dates(self):
        text = """
User name                    alice
Full Name                    Alice Example
Account active               Yes
Last logon                   6/26/2026 10:01:00 AM
Password last set            6/20/2026 9:00:00 AM
Local Group Memberships      *Users *Remote Desktop Users
"""
        parsed = parse_net_user_detail(text)
        self.assertEqual(parsed["User name"], "alice")
        self.assertEqual(parsed["Last logon"], "6/26/2026 10:01:00 AM")
        self.assertEqual(parsed["Password last set"], "6/20/2026 9:00:00 AM")

    def test_annotate_user_password_age_from_net_user_date(self):
        fields = {"Password last set": "4/30/2026 9:00:00 AM"}

        annotate_user_password_age(fields, today=date(2026, 6, 30))

        self.assertEqual(61, fields["PasswordAgeDays"])
        self.assertEqual("4/30/2026 9:00:00 AM", fields["PasswordLastSetSource"])

    def test_parse_ipconfig_all_extracts_adapter_fields(self):
        text = """
Ethernet adapter Ethernet:
   Description . . . . . . . . . . . : Intel(R) Ethernet
   Physical Address. . . . . . . . . : AA-BB-CC-DD-EE-FF
   IPv4 Address. . . . . . . . . . . : 192.168.1.10(Preferred)
   Default Gateway . . . . . . . . . : 192.168.1.1
   DNS Servers . . . . . . . . . . . : 1.1.1.1
                                       8.8.8.8
"""
        adapters = parse_ipconfig_all(text)
        self.assertEqual(adapters[0]["Adapter"], "Ethernet")
        self.assertEqual(adapters[0]["IPv4 Address"], "192.168.1.10")
        self.assertIn("8.8.8.8", adapters[0]["DNS Servers"])

    def test_parse_reg_query_values_extracts_key_value_rows(self):
        text = r"""
HKEY_LOCAL_MACHINE\Software\Example
    Enabled    REG_DWORD    0x1
    Path       REG_SZ       C:\Program Files\Example
"""
        rows = parse_reg_query_values(text)
        self.assertEqual(rows[0]["Subkey"], r"Software\Example\Enabled")
        self.assertEqual(rows[0]["Setting"], "1")
        self.assertEqual(rows[1]["Setting"], r"C:\Program Files\Example")

    def test_parse_route_print_extracts_ipv4_routes(self):
        text = """
IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0       10.0.40.1     10.0.40.84     45
        127.0.0.0        255.0.0.0         On-link       127.0.0.1    331
===========================================================================
"""
        routes = parse_route_print(text)
        self.assertEqual(routes[0]["Destination"], "0.0.0.0")
        self.assertEqual(routes[0]["Next Hop"], "10.0.40.1")
        self.assertEqual(routes[1]["Interface"], "127.0.0.1")

    def test_parse_netstat_ano_enriches_process_names_and_caps(self):
        text = """
  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       1624
  UDP    0.0.0.0:5353           *:*                                    444
"""
        rows, capped = parse_netstat_ano(text, {"1624": "RpcSs", "444": "mDNSResponder"}, limit=1)
        self.assertTrue(capped)
        self.assertEqual(rows[0]["Service Name"], "RpcSs")
        self.assertEqual(rows[0]["Connection State"], "Listening")

    def test_parse_csv_table_handles_powershell_export(self):
        text = '"Name","State"\r\n"Task A","Ready"\r\n"Task B","Disabled"\r\n'
        self.assertEqual(parse_csv_table(text)[1]["State"], "Disabled")

    def test_safe_title_prefers_human_fields(self):
        obj = InventoryObject(
            category_id="m",
            category_name="Memory",
            object_type="memory",
            title="",
            fields={"DeviceLocator": "DIMM_A1", "PartNumber": "ABC"},
            source="fixture",
        )
        self.assertEqual(safe_title(obj, ["Name", "DeviceLocator", "PartNumber"]), "DIMM_A1")

    def test_network_tcpip_uses_cim_fallback_when_ipconfig_has_no_adapters(self):
        def fake_run_command(command, timeout=20):
            if command == ["ipconfig", "/all"]:
                return CommandResult(command, 0, "Windows IP Configuration\r\n", "")
            return CommandResult(command, 0, "", "")

        def fake_run_powershell_json(script, timeout=30):
            result = CommandResult(["powershell"], 0, "[]", "")
            if "Win32_NetworkAdapterConfiguration" in script:
                return [
                    {
                        "Description": "Intel(R) Ethernet",
                        "MACAddress": "AA-BB-CC-DD-EE-FF",
                        "DHCPEnabled": True,
                        "IPAddress": ["192.168.1.10", "fe80::1"],
                        "IPSubnet": ["255.255.255.0"],
                        "DefaultIPGateway": ["192.168.1.1"],
                        "DNSServerSearchOrder": ["1.1.1.1", "8.8.8.8"],
                    }
                ], result
            return [], result

        with patch("ib_audit.collectors.run_command", side_effect=fake_run_command), patch(
            "ib_audit.collectors.run_powershell_json", side_effect=fake_run_powershell_json
        ):
            objects, diagnostics = collect_network_resources()

        adapters = [obj for obj in objects if obj.category_name == "Network TCP/IP"]
        self.assertEqual(1, len(adapters), diagnostics)
        self.assertEqual("PowerShell CIM", adapters[0].source)
        self.assertEqual("192.168.1.10, fe80::1", adapters[0].fields["IP Addresses"])
        self.assertEqual("1.1.1.1, 8.8.8.8", adapters[0].fields["DNS Servers"])

    def test_event_logs_are_structured_get_winevent_objects(self):
        commands: list[list[str]] = []

        def fake_run_command(command, timeout=20):
            commands.append(command)
            return CommandResult(command, 1, "", "not available")

        def fake_run_powershell_json(script, timeout=30):
            result = CommandResult(["powershell"], 0, "[]", "")
            if "Get-WinEvent" in script:
                self.assertIn("ToString('o')", script)
                return [
                    {
                        "LogName": "System",
                        "ProviderName": "Service Control Manager",
                        "TimeCreated": "2026-06-29T15:00:00Z",
                        "Id": 7036,
                        "LevelDisplayName": "Information",
                        "Message": "Service entered the running state.",
                    }
                ], result
            return [], result

        with patch("ib_audit.collectors.run_command", side_effect=fake_run_command), patch(
            "ib_audit.collectors.run_powershell_json", side_effect=fake_run_powershell_json
        ):
            objects, diagnostics = collect_events_environment()

        events = [obj for obj in objects if obj.object_type == "event_log_event"]
        self.assertEqual(3, len(events), diagnostics)
        self.assertIn("ProviderName", events[0].fields)
        self.assertIn("Message", events[0].fields)
        self.assertNotIn("Events", events[0].fields)
        self.assertFalse(any(command and command[0] == "wevtutil" for command in commands))

    def test_software_execution_collects_task_actions_and_signed_driver_status(self):
        def fake_objects_from_wmic(*args, **kwargs):
            return [], []

        def fake_run_powershell_json(script, timeout=30):
            result = CommandResult(["powershell"], 0, "[]", "")
            if "Microsoft.Update.Session" in script or "Win32_StartupCommand" in script:
                return [], result
            if "Get-ScheduledTask" in script:
                self.assertIn("Actions", script)
                return [
                    {
                        "TaskName": f"Task {index}",
                        "TaskPath": "\\",
                        "State": "Ready",
                        "Execute": r"C:\Windows\System32\notepad.exe",
                        "Arguments": "",
                    }
                    for index in range(305)
                ], result
            if "Win32_PnPSignedDriver" in script:
                return [
                    {
                        "DeviceName": f"Example Driver {index}",
                        "DriverProviderName": "Example",
                        "DriverVersion": "1.2.3",
                        "IsSigned": True,
                        "Signer": "Microsoft Windows",
                    }
                    for index in range(605)
                ], result
            return [], result

        with patch("ib_audit.collectors._registry_software", return_value=([], [])), patch(
            "ib_audit.collectors._registry_active_setup", return_value=([], [])
        ), patch("ib_audit.collectors._objects_from_wmic", side_effect=fake_objects_from_wmic), patch(
            "ib_audit.collectors.run_powershell_json", side_effect=fake_run_powershell_json
        ):
            objects, diagnostics = collect_software_execution()

        task = next(obj for obj in objects if obj.object_type == "scheduled_task")
        driver = next(obj for obj in objects if obj.object_type == "driver")
        self.assertEqual(305, sum(1 for obj in objects if obj.object_type == "scheduled_task"))
        self.assertEqual(605, sum(1 for obj in objects if obj.object_type == "driver"))
        self.assertEqual(r"C:\Windows\System32\notepad.exe", task.fields["Execute"])
        self.assertIs(True, driver.fields["IsSigned"])
        self.assertEqual("PowerShell CIM", driver.source)


if __name__ == "__main__":
    unittest.main()
