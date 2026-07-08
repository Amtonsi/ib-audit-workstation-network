import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.abspath("src"))

from ib_audit.commands import CommandResult
from ib_audit.network_scan import (
    NETWORK_COMMAND_OPTIONS,
    NetworkScanConfig,
    collect_network_capture,
    collect_network_services,
    _parse_nmap_xml,
    _parse_tshark_csv,
    build_nmap_command,
    build_tshark_command,
)


class NetworkScanParserTests(unittest.TestCase):
    def test_nmap_command_builder_respects_enabled_options(self):
        config = NetworkScanConfig(
            enabled=True,
            ports="80,443",
            extra_args="--min-rate 50",
            nmap_no_dns=False,
            nmap_skip_host_discovery=False,
            nmap_open_only=False,
            nmap_timing="T4",
            nmap_os_detection=False,
            nmap_service_detection=True,
        )

        command = build_nmap_command(config, ["192.168.56.0/24"])

        self.assertEqual("nmap", command[0])
        self.assertNotIn("-n", command)
        self.assertNotIn("-Pn", command)
        self.assertNotIn("-open", command)
        self.assertNotIn("-O", command)
        self.assertIn("-T4", command)
        self.assertIn("-sV", command)
        self.assertIn("--min-rate", command)
        self.assertIn("50", command)
        self.assertEqual("192.168.56.0/24", command[-1])

    def test_tshark_command_builder_respects_capture_options(self):
        config = NetworkScanConfig(
            enabled=True,
            capture_enabled=True,
            capture_duration=15,
            capture_filter="tcp port 443",
            capture_no_name_resolution=False,
            capture_quiet=False,
        )

        command = build_tshark_command(config, "3")

        self.assertEqual("tshark", command[0])
        self.assertNotIn("-n", command)
        self.assertNotIn("-q", command)
        self.assertIn("duration:15", command)
        self.assertIn("-f", command)
        self.assertIn("tcp port 443", command)
        self.assertIn("ip.src", command)
        self.assertIn("frame.len", command)

    def test_network_command_options_have_russian_tooltips(self):
        option_ids = {item.id for item in NETWORK_COMMAND_OPTIONS}

        self.assertIn("nmap_service_detection", option_ids)
        self.assertIn("nmap_os_detection", option_ids)
        self.assertIn("capture_no_name_resolution", option_ids)
        for item in NETWORK_COMMAND_OPTIONS:
            self.assertTrue(item.label)
            self.assertTrue(item.description_ru)
            self.assertTrue(item.command_preview)

    def test_nmap_parser_keeps_only_open_services_with_product_context(self):
        xml = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="192.168.56.10" addrtype="ipv4"/>
    <hostnames><hostname name="node-a"/></hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.4"><cpe>cpe:/a:openbsd:openssh:8.4</cpe></service>
      </port>
      <port protocol="tcp" portid="23">
        <state state="closed"/>
        <service name="telnet"/>
      </port>
    </ports>
  </host>
</nmaprun>"""

        services = _parse_nmap_xml(xml)

        self.assertEqual(1, len(services))
        service = services[0]
        self.assertEqual("network_service", service.object_type)
        self.assertEqual("192.168.56.10", service.fields["Host IP"])
        self.assertEqual("22", service.fields["Port"])
        self.assertEqual("TCP", service.fields["Protocol"])
        self.assertEqual("OpenSSH", service.fields["Service Product"])
        self.assertEqual("8.4", service.fields["Service Version"])
        self.assertIn("openbsd:openssh:8.4", service.fields["Service CPE"])

    def test_tshark_parser_aggregates_flows_and_marks_direction(self):
        csv_text = "\n".join(
            [
                '"frame.time_epoch","ip.src","ip.dst","tcp.srcport","tcp.dstport","udp.srcport","udp.dstport","_ws.col.Protocol","frame.len"',
                '"10.1","192.168.1.10","8.8.8.8","51515","443","","","TLS","120"',
                '"10.2","192.168.1.10","8.8.8.8","51515","443","","","TLS","80"',
                '"10.3","8.8.8.8","192.168.1.10","443","51515","","","TLS","60"',
            ]
        )

        flows = _parse_tshark_csv(csv_text)

        self.assertEqual(2, len(flows))
        outbound = flows[0]
        self.assertEqual("192.168.1.10", outbound["Source"])
        self.assertEqual("8.8.8.8", outbound["Destination"])
        self.assertEqual(2, outbound["Packets"])
        self.assertEqual(200, outbound["Bytes"])
        self.assertEqual("outbound", outbound["Direction"])
        self.assertEqual("external", outbound["Destination Scope"])

    def test_nmap_falls_back_without_os_detection_when_npcap_missing(self):
        config = NetworkScanConfig(
            enabled=True,
            targets=("192.168.56.10",),
            nmap_os_detection=True,
            nmap_timeout=1,
        )
        xml = """<?xml version="1.0"?>
<nmaprun><host><status state="up"/><address addr="192.168.56.10" addrtype="ipv4"/><hostnames></hostnames><ports>
<port protocol="tcp" portid="80"><state state="open"/><service name="http" product="Apache" version="2.4"/></port>
</ports></host></nmaprun>"""

        first = CommandResult(["nmap"], 1, "", "TCP/IP fingerprinting (for OS scan) requires Npcap, but it seems to be missing.")
        second = CommandResult(["nmap"], 0, xml, "")

        with patch("ib_audit.network_scan.resolve_tool_command", return_value="nmap"), \
                patch("ib_audit.network_scan.command_exists", return_value=True), \
                patch("ib_audit.network_scan.run_command", side_effect=[first, second]):
            services, diagnostics = collect_network_services(config)

        self.assertEqual(1, len(services))
        self.assertEqual("192.168.56.10", services[0].fields["Host IP"])
        self.assertTrue(any("OS detection" in item.message for item in diagnostics))

    def test_tshark_discovery_failure_is_reported_with_detail(self):
        config = NetworkScanConfig(
            enabled=True,
            targets=("192.168.56.0/24",),
            capture_enabled=True,
        )
        tshark_fail = CommandResult(["tshark", "-D"], 1, "", "access denied while opening capture device")

        with patch("ib_audit.network_scan.resolve_tool_command", return_value="tshark"), \
                patch("ib_audit.network_scan.command_exists", return_value=True), \
                patch("ib_audit.network_scan.run_command", return_value=tshark_fail):
            captures, diagnostics = collect_network_capture(config)

        self.assertEqual([], captures)
        self.assertEqual(1, len(diagnostics))
        self.assertIn("tshark -D failed", diagnostics[0].message)


if __name__ == "__main__":
    unittest.main()
