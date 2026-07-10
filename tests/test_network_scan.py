import os
import json
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.abspath("src"))

from ib_audit.commands import CommandResult
from ib_audit.network_scan import (
    NETWORK_COMMAND_OPTIONS,
    NetworkScanConfig,
    NetworkScanService,
    collect_network_capture,
    collect_network_intelligence,
    collect_network_services,
    _detect_tshark_interfaces,
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
        self.assertIn("-sT", command)
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

    def test_tshark_parser_extracts_application_protocol_details(self):
        csv_text = "\n".join(
            [
                '"frame.time_epoch","ip.src","ip.dst","tcp.srcport","tcp.dstport","udp.srcport","udp.dstport","_ws.col.Protocol","frame.len","frame.protocols","_ws.col.Info","dns.qry.name","http.host","http.request.method","http.request.uri","tls.handshake.extensions_server_name","tcp.flags","tcp.analysis.retransmission","ip.ttl"',
                '"10.1","192.168.1.10","93.184.216.34","51515","443","","","TLS","120","eth:ethertype:ip:tcp:tls","Client Hello","", "", "", "", "example.com","0x0002","","64"',
                '"10.2","192.168.1.10","1.1.1.1","","","5353","53","DNS","80","eth:ethertype:ip:udp:dns","Standard query","internal.local","","","","","","128"',
                '"10.3","192.168.1.10","93.184.216.34","51516","80","","","HTTP","140","eth:ethertype:ip:tcp:http","GET /login","", "portal.local", "GET", "/login", "", "0x0018","1","63"',
            ]
        )

        flows = _parse_tshark_csv(csv_text)

        by_protocol = {flow["Protocol"]: flow for flow in flows}
        self.assertEqual("example.com", by_protocol["TLS"]["TLS SNI"])
        self.assertIn("SNI example.com", by_protocol["TLS"]["Protocol Details"])
        self.assertEqual("internal.local", by_protocol["DNS"]["DNS Query"])
        self.assertIn("DNS query internal.local", by_protocol["DNS"]["Protocol Details"])
        self.assertEqual("portal.local", by_protocol["HTTP"]["HTTP Host"])
        self.assertEqual("GET", by_protocol["HTTP"]["HTTP Method"])
        self.assertIn("HTTP GET portal.local/login", by_protocol["HTTP"]["Protocol Details"])
        self.assertEqual("yes", by_protocol["HTTP"]["TCP Retransmission"])
        self.assertEqual("63", by_protocol["HTTP"]["IP TTL"])

    def test_tshark_parser_adds_packet_samples_and_traffic_risk_color(self):
        csv_text = "\n".join(
            [
                '"frame.number","frame.time_epoch","ip.src","ip.dst","tcp.srcport","tcp.dstport","udp.srcport","udp.dstport","_ws.col.Protocol","frame.len","frame.protocols","_ws.col.Info","http.host","http.request.method","http.request.uri","tcp.analysis.retransmission","tcp.analysis.lost_segment","_ws.expert.severity","_ws.expert.message"',
                '"7","10.1","192.168.1.10","93.184.216.34","51516","80","","","HTTP","140","eth:ethertype:ip:tcp:http","GET /login","portal.local","GET","/login","1","","warn","Previous segment not captured"',
            ]
        )

        flows = _parse_tshark_csv(csv_text)

        self.assertEqual(1, len(flows))
        flow = flows[0]
        self.assertEqual("high", flow["Traffic Severity"])
        self.assertEqual("#ef4444", flow["Traffic Color"])
        self.assertIn("Clear-text HTTP", flow["Traffic Findings"])
        self.assertIn("TCP retransmission", flow["Traffic Findings"])
        self.assertIn("#7", flow["Packet Samples"])
        self.assertIn("HTTP", flow["Packet Samples"])
        self.assertIn("GET portal.local/login", flow["Packet Samples"])

    def test_tshark_parser_keeps_wireshark_packet_rows_for_ui_and_report(self):
        csv_text = "\n".join(
            [
                '"frame.number","frame.time_relative","ip.src","ip.dst","tcp.srcport","tcp.dstport","_ws.col.Protocol","frame.len","frame.protocols","_ws.col.Info","data.data"',
                '"7","10.125","192.168.1.10","93.184.216.34","51516","80","HTTP","140","eth:ethertype:ip:tcp:http","GET /login HTTP/1.1","0001020a0b0c"',
            ]
        )

        flows = _parse_tshark_csv(csv_text)

        self.assertEqual(1, len(flows))
        packet_rows = json.loads(flows[0]["Packet Rows JSON"])
        self.assertEqual(1, len(packet_rows))
        row = packet_rows[0]
        self.assertEqual("7", row["No."])
        self.assertEqual("10.125", row["Time"])
        self.assertEqual("192.168.1.10:51516", row["Source"])
        self.assertEqual("93.184.216.34:80", row["Destination"])
        self.assertEqual("HTTP", row["Protocol"])
        self.assertEqual("140", row["Length"])
        self.assertIn("GET /login", row["Info"])
        self.assertIn("00 01 02 0a 0b 0c", row["Bytes Hex"])

    def test_network_intelligence_reports_nmap_and_traffic_analysis_progress(self):
        config = NetworkScanConfig(enabled=True, capture_enabled=True)
        service = NetworkScanService(
            "network_service",
            "192.168.1.20 22/TCP ssh",
            {"Host IP": "192.168.1.20", "Port": "22", "Protocol": "TCP", "Service": "ssh"},
        )
        capture = NetworkScanService(
            "network_capture",
            "192.168.1.10:51516 -> 93.184.216.34:80 (HTTP)",
            {
                "Source": "192.168.1.10",
                "Destination": "93.184.216.34",
                "Source Port": "51516",
                "Destination Port": "80",
                "Protocol": "HTTP",
                "Packets": "1",
                "Bytes": "140",
                "Traffic Severity": "high",
                "Traffic Findings": "Clear-text HTTP request to portal.local/login",
                "Interface": "5",
            },
        )
        events: list[str] = []

        with patch("ib_audit.network_scan.collect_network_services", return_value=([service], [])), \
                patch("ib_audit.network_scan.collect_network_capture", return_value=([capture], [])):
            services, captures, diagnostics = collect_network_intelligence(config, progress=events.append)

        self.assertEqual([service], services)
        self.assertEqual([capture], captures)
        self.assertTrue(any("Nmap phase enabled" in item for item in events))
        self.assertTrue(any("Traffic analysis phase enabled" in item for item in events))
        self.assertTrue(any(item.startswith("TRAFFIC_RISK|high|") for item in events))
        self.assertTrue(any("Critical service found" in item.message for item in diagnostics))

    def test_network_intelligence_runs_capture_before_nmap_for_visible_monitoring(self):
        config = NetworkScanConfig(enabled=True, nmap_enabled=True, capture_enabled=True, capture_interfaces=("5",))
        call_order: list[str] = []

        def fake_capture(_config, progress=None):
            call_order.append("capture")
            if progress:
                progress("CAPTURE_ACTIVE|info|Захват трафика выполняется: интерфейсы=5")
            return [], []

        def fake_services(_config, progress=None):
            call_order.append("nmap")
            if progress:
                progress("Nmap scan started on 1 target(s)")
            return [], []

        with patch("ib_audit.network_scan.collect_network_capture", side_effect=fake_capture), \
                patch("ib_audit.network_scan.collect_network_services", side_effect=fake_services):
            collect_network_intelligence(config, progress=lambda _event: None)

        self.assertEqual(["capture", "nmap"], call_order)

    def test_capture_only_network_intelligence_skips_nmap_and_runs_traffic(self):
        config = NetworkScanConfig(enabled=True, nmap_enabled=False, capture_enabled=True, capture_interfaces=("5",))
        capture = NetworkScanService(
            "network_capture",
            "192.168.1.10:51516 -> 93.184.216.34:80 (TCP)",
            {
                "Source": "192.168.1.10",
                "Destination": "93.184.216.34",
                "Source Port": "51516",
                "Destination Port": "80",
                "Protocol": "TCP",
                "Packets": "1",
                "Bytes": "0",
                "Traffic Severity": "info",
                "Traffic Findings": "Safe connection metadata observed",
            },
        )
        events: list[str] = []

        with patch("ib_audit.network_scan.collect_network_services") as services, \
                patch("ib_audit.network_scan.collect_network_capture", return_value=([capture], [])):
            services.side_effect = AssertionError("Nmap must not run in capture-only mode")
            services_result, captures, diagnostics = collect_network_intelligence(config, progress=events.append)

        self.assertEqual([], services_result)
        self.assertEqual([capture], captures)
        self.assertTrue(any("Nmap phase skipped" in item for item in events))
        self.assertTrue(any("Traffic analysis phase enabled" in item for item in events))
        self.assertFalse(any("Critical service found" in item.message for item in diagnostics))

    def test_nmap_safe_command_disables_raw_os_detection(self):
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

        with patch("ib_audit.network_scan.resolve_tool_command", return_value="nmap"),                 patch("ib_audit.network_scan.command_exists", return_value=True),                 patch("ib_audit.network_scan.run_command", return_value=CommandResult(["nmap"], 0, xml, "")) as run_command:
            services, diagnostics = collect_network_services(config)

        self.assertEqual(1, len(services))
        self.assertEqual("192.168.56.10", services[0].fields["Host IP"])
        command = run_command.call_args.args[0]
        self.assertIn("-sT", command)
        self.assertNotIn("-O", command)
        self.assertTrue(any("OS detection is disabled in safe mode" in item.message for item in diagnostics))

    def test_capture_falls_back_to_safe_telemetry_when_tshark_returns_no_packets(self):
        config = NetworkScanConfig(
            enabled=True,
            targets=("192.168.56.0/24",),
            capture_enabled=True,
            capture_interfaces=("5",),
        )

        with patch("ib_audit.network_scan._collect_tshark_live_traffic", return_value=([], [])), \
                patch("ib_audit.network_scan.run_powershell_json", return_value=([], CommandResult(["pwsh"], 0, "", ""))), \
                patch("ib_audit.network_scan.run_command") as run_command:
            captures, diagnostics = collect_network_capture(config)

        self.assertEqual([], captures)
        self.assertEqual(1, len(diagnostics))
        self.assertIn("Safe Windows traffic telemetry", diagnostics[0].message)
        run_command.assert_not_called()

    def test_capture_prefers_tshark_live_packet_capture_when_available(self):
        config = NetworkScanConfig(
            enabled=True,
            nmap_enabled=False,
            capture_enabled=True,
            capture_interfaces=("5",),
        )
        tshark_flow = {
            "Source": "192.168.1.10",
            "Destination": "93.184.216.34",
            "Protocol": "HTTP",
            "Source Port": "51516",
            "Destination Port": "80",
            "Frame Protocols": "eth:ip:tcp:http",
            "Packet Info": "GET /",
            "Protocol Details": "HTTP GET /",
            "Traffic Severity": "high",
            "Traffic Color": "#ef4444",
            "Traffic Findings": "Clear-text HTTP request observed",
            "Packet Samples": "#1 t=0.1 HTTP 192.168.1.10:51516 -> 93.184.216.34:80 len=120 info=HTTP GET /",
            "Packet Sample Count": "1",
            "Packets": "1",
            "Bytes": "120",
            "LastSeen": "0.1",
            "Interface": "5",
            "Capture Mode": "tshark-live-capture",
            "Traffic Evidence Type": "Live tshark packet capture",
        }

        with patch("ib_audit.network_scan._collect_tshark_live_traffic", return_value=([tshark_flow], [])), \
                patch("ib_audit.network_scan._collect_safe_network_traffic") as safe_capture:
            captures, diagnostics = collect_network_capture(config)

        self.assertEqual(1, len(captures))
        self.assertEqual("tshark-live-capture", captures[0].fields["Capture Mode"])
        self.assertIn("#1", captures[0].fields["Packet Samples"])
        self.assertEqual([], diagnostics)
        safe_capture.assert_not_called()

    def test_safe_capture_emits_visible_capture_active_progress(self):
        config = NetworkScanConfig(
            enabled=True,
            nmap_enabled=False,
            capture_enabled=True,
            capture_interfaces=("5",),
        )
        events: list[str] = []

        def fake_tshark(_config, _interfaces, progress=None):
            if progress:
                progress("CAPTURE_ACTIVE|info|Захват пакетов tshark выполняется: интерфейсы=5")
            return [], []

        with patch("ib_audit.network_scan._collect_tshark_live_traffic", side_effect=fake_tshark), \
                patch("ib_audit.network_scan.run_powershell_json", return_value=([], CommandResult(["pwsh"], 0, "", ""))), \
                patch("ib_audit.network_scan.run_command"):
            collect_network_capture(config, progress=events.append)

        self.assertTrue(any(event.startswith("CAPTURE_ACTIVE|info|") for event in events))

    def test_safe_capture_reports_selected_interface_counters_when_tcp_snapshot_is_empty(self):
        config = NetworkScanConfig(
            enabled=True,
            nmap_enabled=False,
            capture_enabled=True,
            capture_interfaces=("5",),
        )
        tcp_result = CommandResult(["powershell"], 0, "[]", "")
        stats_result = CommandResult(["powershell"], 0, "[]", "")
        adapter_stats = [
            {
                "Name": "Wireless network",
                "InterfaceDescription": "Wireless Adapter",
                "ifIndex": 5,
                "Status": "Up",
                "LinkSpeed": "156 Mbps",
                "ReceivedBytes": 750489724,
                "SentBytes": 745766,
            }
        ]

        with patch("ib_audit.network_scan._collect_tshark_live_traffic", return_value=([], [])), \
                patch(
                    "ib_audit.network_scan.run_powershell_json",
                    side_effect=[([], tcp_result), (adapter_stats, stats_result)],
                ), patch("ib_audit.network_scan.run_command") as run_command:
            captures, diagnostics = collect_network_capture(config)

        self.assertEqual(1, len(captures))
        fields = captures[0].fields
        self.assertEqual("safe-windows-interface-counters", fields["Capture Mode"])
        self.assertEqual("INTERFACE", fields["Protocol"])
        self.assertIn("Wireless network", fields["Interface"])
        self.assertIn("750489724", fields["Packet Samples"])
        self.assertTrue(any("adapter counter" in item.message for item in diagnostics))
        run_command.assert_not_called()

    def test_capture_requires_explicit_interface_selection(self):
        config = NetworkScanConfig(
            enabled=True,
            targets=("192.168.56.0/24",),
            capture_enabled=True,
        )

        with patch("ib_audit.network_scan.resolve_tool_command", return_value="tshark"), \
                patch("ib_audit.network_scan.command_exists", return_value=True), \
                patch(
                    "ib_audit.network_scan._detect_tshark_interfaces",
                    return_value=([{"index": "1", "name": "1", "description": "Ethernet"}], None),
                ), \
                patch("ib_audit.network_scan.run_command") as run_command:
            captures, diagnostics = collect_network_capture(config)

        self.assertEqual([], captures)
        run_command.assert_not_called()
        self.assertEqual(1, len(diagnostics))
        self.assertIn("Select at least one capture interface", diagnostics[0].message)

    def test_tshark_interface_detection_marks_active_and_risky_interfaces(self):
        tshark_output = "\n".join(
            [
                "1. \\Device\\NPF_{WIFI} (Беспроводная сеть)",
                "2. \\Device\\NPF_{VMNET8} (VMware Network Adapter VMnet8)",
                "3. \\Device\\NPF_Loopback (Adapter for loopback traffic capture)",
                "4. ciscodump (Cisco remote capture)",
            ]
        )
        adapters = [
            {"Name": "Беспроводная сеть", "InterfaceDescription": "Intel Wi-Fi", "Status": "Up", "LinkSpeed": "866 Mbps"},
            {"Name": "VMware Network Adapter VMnet8", "InterfaceDescription": "VMware Virtual Ethernet Adapter", "Status": "Up", "LinkSpeed": "100 Mbps"},
        ]

        with patch("ib_audit.network_scan.run_command", return_value=CommandResult(["tshark", "-D"], 0, tshark_output, "")), \
                patch("ib_audit.network_scan.run_powershell_json", return_value=(adapters, CommandResult(["pwsh"], 0, "", ""))):
            interfaces, error = _detect_tshark_interfaces("tshark")

        self.assertIsNone(error)
        self.assertEqual("yes", interfaces[0]["active"])
        self.assertEqual("physical", interfaces[0]["kind"])
        self.assertEqual("Беспроводная сеть", interfaces[0]["friendly_name"])
        self.assertEqual("virtual", interfaces[1]["kind"])
        self.assertEqual("loopback", interfaces[2]["kind"])
        self.assertEqual("extcap", interfaces[3]["kind"])
        self.assertEqual("no", interfaces[3]["active"])

    def test_network_only_runs_network_intelligence_before_local_resources(self):
        from ib_audit.collectors import get_collectors

        collectors = get_collectors(NetworkScanConfig(enabled=True), only_network=True)

        self.assertEqual("network_intelligence", collectors[0].name)

    def test_network_only_collector_adapts_network_intelligence_to_inventory_pair(self):
        from ib_audit.collectors import get_collectors
        from ib_audit.models import CollectorDiagnostic

        config = NetworkScanConfig(enabled=True, nmap_enabled=False, capture_enabled=True, capture_interfaces=("5",))
        service = NetworkScanService(
            "network_service",
            "192.168.1.20 22/TCP ssh",
            {"Host IP": "192.168.1.20", "Port": "22", "Protocol": "TCP", "Service": "ssh"},
        )
        capture = NetworkScanService(
            "network_capture",
            "192.168.1.10:51516 -> 93.184.216.34:80 (HTTP)",
            {
                "Source": "192.168.1.10",
                "Destination": "93.184.216.34",
                "Source Port": "51516",
                "Destination Port": "80",
                "Protocol": "HTTP",
                "Packets": "1",
            },
        )
        diagnostic = CollectorDiagnostic("network_intelligence", "info", "sample", "test")

        with patch(
            "ib_audit.collectors.collect_network_intelligence_data",
            return_value=([service], [capture], [diagnostic]),
        ):
            collectors = get_collectors(config, only_network=True)
            objects, diagnostics = collectors[0].func(lambda _event: None)

        self.assertEqual([diagnostic], diagnostics)
        self.assertEqual(["network_service", "network_capture"], [obj.object_type for obj in objects])


if __name__ == "__main__":
    unittest.main()
