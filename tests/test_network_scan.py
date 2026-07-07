import os
import sys
import unittest

sys.path.insert(0, os.path.abspath("src"))

from ib_audit.network_scan import _parse_nmap_xml, _parse_tshark_csv


class NetworkScanParserTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
