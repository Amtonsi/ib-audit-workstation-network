import argparse
import os
import sys
from pathlib import Path

ROOT = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(ROOT, "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)

from ib_audit.app import run_audit
from ib_audit.network_scan import NetworkScanConfig


def main() -> int:
    parser = argparse.ArgumentParser(description="Run local IB audit and generate HTML report.")
    parser.add_argument("--db", default=None, help="Optional SQLite audit DB path. Defaults to a temporary DB.")
    parser.add_argument("--output", default=None, help="Report output directory. Defaults to outputs/")
    parser.add_argument("--enrich", action="store_true", help="Try internet vulnerability enrichment.")
    parser.add_argument("--offline", action="store_true", help="Use cached vulnerability data and local rules only.")
    parser.add_argument(
        "--vulnerability-mode",
        choices=("full", "fast"),
        default="full",
        help="full = online NVD/CISA plus live FSTEC; fast = cached NVD/CISA without live FSTEC.",
    )
    parser.add_argument("--network-scan", action="store_true", help="Run full network nmap scan.")
    parser.add_argument(
        "--network-capture",
        action="store_true",
        help="Capture network traffic with tshark during the scan.",
    )
    parser.add_argument(
        "--network-targets",
        default="",
        help="Comma or semicolon separated scan targets (CIDR/hostname). If empty, use local routes.",
    )
    parser.add_argument(
        "--network-ports",
        default="1-65535",
        help="Port list/range for nmap (default: 1-65535).",
    )
    parser.add_argument(
        "--network-extra-args",
        default="",
        help="Additional arguments passed to nmap (quoted once for spaces).",
    )
    parser.add_argument(
        "--network-scan-timeout",
        type=int,
        default=600,
        help="nmap timeout in seconds.",
    )
    parser.add_argument(
        "--no-nmap-os-detection",
        action="store_true",
        help="Disable nmap OS detection (-O).",
    )
    parser.add_argument(
        "--no-nmap-service-detection",
        action="store_true",
        help="Disable nmap service/version detection (-sV).",
    )
    parser.add_argument(
        "--network-capture-interface",
        default="",
        help="tshark interface index/name. If empty, use first detected interface.",
    )
    parser.add_argument(
        "--network-capture-duration",
        type=int,
        default=20,
        help="tshark capture duration in seconds.",
    )
    parser.add_argument(
        "--network-capture-timeout",
        type=int,
        default=130,
        help="Command timeout for tshark in seconds.",
    )
    parser.add_argument(
        "--network-capture-filter",
        default="",
        help="Optional capture filter for tshark (raw tcpdump syntax).",
    )
    parser.add_argument("--no-open", action="store_true", help="Do not open the generated report.")
    args = parser.parse_args()
    enabled_network_scan = bool(args.network_scan or args.network_capture)
    raw_targets = [item.strip() for item in args.network_targets.replace(";", ",").split(",") if item.strip()]
    network_scan_config = NetworkScanConfig(
        enabled=enabled_network_scan,
        targets=tuple(raw_targets),
        ports=args.network_ports,
        extra_args=args.network_extra_args,
        nmap_timeout=args.network_scan_timeout,
        nmap_os_detection=not args.no_nmap_os_detection,
        nmap_service_detection=not args.no_nmap_service_detection,
        capture_enabled=args.network_capture,
        capture_interface=(args.network_capture_interface or None),
        capture_duration=args.network_capture_duration,
        capture_timeout=args.network_capture_timeout,
        capture_filter=args.network_capture_filter,
    )

    result = run_audit(
        db_path=args.db,
        output_dir=args.output,
        enrich=args.enrich,
        online_sources=not args.offline,
        vulnerability_mode=args.vulnerability_mode,
        network_scan=network_scan_config,
        open_report=not args.no_open,
        progress=lambda message: print(message, flush=True),
    )
    print(f"DB: {result['db_path']}")
    print(f"Report: {result['report_path']}")
    print(f"Inventory objects: {result['inventory_count']}")
    print(f"Diagnostics: {result['diagnostic_count']}")
    print(f"Vulnerabilities: {result['vulnerability_count']}")
    print(f"Risks: {result['risk_count']}")
    print(f"Document coverage: {result['coverage_percent']}%")
    print(f"Rule-checked depth: {result.get('rule_checked_percent', result['coverage_percent'])}%")
    print(f"Insufficient data: {result['insufficient_count']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
