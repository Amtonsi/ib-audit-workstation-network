import argparse
import os
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(ROOT, "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)

from ib_audit.app import run_audit


def main() -> int:
    parser = argparse.ArgumentParser(description="Run local IB audit and generate HTML report.")
    parser.add_argument("--db", default=None, help="SQLite DB path. Defaults to outputs/ib_audit.db")
    parser.add_argument("--output", default=None, help="Report output directory. Defaults to outputs/")
    parser.add_argument("--enrich", action="store_true", help="Try internet vulnerability enrichment.")
    parser.add_argument("--offline", action="store_true", help="Use cached vulnerability data and local rules only.")
    parser.add_argument(
        "--vulnerability-mode",
        choices=("full", "fast"),
        default="full",
        help="full = online NVD/CISA plus live FSTEC; fast = cached NVD/CISA without live FSTEC.",
    )
    parser.add_argument("--no-open", action="store_true", help="Do not open the generated report.")
    args = parser.parse_args()

    result = run_audit(
        db_path=args.db,
        output_dir=args.output,
        enrich=args.enrich,
        online_sources=not args.offline,
        vulnerability_mode=args.vulnerability_mode,
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
