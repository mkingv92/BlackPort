import argparse
from blackport.scanner import run_scan
from blackport.reporter import generate_report


def main():
    parser = argparse.ArgumentParser(
        prog="blackport",
        description="Offensive Exposure Intelligence Framework"
    )

    subparsers = parser.add_subparsers(dest="command")

    # ---- Scan Command ----
    scan_parser = subparsers.add_parser("scan", help="Scan a target host")
    scan_parser.add_argument("target", help="Target IP address")
    scan_parser.add_argument(
        "--profile",
        choices=["fast", "full"],
        default="fast",
        help="Scan profile type"
    )

    # ---- Report Command ----
    report_parser = subparsers.add_parser("report", help="Generate report from scan file")
    report_parser.add_argument("--input", required=True, help="Input JSON file")
    report_parser.add_argument(
        "--format",
        choices=["html", "csv"],
        default="html",
        help="Report format"
    )

    args = parser.parse_args()

    if args.command == "scan":
        run_scan(args.target, args.profile)

    elif args.command == "report":
        generate_report(args.input, args.format)

    else:
        parser.print_help()
