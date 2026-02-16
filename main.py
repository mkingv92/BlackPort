# =====================================================================
# File: main.py
# Notes:
# - This file is part of the BlackPort project.
# - The comments added here are for readability only (no behavior change).
# - Use only on hosts/networks you own or have explicit permission to test.
# =====================================================================

import argparse
import sys
from banner import show_banner
from blackport.scanner import PortScanner
import json
import time
from cve_lookup import load_cve_db, match_cves
from cve_db import CVE_DATABASE
from enum_modules import get_http_title, check_ftp_anonymous, enum_smb_shares
VERSION = "2.0.0"


# NOTE: sort_by_risk() - helper/entry function. Read the body for the exact steps.
def sort_by_risk(results):
    priority = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    return sorted(results, key=lambda x: priority.get(x["risk"], 3))


# NOTE: main() - helper/entry function. Read the body for the exact steps.
def main():
    show_banner(VERSION)


    parser = argparse.ArgumentParser(
        description="BlackPort - Offensive Port Intelligence Engine"
    )


    parser.add_argument(
        "--version",
        action="version",
        version=f"BlackPort v{VERSION}"
    )

    parser.add_argument("target", help="Target IP address")
    parser.add_argument("start_port", type=int, nargs="?", help="Start port")
    parser.add_argument("end_port", type=int, nargs="?", help="End port")

    parser.add_argument(
        "--threads",
        type=int,
        default=100,
        help="Number of threads (default: 100)"
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=1.0,
        help="Socket timeout in seconds (default: 1.0)"
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results in JSON format"
    )

    parser.add_argument(
        "--output",
        help="Save results to file"
    )

    parser.add_argument(
        "--fast",
        action="store_true",
        help="Scan common top 100 ports"
    )

    parser.add_argument(
        "--full",
        action="store_true",
        help="Scan full 1-65535 range"
    )

    parser.add_argument(
        "--top-100",
        action="store_true",
        help="Scan predefined top 100 ports"
    )

    parser.add_argument(
        "--top-1000",
        action="store_true",
        help="Scan top 1000 ports (1-1000)"
    )


    args = parser.parse_args()

    if args.fast:
        args.start_port = 1
        args.end_port = 100

    elif args.top_1000:
        args.start_port = 1
        args.end_port = 1000

    elif args.full:
        args.start_port = 1
        args.end_port = 65535

    # If no profile used and ports missing → error
    if args.start_port is None or args.end_port is None:
        parser.error("You must specify start_port and end_port unless using --fast,--top-1000 or --full")

    # Auto-scale threads if user didn’t manually specify
    if not any(flag in sys.argv for flag in ["--threads"]):  # default value
        total_ports = args.end_port - args.start_port + 1

        if total_ports <= 100:
            args.threads = 50
        elif total_ports <= 1000:
            args.threads = 200
        else:
            args.threads = 400

    try:
        scanner = PortScanner(
            args.target,
            args.start_port,
            args.end_port,
            threads=args.threads,
            timeout=args.timeout
        )

        scanner.scan()

    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.")
        sys.exit(0)

    except Exception as e:
        print(f"[!] Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
