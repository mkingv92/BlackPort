"""
MayheM-Sec Added

Unified BlackPort scan launcher for the MayheM-Sec fork.

This wrapper keeps upstream TCP/SYN behavior in main.py, applies MayheM-Sec
assessment policy through assessment_runner.py, and delegates UDP work to
udp_scanner.py. Mixed mode runs both paths sequentially so CLI and GUI share
one orchestration layer.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent

TCP_PROFILES = {
    "top-100": "--top-100",
    "top-500": "--top-500",
    "top-1000": "--top-1000",
    "full": "--full",
}
UDP_PROFILES = {
    "top-25": "--top-25",
    "top-50": "--top-50",
    "top-100": "--top-100",
    "full": "--full",
}
ASSESSMENT_PROFILES = {"safe", "verify", "aggressive"}


def _run(command: list[str]) -> int:
    """MayheM-Sec Added: stream a child scanner directly to the current console."""
    process = subprocess.Popen(command, cwd=str(ROOT))
    try:
        return process.wait()
    except KeyboardInterrupt:
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
        raise


def _json_reports(output_dir: Path) -> set[Path]:
    """MayheM-Sec Added: snapshot upstream JSON reports, excluding fork sidecars."""
    if not output_dir.exists():
        return set()
    return {
        p.resolve()
        for p in output_dir.glob("blackport_*.json")
        if not p.name.endswith(".mayhem.json") and not p.name.endswith("_udp.json")
    }


def _enrich_new_reports(before: set[Path], output_dir: Path, enabled: bool) -> None:
    if not enabled:
        return
    after = _json_reports(output_dir)
    for report in sorted(after - before):
        code = _run([sys.executable, str(ROOT / "report_enricher.py"), str(report)])
        if code != 0:
            print(f"[MayheM-Sec Added] Intelligence enrichment failed for {report.name}.")


def tcp_command(args: argparse.Namespace) -> list[str]:
    # MayheM-Sec Added: assessment_runner applies policy, then forwards the normal
    # upstream BlackPort arguments without changing main.py.
    command = [
        sys.executable,
        str(ROOT / "assessment_runner.py"),
        "--profile", args.assessment_profile,
        "--",
        args.target,
        TCP_PROFILES[args.tcp_profile],
        "--timeout", str(args.timeout),
        "--output-dir", str(Path(args.output_dir).expanduser()),
    ]
    if args.mode == "syn":
        command.append("--syn")
    if args.pdf:
        command.append("--pdf")
    return command


def udp_command(args: argparse.Namespace) -> list[str]:
    return [
        sys.executable,
        str(ROOT / "udp_scanner.py"),
        args.target,
        UDP_PROFILES[args.udp_profile],
        "--timeout", str(args.udp_timeout),
        "--retries", str(args.udp_retries),
        "--workers", str(args.udp_workers),
        "--output-dir", str(Path(args.output_dir).expanduser()),
    ]


def run_tcp(args: argparse.Namespace) -> int:
    """MayheM-Sec Added: run TCP/SYN and enrich only reports created by this run."""
    output_dir = Path(args.output_dir).expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    before = _json_reports(output_dir)
    code = _run(tcp_command(args))
    if code == 0:
        _enrich_new_reports(before, output_dir, enabled=not args.no_intel)
    return code


def main() -> None:
    parser = argparse.ArgumentParser(description="BlackPort unified scanner - MayheM-Sec Added")
    parser.add_argument("target", help="Target IP or hostname; CIDR is supported by TCP/SYN modes")
    parser.add_argument("--mode", choices=["tcp", "syn", "udp", "mixed"], default="tcp")
    parser.add_argument("--assessment-profile", choices=sorted(ASSESSMENT_PROFILES), default="safe",
                        help="TCP/SYN plugin policy: safe, verify, or aggressive (default: safe)")
    parser.add_argument("--tcp-profile", choices=TCP_PROFILES, default="top-100")
    parser.add_argument("--udp-profile", choices=UDP_PROFILES, default="top-25")
    parser.add_argument("--timeout", type=float, default=1.0, help="TCP/SYN timeout")
    parser.add_argument("--udp-timeout", type=float, default=1.0)
    parser.add_argument("--udp-retries", type=int, default=2)
    parser.add_argument("--udp-workers", type=int, default=80)
    parser.add_argument("--output-dir", default="reports")
    parser.add_argument("--pdf", action="store_true")
    parser.add_argument("--no-intel", action="store_true", help="Skip MayheM-Sec KEV/EPSS report enrichment")
    args = parser.parse_args()

    # MayheM-Sec Added: UDP CIDR support is deferred until host-discovery semantics are added.
    if args.mode in {"udp", "mixed"} and "/" in args.target:
        parser.error("UDP and mixed modes currently accept one IP address or hostname, not CIDR")

    if args.mode in {"tcp", "syn"}:
        raise SystemExit(run_tcp(args))

    if args.mode == "udp":
        raise SystemExit(_run(udp_command(args)))

    print("[MayheM-Sec Added] Mixed scan: starting TCP phase")
    tcp_args = argparse.Namespace(**vars(args))
    tcp_args.mode = "tcp"
    tcp_code = run_tcp(tcp_args)
    if tcp_code != 0:
        print(f"[MayheM-Sec Added] TCP phase exited with code {tcp_code}; UDP phase will still run.")

    print("\n[MayheM-Sec Added] Mixed scan: starting UDP phase")
    udp_code = _run(udp_command(args))
    raise SystemExit(tcp_code or udp_code)


if __name__ == "__main__":
    main()
