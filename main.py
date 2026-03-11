# =====================================================================
# File: main.py
# Notes:
# - This file is part of the BlackPort project.
# - Entry point — argument parsing, scan orchestration, multi-host support.
# - Use only on hosts/networks you own or have explicit permission to test.
# =====================================================================

import argparse
import ipaddress
import json
import os
import sys
import time

from banner import show_banner
from blackport.scanner import PortScanner
from colorama import Fore, Style, init
init(autoreset=True)

VERSION = "2.3.0"

# ── Curated port lists ────────────────────────────────────────────────────────
# Top 100: highest-value targets — covers 95% of real-world findings
TOP_100_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 512, 513, 514,
    587, 993, 995, 1099, 1433, 1521, 1524, 2049, 2121, 3306, 3389, 3632, 4444,
    5432, 5900, 5985, 6000, 6667, 6697, 7000, 7001, 8009, 8080, 8180, 8443,
    8787, 9200, 9300, 10000, 27017, 27018, 50000,
]

# Top 500: adds uncommon but high-value ports (Redis, MongoDB, Docker, etc.)
TOP_500_PORTS = sorted(set(TOP_100_PORTS + [
    69, 79, 88, 102, 119, 137, 138, 161, 162, 179, 194, 201, 264, 389, 464,
    500, 502, 515, 520, 554, 623, 631, 636, 873, 902, 989, 990, 992, 1080,
    1194, 1234, 1337, 1443, 1900, 2000, 2001, 2082, 2083, 2086, 2087, 2095,
    2096, 2100, 2222, 2375, 2376, 2379, 2380, 3000, 3128, 3260, 3299, 3478,
    3500, 3690, 4000, 4040, 4443, 4848, 4899, 4984, 5000, 5001, 5005, 5006,
    5007, 5009, 5044, 5060, 5061, 5500, 5555, 5601, 5632, 5800, 5801, 5938,
    6379, 6443, 6881, 7080, 7180, 7443, 7474, 7547, 7548, 8000, 8001, 8008,
    8010, 8020, 8042, 8069, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088,
    8089, 8090, 8091, 8161, 8200, 8300, 8301, 8302, 8400, 8500, 8600, 8880,
    8888, 8889, 8983, 9000, 9001, 9002, 9042, 9090, 9091, 9100, 9200, 9418,
    9443, 9999, 10001, 10050, 10051, 10080, 10443, 11211, 15672, 16010, 16000,
    17000, 18080, 18443, 19999, 20000, 20547, 21025, 22222, 23023, 25565,
    27015, 28017, 32768, 32769, 37777, 49152, 49153, 49154, 49155, 49156,
    50030, 50060, 50070, 51106, 55443, 55555, 60000, 61616,
]))


def _resolve_ports(args):
    """Return (ports_list_or_None, start_port, end_port) based on CLI flags."""
    if args.top_100:
        return TOP_100_PORTS, None, None
    if args.top_500:
        return TOP_500_PORTS, None, None
    if args.fast:
        return None, 1, 100
    if args.top_1000:
        return None, 1, 1000
    if args.full:
        return None, 1, 65535
    if args.start_port is not None and args.end_port is not None:
        return None, args.start_port, args.end_port
    return None, None, None


def _auto_threads(port_count):
    if port_count <= 100:
        return 50
    elif port_count <= 500:
        return 100
    elif port_count <= 1000:
        return 200
    else:
        return 400


def _discover_hosts(network):
    """
    Ping-sweep a CIDR range and return list of live host IPs.
    Uses TCP connect to port 80 and 443 as a fast liveness check —
    avoids needing raw socket privileges for ICMP.
    """
    import socket
    from concurrent.futures import ThreadPoolExecutor, as_completed

    net   = ipaddress.ip_network(network, strict=False)
    hosts = list(net.hosts())

    if len(hosts) > 1024:
        print(f"{Fore.YELLOW}[!] Large network ({len(hosts)} hosts) — discovery may take a while.{Style.RESET_ALL}")

    print(f"{Fore.CYAN}[*] Discovering live hosts in {network}...{Style.RESET_ALL}")

    live = []

    def probe(ip):
        ip_str = str(ip)
        for port in (80, 443, 22, 445, 8080, 3306, 21, 25):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.5)
                    if s.connect_ex((ip_str, port)) == 0:
                        return ip_str
            except Exception:
                pass
        return None

    with ThreadPoolExecutor(max_workers=200) as pool:
        futures = {pool.submit(probe, ip): ip for ip in hosts}
        done    = 0
        for future in as_completed(futures):
            done += 1
            print(f"  Discovery: {done}/{len(hosts)}", end="\r")
            result = future.result()
            if result:
                live.append(result)

    print()
    live.sort(key=lambda x: list(map(int, x.split("."))))
    print(f"{Fore.GREEN}[+] Found {len(live)} live host(s): {', '.join(live)}{Style.RESET_ALL}\n")
    return live


def _scan_target(target, args, port_list, start_port, end_port, output_dir):
    """Run a full scan against a single target and return the scanner object."""
    
    # Determine thread count
    threads = args.threads
    if not any(f in sys.argv for f in ["--threads"]):
        count   = len(port_list) if port_list else (end_port - start_port + 1)
        threads = _auto_threads(count)
    
    # Phase 1: Port Discovery (SYN or TCP)
    if args.syn:
        # Use SYN scanning for discovery
        try:
            from unified_scanner import UnifiedScanner
            
            print(f"{Fore.CYAN}[*] Using SYN scanning mode (stealth){Style.RESET_ALL}")
            
            # Initialize SYN scanner
            syn_scanner = UnifiedScanner(
                timeout=args.timeout,
                threads=threads,
                force_tcp=False  # Use SYN
            )
            
            # Get ports to scan
            if port_list:
                ports = port_list
            else:
                ports = list(range(start_port, end_port + 1))
            
            # Run SYN discovery
            print(f"{Fore.CYAN}[*] Phase 1: SYN Port Discovery{Style.RESET_ALL}")
            open_ports_data = syn_scanner.full_scan(target, ports, show_progress=(not args.quiet))
            
            # Convert to format expected by PortScanner
            # Extract just the port numbers
            discovered_ports = [p['port'] for p in open_ports_data if p['state'] == 'open']
            
            if not discovered_ports:
                print(f"{Fore.YELLOW}[!] No open ports found with SYN scan{Style.RESET_ALL}")
                # Still create scanner with empty results
                scanner = PortScanner(
                    target=target,
                    start_port=start_port or 1,
                    end_port=end_port or 1000,
                    threads=threads,
                    timeout=args.timeout,
                    output_dir=output_dir,
                    port_list=[],  # Empty - no open ports
                    pdf=getattr(args, 'pdf', False),
                )
                scanner.results = []
                return scanner
            
            print(f"{Fore.GREEN}[+] SYN scan found {len(discovered_ports)} open ports{Style.RESET_ALL}")
            print(f"{Fore.CYAN}[*] Phase 2 & 3: Plugin verification and banner grabbing...{Style.RESET_ALL}\n")
            
            # Phase 2 & 3: Run full scanner with only open ports (for plugins and banners)
            scanner = PortScanner(
                target=target,
                start_port=start_port or 1,
                end_port=end_port or 1000,
                threads=threads,
                timeout=args.timeout,
                output_dir=output_dir,
                port_list=discovered_ports,  # Only scan ports SYN found as open
                pdf=getattr(args, 'pdf', False),
            )
            scanner.scan()
            return scanner
            
        except ImportError:
            print(f"{Fore.YELLOW}[!] Scapy not installed. Install with: pip install scapy{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[!] Falling back to TCP connect mode{Style.RESET_ALL}\n")
        except PermissionError:
            print(f"{Fore.YELLOW}[!] SYN scanning requires root/sudo privileges{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[!] Falling back to TCP connect mode{Style.RESET_ALL}\n")
        except Exception as e:
            print(f"{Fore.YELLOW}[!] SYN scan failed: {e}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[!] Falling back to TCP connect mode{Style.RESET_ALL}\n")
    
    # Standard TCP connect scan (original behavior)
    scanner = PortScanner(
        target=target,
        start_port=start_port or 1,
        end_port=end_port or 1000,
        threads=threads,
        timeout=args.timeout,
        output_dir=output_dir,
        port_list=port_list,
        pdf=getattr(args, 'pdf', False),
    )
    scanner.scan()
    return scanner


def main():
    show_banner(VERSION)

    parser = argparse.ArgumentParser(
        description  = "BlackPort v2.3.0 — Offensive Port Intelligence Engine",
        formatter_class = argparse.RawDescriptionHelpFormatter,
        epilog = """
Examples:
  python main.py 192.168.1.1 --top-100          # Fast curated scan (~3s)
  python main.py 192.168.1.1 --top-500          # Broader curated scan (~8s)
  python main.py 192.168.1.1 --top-1000         # 1-1000 sequential (~10s)
  python main.py 192.168.1.1 --full             # Full 65535 port scan (~97s)
  python main.py 192.168.1.1 80 443             # Specific port range
  python main.py 192.168.1.0/24 --top-100       # CIDR network scan
  python main.py 192.168.1.1 --top-100 --output-dir ~/reports
  python main.py 192.168.1.1 --top-100 --pdf    # Generate PDF report
  
  # SYN scanning (requires root/sudo) - faster and stealthier
  sudo python main.py 192.168.1.1 --top-100 --syn
  sudo python main.py 192.168.1.1 --full --syn  # Full scan in ~46s (vs 97s)
        """
    )

    parser.add_argument("--version", action="version", version=f"BlackPort v{VERSION}")
    parser.add_argument("target",     help="Target IP, hostname, or CIDR range (e.g. 192.168.1.0/24)")
    parser.add_argument("start_port", type=int, nargs="?", help="Start port (optional if using a profile)")
    parser.add_argument("end_port",   type=int, nargs="?", help="End port (optional if using a profile)")

    # Scan profiles
    profiles = parser.add_argument_group("scan profiles")
    profiles.add_argument("--top-100",  action="store_true", help="Curated top 100 high-value ports (~3s)")
    profiles.add_argument("--top-500",  action="store_true", help="Curated top 500 ports including databases/APIs (~8s)")
    profiles.add_argument("--fast",     action="store_true", help="Sequential ports 1-100")
    profiles.add_argument("--top-1000", action="store_true", help="Sequential ports 1-1000 (~10s)")
    profiles.add_argument("--full",     action="store_true", help="Full 1-65535 scan (~97s TCP, ~46s SYN)")

    # Scan mode
    scan_mode = parser.add_argument_group("scan mode")
    scan_mode.add_argument("--syn", action="store_true", help="Use SYN scanning (requires root/sudo, 2x faster)")

    # Tuning
    tuning = parser.add_argument_group("tuning")
    tuning.add_argument("--threads",    type=int,   default=200,  help="Thread count for port sweep (default: auto)")
    tuning.add_argument("--timeout",    type=float, default=1.0,  help="Socket timeout in seconds (default: 1.0)")
    tuning.add_argument("--delay",      type=float, default=0.0,  help="Delay between plugin checks in seconds")

    # Output
    output_grp = parser.add_argument_group("output")
    output_grp.add_argument("--output-dir", default=".", metavar="DIR",
                            help="Directory for report files (default: current directory)")
    output_grp.add_argument("--json",   action="store_true", help="Print JSON results to stdout")
    output_grp.add_argument("--quiet",  action="store_true", help="Suppress progress output")
    output_grp.add_argument("--pdf",    action="store_true", help="Generate PDF report in addition to HTML/JSON/CSV")

    args = parser.parse_args()

    # Resolve port list / range
    port_list, start_port, end_port = _resolve_ports(args)

    if port_list is None and start_port is None:
        parser.error(
            "Specify a scan profile (--top-100, --top-500, --top-1000, --full) "
            "or a port range (start_port end_port)."
        )

    # Output directory
    output_dir = os.path.expanduser(args.output_dir)
    os.makedirs(output_dir, exist_ok=True)

    # ── CIDR / multi-host ─────────────────────────────────────────────
    try:
        net = ipaddress.ip_network(args.target, strict=False)
        if net.num_addresses > 1:
            targets = _discover_hosts(str(net))
            if not targets:
                print(f"{Fore.YELLOW}[!] No live hosts found in {args.target}{Style.RESET_ALL}")
                sys.exit(0)

            all_results = {}
            for host in targets:
                print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
                print(f"{Fore.CYAN}[*] Scanning {host} ({targets.index(host)+1}/{len(targets)}){Style.RESET_ALL}")
                print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")
                try:
                    scanner       = _scan_target(host, args, port_list, start_port, end_port, output_dir)
                    all_results[host] = scanner.results
                except Exception as e:
                    print(f"{Fore.RED}[!] Failed to scan {host}: {e}{Style.RESET_ALL}")

            if args.json:
                print(json.dumps(all_results, indent=2))
            return

    except ValueError:
        pass  # Not a network — treat as single host

    # ── Single host ──────────────────────────────────────────────────
    target = args.target
    scan_mode = "SYN" if args.syn else "TCP"
    print(f"{Fore.CYAN}[*] Scanning {target} ({scan_mode} mode)...{Style.RESET_ALL}")

    try:
        scanner = _scan_target(target, args, port_list, start_port, end_port, output_dir)

        if args.json:
            print(json.dumps(scanner.results, indent=2))

    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Scan interrupted by user.{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"{Fore.RED}[!] Error: {e}{Style.RESET_ALL}")
        sys.exit(1)


if __name__ == "__main__":
    main()
