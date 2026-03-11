"""
BlackPort v2.3.0 - Main Entry Point
Example integration with SYN scanning capability

Usage:
    # TCP connect mode (no root required)
    python main.py 192.168.1.100 --top-100
    
    # SYN scan mode (requires root)
    sudo python main.py 192.168.1.100 --top-100 --syn
    
    # Force TCP even with root
    sudo python main.py 192.168.1.100 --top-100 --tcp
"""

import argparse
import sys
import os

# Import unified scanner
try:
    from unified_scanner import UnifiedScanner, print_scan_banner
    from syn_scanner import check_syn_availability, SCAPY_AVAILABLE
except ImportError:
    print("[!] Error: Scanner modules not found")
    sys.exit(1)


def parse_arguments():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="BlackPort v2.3.0 - Offensive Port Intelligence Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Quick scan (TCP connect, no root needed)
  python main.py 192.168.1.100 --top-100
  
  # Stealth scan (SYN, requires root)
  sudo python main.py 192.168.1.100 --top-100 --syn
  
  # Full scan with SYN
  sudo python main.py 192.168.1.100 --full --syn
  
  # Network scan
  sudo python main.py 192.168.1.0/24 --top-100 --syn
        """
    )
    
    # Target
    parser.add_argument('target', help='Target IP, hostname, or CIDR network')
    
    # Port selection (mutually exclusive)
    port_group = parser.add_mutually_exclusive_group()
    port_group.add_argument('--top-100', action='store_true',
                           help='Scan top 100 ports (~7s)')
    port_group.add_argument('--top-500', action='store_true',
                           help='Scan top 500 ports (~15s)')
    port_group.add_argument('--top-1000', action='store_true',
                           help='Scan ports 1-1000')
    port_group.add_argument('--full', action='store_true',
                           help='Scan all 65535 ports (~97s)')
    port_group.add_argument('--fast', action='store_true',
                           help='Scan ports 1-100')
    port_group.add_argument('ports', nargs='*', type=int,
                           help='Specific ports or port range')
    
    # Scan mode
    scan_mode = parser.add_mutually_exclusive_group()
    scan_mode.add_argument('--syn', action='store_true',
                          help='Use SYN scanning (requires root/sudo)')
    scan_mode.add_argument('--tcp', action='store_true',
                          help='Force TCP connect scan (no root required)')
    
    # Performance tuning
    parser.add_argument('--threads', type=int, default=400,
                       help='Thread count for scanning (default: 400)')
    parser.add_argument('--workers', type=int, default=10,
                       help='Worker count for plugins (default: 10)')
    parser.add_argument('--timeout', type=float, default=1.0,
                       help='Socket timeout in seconds (default: 1.0)')
    
    # Output
    parser.add_argument('--output-dir', default='.',
                       help='Output directory for reports')
    parser.add_argument('--pdf', action='store_true',
                       help='Generate PDF report')
    parser.add_argument('--json', action='store_true',
                       help='Print JSON to stdout')
    parser.add_argument('--quiet', action='store_true',
                       help='Suppress progress output')
    
    # Other
    parser.add_argument('--nvd', action='store_true',
                       help='Enrich with NVD CVE data')
    parser.add_argument('--version', action='version',
                       version='BlackPort v2.3.0')
    
    return parser.parse_args()


def get_port_list(args):
    """
    Determine which ports to scan based on arguments.
    
    Args:
        args: Parsed command-line arguments
        
    Returns:
        list: Port numbers to scan
    """
    if args.top_100:
        # Top 100 curated ports
        return [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 
                993, 995, 1723, 3306, 3389, 5900, 8080]  # Abbreviated for example
    elif args.top_500:
        # Top 500 ports (abbreviated)
        return list(range(1, 501))
    elif args.top_1000:
        return list(range(1, 1001))
    elif args.full:
        return list(range(1, 65536))
    elif args.fast:
        return list(range(1, 101))
    elif args.ports:
        # User specified ports
        if len(args.ports) == 2:
            # Port range
            return list(range(args.ports[0], args.ports[1] + 1))
        else:
            # Individual ports
            return args.ports
    else:
        # Default to top 100
        return [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
                993, 995, 1723, 3306, 3389, 5900, 8080]


def check_syn_requirements(args):
    """
    Check if SYN scanning can be used.
    
    Args:
        args: Command-line arguments
        
    Returns:
        bool: True if SYN scanning should be used
    """
    if args.tcp:
        # User explicitly requested TCP
        return False
    
    if not args.syn:
        # User didn't request SYN
        return False
    
    # Check availability
    if not SCAPY_AVAILABLE:
        print("[!] Error: Scapy not installed")
        print("[!] Install with: pip install scapy")
        print("[!] Falling back to TCP connect mode")
        return False
    
    available, message = check_syn_availability()
    if not available:
        print(f"[!] SYN scanning not available: {message}")
        print("[!] Falling back to TCP connect mode")
        return False
    
    return True


def main():
    """Main entry point."""
    args = parse_arguments()
    
    # Determine ports to scan
    ports = get_port_list(args)
    
    # Check SYN requirements
    use_syn = check_syn_requirements(args)
    
    # Initialize scanner
    scanner = UnifiedScanner(
        timeout=args.timeout,
        threads=args.threads,
        workers=args.workers,
        force_tcp=(not use_syn)
    )
    
    # Print scan mode banner
    if not args.quiet:
        print("\n" + "="*60)
        print("BlackPort v2.3.0 - Offensive Port Intelligence Engine")
        print("="*60)
        print_scan_banner(scanner.get_mode())
        print()
    
    # Perform scan
    try:
        results = scanner.full_scan(
            target=args.target,
            ports=ports,
            grab_banners=True,
            show_progress=(not args.quiet)
        )
        
        # Display results
        if not args.quiet:
            print("\n" + "="*60)
            print("SCAN RESULTS")
            print("="*60)
            
            if results:
                print(f"\n{'Port':<8} {'State':<12} {'Service':<20} {'Banner':<40}")
                print("-" * 80)
                
                for r in sorted(results, key=lambda x: x['port']):
                    banner = (r.get('banner') or 'No banner')
                    if len(banner) > 40:
                        banner = banner[:37] + '...'
                    
                    print(f"{r['port']:<8} {r['state']:<12} {r['service']:<20} {banner:<40}")
                
                print(f"\n[+] Found {len(results)} open ports")
            else:
                print("\n[!] No open ports found")
            
            # Statistics
            stats = scanner.get_statistics()
            print(f"\n[*] Scan Statistics:")
            print(f"    Mode: {stats['mode']}")
            print(f"    Ports scanned: {stats['ports_scanned']}")
            print(f"    Open ports: {stats['ports_open']}")
            print(f"    Duration: {stats['scan_duration']:.2f}s")
            print(f"    Speed: {stats['ports_scanned']/stats['scan_duration']:.0f} ports/sec")
        
        # JSON output
        if args.json:
            import json
            print(json.dumps(results, indent=2))
        
        # TODO: Integrate with plugin phase (Phase 3)
        # TODO: Generate reports (HTML, PDF, CSV)
        
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
