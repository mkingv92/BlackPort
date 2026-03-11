"""
Unified Scanner Module for BlackPort v2.3.0
Intelligently combines SYN scanning with TCP connect and plugin verification

This module provides:
1. SYN scanning when root privileges available (fast, stealthy)
2. TCP connect fallback (works without root)
3. Smart two-phase approach: discovery + verification
"""

import socket
import logging
from typing import List, Dict, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

# Try to import SYN scanner
try:
    from syn_scanner import SYNScanner, check_syn_availability, SCAPY_AVAILABLE
    SYN_AVAILABLE = True
except ImportError:
    SYN_AVAILABLE = False
    SCAPY_AVAILABLE = False


class UnifiedScanner:
    """
    Intelligent scanner that combines multiple scanning techniques.
    
    Phase 1: Port Discovery
        - SYN scan if root (fast, returns open ports only)
        - TCP connect if no root (slower but works)
    
    Phase 2: Service Verification
        - TCP connect to grab banners
        - Plugin-based active verification
    
    This two-phase approach maximizes speed and accuracy.
    """
    
    def __init__(
        self,
        timeout: float = 1.0,
        threads: int = 400,
        workers: int = 10,
        force_tcp: bool = False
    ):
        """
        Initialize unified scanner.
        
        Args:
            timeout: Socket/packet timeout in seconds
            threads: Thread count for TCP sweeps
            workers: Worker count for plugins
            force_tcp: Force TCP connect scan even with root
        """
        self.timeout = timeout
        self.threads = threads
        self.workers = workers
        self.force_tcp = force_tcp
        
        self.logger = logging.getLogger(__name__)
        
        # Determine scanning mode
        self.scan_mode = self._determine_scan_mode()
        
        # Initialize appropriate scanner
        if self.scan_mode == "SYN":
            self.syn_scanner = SYNScanner(timeout=timeout, max_workers=threads)
        
        # Statistics
        self.stats = {
            'mode': self.scan_mode,
            'ports_scanned': 0,
            'ports_open': 0,
            'scan_start': None,
            'scan_duration': 0
        }
    
    def _determine_scan_mode(self) -> str:
        """
        Determine which scanning mode to use.
        
        Returns:
            str: 'SYN', 'TCP', or 'HYBRID'
        """
        if self.force_tcp:
            return "TCP"
        
        if not SYN_AVAILABLE or not SCAPY_AVAILABLE:
            return "TCP"
        
        # Check if we have privileges for SYN scanning
        available, _ = check_syn_availability()
        if available:
            return "SYN"
        else:
            return "TCP"
    
    def scan_ports_discovery(
        self,
        target: str,
        ports: List[int],
        show_progress: bool = True
    ) -> List[Dict]:
        """
        Phase 1: Fast port discovery.
        
        Uses SYN scanning if available for speed,
        falls back to TCP connect otherwise.
        
        Args:
            target: Target IP or hostname
            ports: List of ports to scan
            show_progress: Show progress updates
            
        Returns:
            list: Open port results only
        """
        self.stats['scan_start'] = time.time()
        self.stats['ports_scanned'] = len(ports)
        
        if show_progress:
            mode_name = "SYN" if self.scan_mode == "SYN" else "TCP Connect"
            print(f"[*] Phase 1: Port Discovery ({mode_name})")
            print(f"[*] Scanning {target} - {len(ports)} ports")
        
        if self.scan_mode == "SYN":
            # Use SYN scanner for fast discovery
            results = self.syn_scanner.scan_ports(target, ports, show_progress=False)
            open_results = [r for r in results if r['state'] == 'open']
        else:
            # Use TCP connect scan
            open_results = self._tcp_sweep(target, ports, show_progress)
        
        self.stats['ports_open'] = len(open_results)
        self.stats['scan_duration'] = time.time() - self.stats['scan_start']
        
        if show_progress:
            print(f"[+] Discovery complete: {len(open_results)} open ports "
                  f"in {self.stats['scan_duration']:.2f}s")
        
        return open_results
    
    def _tcp_sweep(
        self,
        target: str,
        ports: List[int],
        show_progress: bool = True
    ) -> List[Dict]:
        """
        TCP connect sweep (fallback when no SYN).
        
        Args:
            target: Target IP or hostname
            ports: Ports to scan
            show_progress: Display progress
            
        Returns:
            list: Open port results
        """
        open_ports = []
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_port = {
                executor.submit(self._tcp_connect_single, target, port): port
                for port in ports
            }
            
            completed = 0
            for future in as_completed(future_to_port):
                result = future.result()
                if result and result['state'] == 'open':
                    open_ports.append(result)
                
                completed += 1
                if show_progress and completed % 500 == 0:
                    print(f"[*] Progress: {completed}/{len(ports)} ports")
        
        return open_ports
    
    def _tcp_connect_single(self, target: str, port: int) -> Optional[Dict]:
        """
        Single TCP connect attempt.
        
        Args:
            target: Target IP or hostname
            port: Port number
            
        Returns:
            dict or None: Result if open, None if closed
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            start_time = time.time()
            result = sock.connect_ex((target, port))
            response_time = (time.time() - start_time) * 1000
            
            if result == 0:
                # Try to grab banner
                banner = None
                try:
                    sock.settimeout(0.5)
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                except:
                    pass
                
                sock.close()
                
                return {
                    'port': port,
                    'state': 'open',
                    'service': self._get_service_name(port),
                    'banner': banner,
                    'response_time': round(response_time, 2)
                }
            
            sock.close()
            return None
            
        except Exception as e:
            return None
    
    def grab_banner(self, target: str, port: int) -> Optional[str]:
        """
        Connect to port and grab service banner.
        
        Used in Phase 2 after SYN discovery to get banners.
        
        Args:
            target: Target IP or hostname
            port: Port number
            
        Returns:
            str or None: Service banner
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2.0)
            sock.connect((target, port))
            
            # Try to receive banner
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            
            return banner if banner else None
            
        except Exception:
            return None
    
    def enrich_with_banners(
        self,
        target: str,
        results: List[Dict],
        show_progress: bool = True
    ) -> List[Dict]:
        """
        Phase 2: Enrich SYN results with banners.
        
        After fast SYN discovery, connect to open ports
        to grab banners for fingerprinting.
        
        Args:
            target: Target IP or hostname
            results: Results from Phase 1 (SYN scan)
            show_progress: Display progress
            
        Returns:
            list: Enriched results with banners
        """
        if not results:
            return results
        
        if show_progress:
            print(f"[*] Phase 2: Banner Grabbing")
            print(f"[*] Connecting to {len(results)} open ports...")
        
        enriched = []
        
        with ThreadPoolExecutor(max_workers=self.workers) as executor:
            future_to_result = {
                executor.submit(self.grab_banner, target, r['port']): r
                for r in results
            }
            
            for future in as_completed(future_to_result):
                original = future_to_result[future]
                banner = future.result()
                
                # Add banner to result
                enriched_result = original.copy()
                enriched_result['banner'] = banner
                enriched.append(enriched_result)
        
        if show_progress:
            banners_found = sum(1 for r in enriched if r.get('banner'))
            print(f"[+] Banners grabbed: {banners_found}/{len(enriched)}")
        
        return enriched
    
    def full_scan(
        self,
        target: str,
        ports: List[int],
        grab_banners: bool = True,
        show_progress: bool = True
    ) -> List[Dict]:
        """
        Complete scan: discovery + banner grabbing.
        
        This is the main entry point for scanning.
        
        Args:
            target: Target IP or hostname
            ports: List of ports to scan
            grab_banners: Whether to grab banners (Phase 2)
            show_progress: Display progress updates
            
        Returns:
            list: Complete scan results
        """
        # Phase 1: Port discovery
        results = self.scan_ports_discovery(target, ports, show_progress)
        
        # Phase 2: Banner grabbing (if using SYN and banners requested)
        if self.scan_mode == "SYN" and grab_banners and results:
            results = self.enrich_with_banners(target, results, show_progress)
        
        return results
    
    def _get_service_name(self, port: int) -> str:
        """Get service name for port."""
        try:
            return socket.getservbyport(port)
        except:
            common_ports = {
                8080: 'http-proxy', 8443: 'https-alt', 3389: 'ms-wbt-server',
                5900: 'vnc', 6379: 'redis', 27017: 'mongodb', 3632: 'distccd',
                8009: 'ajp13', 8180: 'tomcat'
            }
            return common_ports.get(port, 'unknown')
    
    def get_mode(self) -> str:
        """Get current scanning mode."""
        return self.scan_mode
    
    def get_statistics(self) -> Dict:
        """Get scan statistics."""
        return self.stats.copy()


def print_scan_banner(mode: str):
    """
    Print informational banner about scan mode.
    
    Args:
        mode: Scanning mode (SYN or TCP)
    """
    if mode == "SYN":
        print("╔═══════════════════════════════════════════════════════════╗")
        print("║          SYN SCANNING MODE (Stealth)                     ║")
        print("║  • Half-open scanning (doesn't complete handshake)       ║")
        print("║  • Faster than TCP connect                                ║")
        print("║  • Less likely to be logged                               ║")
        print("║  • Requires root/administrator privileges                 ║")
        print("╚═══════════════════════════════════════════════════════════╝")
    else:
        print("╔═══════════════════════════════════════════════════════════╗")
        print("║        TCP CONNECT SCANNING MODE                          ║")
        print("║  • Full 3-way handshake                                   ║")
        print("║  • No special privileges required                         ║")
        print("║  • Grabs banners during connection                        ║")
        print("║  • May be logged by target applications                   ║")
        print("╚═══════════════════════════════════════════════════════════╝")


# Example usage
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Unified Scanner Test")
    parser.add_argument('target', help='Target IP or hostname')
    parser.add_argument('--ports', default='22,80,443,3306,8080', help='Ports to scan')
    parser.add_argument('--timeout', type=float, default=1.0, help='Timeout')
    parser.add_argument('--force-tcp', action='store_true', help='Force TCP mode')
    
    args = parser.parse_args()
    
    # Parse ports
    ports = [int(p.strip()) for p in args.ports.split(',')]
    
    # Initialize scanner
    scanner = UnifiedScanner(
        timeout=args.timeout,
        force_tcp=args.force_tcp
    )
    
    # Print mode banner
    print_scan_banner(scanner.get_mode())
    print()
    
    # Scan
    results = scanner.full_scan(args.target, ports)
    
    # Display results
    print("\n[+] Open Ports:")
    print(f"{'Port':<8} {'Service':<20} {'Banner':<50}")
    print("-" * 80)
    
    for r in sorted(results, key=lambda x: x['port']):
        banner = (r.get('banner') or 'No banner')[:47] + '...' if len(r.get('banner', '')) > 50 else (r.get('banner') or 'No banner')
        print(f"{r['port']:<8} {r['service']:<20} {banner:<50}")
    
    # Statistics
    stats = scanner.get_statistics()
    print(f"\n[*] Scan Statistics:")
    print(f"    Mode: {stats['mode']}")
    print(f"    Ports scanned: {stats['ports_scanned']}")
    print(f"    Open ports: {stats['ports_open']}")
    print(f"    Duration: {stats['scan_duration']:.2f}s")
