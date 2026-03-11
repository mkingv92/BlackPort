"""
SYN Scanner Module for BlackPort v2.3.0
High-performance stealth port scanning using raw packets

Requires: scapy, root/administrator privileges
Author: Matthew Valdez
"""

import socket
import logging
import os
import sys
from typing import Dict, List, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

try:
    from scapy.all import IP, TCP, ICMP, sr1, RandShort, conf
    SCAPY_AVAILABLE = True
    # Disable scapy warnings
    conf.verb = 0
except ImportError:
    SCAPY_AVAILABLE = False


class SYNScanner:
    """
    High-performance SYN (half-open) port scanner.
    
    SYN scanning is stealthier than TCP connect scanning:
    - Doesn't complete the 3-way handshake
    - Less likely to be logged by applications
    - Faster than full TCP connections
    - Requires root/administrator privileges
    """
    
    def __init__(self, timeout: float = 1.0, max_workers: int = 100):
        """
        Initialize SYN scanner.
        
        Args:
            timeout: Response timeout in seconds (default: 1.0)
            max_workers: Maximum concurrent scans (default: 100)
                        Note: Automatically reduced for large scans to prevent
                        file descriptor exhaustion
        """
        if not SCAPY_AVAILABLE:
            raise ImportError(
                "Scapy is required for SYN scanning. Install with: pip install scapy"
            )
        
        if not self._check_privileges():
            raise PermissionError(
                "SYN scanning requires root/administrator privileges.\n"
                "Linux/macOS: Run with 'sudo'\n"
                "Windows: Run terminal as Administrator"
            )
        
        self.timeout = timeout
        self.max_workers = max_workers
        self.logger = logging.getLogger(__name__)
        
        # Auto-detect system file descriptor limit
        self.fd_limit = self._get_fd_limit()
        
        # Statistics
        self.stats = {
            'sent': 0,
            'received': 0,
            'open': 0,
            'closed': 0,
            'filtered': 0
        }
    
    def _get_fd_limit(self) -> int:
        """
        Get the system file descriptor limit.
        
        Returns:
            int: Maximum number of open file descriptors
        """
        try:
            import resource
            soft_limit, hard_limit = resource.getrlimit(resource.RLIMIT_NOFILE)
            return soft_limit
        except Exception:
            # Default conservative limit if we can't detect
            return 1024
    
    def _check_privileges(self) -> bool:
        """Check if running with sufficient privileges for raw sockets."""
        try:
            # Unix-like systems
            if hasattr(os, 'geteuid'):
                return os.geteuid() == 0
            # Windows
            else:
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    
    def syn_scan_port(self, target: str, port: int) -> Dict:
        """
        Perform SYN scan on a single port.
        
        Args:
            target: Target IP address or hostname
            port: Port number to scan
            
        Returns:
            dict: {
                'port': int,
                'state': 'open'|'closed'|'filtered'|'error',
                'service': str,
                'ttl': int or None,
                'response_time': float or None
            }
        """
        try:
            # Resolve hostname to IP if needed
            target_ip = socket.gethostbyname(target)
            
            # Generate random source port to avoid conflicts
            src_port = RandShort()
            
            # Build SYN packet
            # IP layer: destination = target
            # TCP layer: SYN flag set, random source port, target destination port
            ip_layer = IP(dst=target_ip)
            tcp_layer = TCP(
                sport=src_port,
                dport=port,
                flags='S',  # SYN flag
                seq=1000    # Initial sequence number
            )
            packet = ip_layer / tcp_layer
            
            # Send packet and measure response time
            self.stats['sent'] += 1
            start_time = time.time()
            
            response = sr1(
                packet,
                timeout=self.timeout,
                verbose=0,
                retry=0
            )
            
            response_time = (time.time() - start_time) * 1000  # Convert to ms
            
            # No response - port is filtered or host is down
            if response is None:
                self.stats['filtered'] += 1
                return {
                    'port': port,
                    'state': 'filtered',
                    'service': self._get_service_name(port),
                    'ttl': None,
                    'response_time': None
                }
            
            self.stats['received'] += 1
            
            # Analyze response
            if response.haslayer(TCP):
                tcp_flags = response.getlayer(TCP).flags
                
                # SYN-ACK response = port is OPEN
                if tcp_flags == 0x12:  # SYN-ACK (binary: 010010)
                    # Send RST to gracefully terminate connection
                    # This prevents the target from waiting for ACK
                    rst_packet = IP(dst=target_ip) / TCP(
                        sport=src_port,
                        dport=port,
                        flags='R',  # RST flag
                        seq=response.getlayer(TCP).ack
                    )
                    sr1(rst_packet, timeout=0.1, verbose=0)
                    
                    self.stats['open'] += 1
                    return {
                        'port': port,
                        'state': 'open',
                        'service': self._get_service_name(port),
                        'ttl': response.getlayer(IP).ttl if response.haslayer(IP) else None,
                        'response_time': round(response_time, 2)
                    }
                
                # RST or RST-ACK response = port is CLOSED
                elif tcp_flags & 0x04:  # RST flag set
                    self.stats['closed'] += 1
                    return {
                        'port': port,
                        'state': 'closed',
                        'service': self._get_service_name(port),
                        'ttl': response.getlayer(IP).ttl if response.haslayer(IP) else None,
                        'response_time': round(response_time, 2)
                    }
            
            # ICMP error response (typically means filtered)
            elif response.haslayer(ICMP):
                icmp_type = response.getlayer(ICMP).type
                icmp_code = response.getlayer(ICMP).code
                
                # Type 3 = Destination Unreachable
                # Code 1, 2, 3, 9, 10, 13 = Filtered
                if icmp_type == 3 and icmp_code in [1, 2, 3, 9, 10, 13]:
                    self.stats['filtered'] += 1
                    return {
                        'port': port,
                        'state': 'filtered',
                        'service': self._get_service_name(port),
                        'ttl': response.getlayer(IP).ttl if response.haslayer(IP) else None,
                        'response_time': round(response_time, 2)
                    }
            
            # Unknown response
            self.stats['filtered'] += 1
            return {
                'port': port,
                'state': 'filtered',
                'service': self._get_service_name(port),
                'ttl': None,
                'response_time': round(response_time, 2)
            }
            
        except socket.gaierror:
            self.logger.error(f"Cannot resolve hostname: {target}")
            return {
                'port': port,
                'state': 'error',
                'service': None,
                'ttl': None,
                'response_time': None,
                'error': f'Cannot resolve {target}'
            }
        except PermissionError:
            self.logger.error("Insufficient privileges for raw socket operations")
            return {
                'port': port,
                'state': 'error',
                'service': None,
                'ttl': None,
                'response_time': None,
                'error': 'Permission denied - need root/admin'
            }
        except Exception as e:
            self.logger.error(f"SYN scan error on {target}:{port} - {e}")
            return {
                'port': port,
                'state': 'error',
                'service': None,
                'ttl': None,
                'response_time': None,
                'error': str(e)
            }
    
    def scan_ports(self, target: str, ports: List[int], show_progress: bool = True) -> List[Dict]:
        """
        Scan multiple ports using concurrent SYN scanning with intelligent batching.
        
        Automatically batches large scans to prevent file descriptor exhaustion.
        For scans >5000 ports, processes in batches to avoid system limits.
        
        Args:
            target: Target IP address or hostname
            ports: List of port numbers to scan
            show_progress: Display progress indicator
            
        Returns:
            list: List of result dictionaries (all ports scanned)
        """
        total_ports = len(ports)
        
        # Auto-adjust workers and batching based on scan size
        if total_ports > 10000:
            # Large scan: reduce workers, use batching
            batch_size = 5000
            max_workers = min(50, self.max_workers)
            if show_progress:
                print(f"[*] Large scan detected ({total_ports} ports)")
                print(f"[*] Using batched mode: {batch_size} ports per batch, {max_workers} workers")
        elif total_ports > 5000:
            # Medium scan: moderate batching
            batch_size = 2500
            max_workers = min(75, self.max_workers)
        else:
            # Small scan: no batching needed
            batch_size = total_ports
            max_workers = self.max_workers
        
        if show_progress:
            print(f"[*] SYN scanning {target} - {total_ports} ports")
        
        start_time = time.time()
        results = []
        
        # Process in batches
        for batch_start in range(0, total_ports, batch_size):
            batch_end = min(batch_start + batch_size, total_ports)
            batch_ports = ports[batch_start:batch_end]
            
            if show_progress and total_ports > batch_size:
                print(f"[*] Batch {batch_start//batch_size + 1}/{(total_ports + batch_size - 1)//batch_size}: "
                      f"Scanning ports {batch_start + 1}-{batch_end}")
            
            # Scan this batch
            batch_results = self._scan_batch(target, batch_ports, max_workers, show_progress)
            results.extend(batch_results)
            
            # Brief pause between batches to let file descriptors close
            if batch_end < total_ports:
                time.sleep(0.1)
        
        duration = time.time() - start_time
        
        if show_progress:
            open_ports = [r for r in results if r['state'] == 'open']
            print(f"[+] Scan complete in {duration:.2f}s - {len(open_ports)} open ports found")
        
        return results
    
    def _scan_batch(self, target: str, ports: List[int], max_workers: int, show_progress: bool) -> List[Dict]:
        """
        Scan a batch of ports concurrently.
        
        Args:
            target: Target IP address
            ports: List of ports to scan in this batch
            max_workers: Maximum concurrent workers for this batch
            show_progress: Whether to show progress
            
        Returns:
            list: Results for this batch
        """
        batch_results = []
        
        # Use ThreadPoolExecutor for concurrent scanning
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all scan tasks for this batch
            future_to_port = {
                executor.submit(self.syn_scan_port, target, port): port
                for port in ports
            }
            
            # Process results as they complete
            completed = 0
            for future in as_completed(future_to_port):
                result = future.result()
                batch_results.append(result)
                
                completed += 1
                if show_progress and completed % 500 == 0:
                    print(f"[*] Progress: {completed}/{len(ports)} in current batch")
        
        return batch_results
    
    def scan_ports_fast(self, target: str, ports: List[int]) -> List[Dict]:
        """
        Fast scan returning only OPEN ports (filters closed/filtered).
        
        Args:
            target: Target IP address or hostname
            ports: List of port numbers to scan
            
        Returns:
            list: List of OPEN port results only
        """
        all_results = self.scan_ports(target, ports, show_progress=False)
        open_results = [r for r in all_results if r['state'] == 'open']
        return open_results
    
    def _get_service_name(self, port: int) -> str:
        """
        Get common service name for a port number.
        
        Args:
            port: Port number
            
        Returns:
            str: Service name or 'unknown'
        """
        try:
            return socket.getservbyport(port)
        except OSError:
            # Common ports not in getservbyport
            common_ports = {
                8080: 'http-proxy',
                8443: 'https-alt',
                8000: 'http-alt',
                3389: 'ms-wbt-server',
                5900: 'vnc',
                6379: 'redis',
                27017: 'mongodb',
                9200: 'elasticsearch',
                5432: 'postgresql',
                3632: 'distccd',
                8009: 'ajp13'
            }
            return common_ports.get(port, 'unknown')
    
    def get_statistics(self) -> Dict:
        """
        Get scanning statistics.
        
        Returns:
            dict: Statistics including packets sent/received, ports by state
        """
        return self.stats.copy()
    
    def reset_statistics(self):
        """Reset all statistics counters."""
        self.stats = {
            'sent': 0,
            'received': 0,
            'open': 0,
            'closed': 0,
            'filtered': 0
        }


class HybridScanner:
    """
    Hybrid scanner that combines SYN scanning with TCP connect fallback.
    
    Automatically uses SYN scanning when root privileges available,
    falls back to TCP connect otherwise.
    """
    
    def __init__(self, timeout: float = 1.0, max_workers: int = 100):
        """
        Initialize hybrid scanner.
        
        Args:
            timeout: Socket/packet timeout in seconds
            max_workers: Maximum concurrent operations
        """
        self.timeout = timeout
        self.max_workers = max_workers
        self.mode = None
        self.scanner = None
        
        # Try to initialize SYN scanner
        if self._can_use_syn():
            try:
                self.scanner = SYNScanner(timeout, max_workers)
                self.mode = "SYN"
            except (ImportError, PermissionError) as e:
                self.mode = "TCP"
                self._init_tcp_scanner()
        else:
            self.mode = "TCP"
            self._init_tcp_scanner()
    
    def _can_use_syn(self) -> bool:
        """Check if SYN scanning is available."""
        if not SCAPY_AVAILABLE:
            return False
        
        try:
            if hasattr(os, 'geteuid'):
                return os.geteuid() == 0
            else:
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    
    def _init_tcp_scanner(self):
        """Initialize TCP connect scanner as fallback."""
        # Placeholder - integrate with your existing TCP scanner
        self.scanner = None  # Use BlackPort's existing TCP scanner
    
    def scan_port(self, target: str, port: int) -> Dict:
        """
        Scan a single port using best available method.
        
        Args:
            target: Target IP or hostname
            port: Port number
            
        Returns:
            dict: Scan result
        """
        if self.mode == "SYN":
            return self.scanner.syn_scan_port(target, port)
        else:
            # Use existing TCP connect method
            return self._tcp_connect_scan(target, port)
    
    def _tcp_connect_scan(self, target: str, port: int) -> Dict:
        """
        Fallback TCP connect scan.
        
        Args:
            target: Target IP or hostname
            port: Port number
            
        Returns:
            dict: Scan result
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            result = sock.connect_ex((target, port))
            sock.close()
            
            if result == 0:
                return {
                    'port': port,
                    'state': 'open',
                    'service': socket.getservbyport(port) if port < 1024 else 'unknown',
                    'ttl': None,
                    'response_time': None
                }
            else:
                return {
                    'port': port,
                    'state': 'closed',
                    'service': None,
                    'ttl': None,
                    'response_time': None
                }
        except Exception as e:
            return {
                'port': port,
                'state': 'error',
                'service': None,
                'ttl': None,
                'response_time': None,
                'error': str(e)
            }
    
    def get_mode(self) -> str:
        """Get current scanning mode."""
        return self.mode


def check_syn_availability() -> Tuple[bool, str]:
    """
    Check if SYN scanning is available on this system.
    
    Returns:
        tuple: (is_available: bool, message: str)
    """
    if not SCAPY_AVAILABLE:
        return False, "Scapy not installed. Install with: pip install scapy"
    
    try:
        if hasattr(os, 'geteuid'):
            has_root = os.geteuid() == 0
        else:
            import ctypes
            has_root = ctypes.windll.shell32.IsUserAnAdmin() != 0
        
        if not has_root:
            if sys.platform.startswith('linux') or sys.platform == 'darwin':
                return False, "Root privileges required. Run with: sudo python main.py --syn ..."
            else:
                return False, "Administrator privileges required. Run terminal as Administrator"
        
        return True, "SYN scanning available"
        
    except Exception as e:
        return False, f"Cannot check privileges: {e}"


# Example usage and testing
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="SYN Scanner Test")
    parser.add_argument('target', help='Target IP or hostname')
    parser.add_argument('--ports', default='22,80,443', help='Comma-separated ports')
    parser.add_argument('--timeout', type=float, default=1.0, help='Timeout in seconds')
    parser.add_argument('--workers', type=int, default=100, help='Max concurrent scans')
    
    args = parser.parse_args()
    
    # Parse ports
    ports = [int(p.strip()) for p in args.ports.split(',')]
    
    # Check availability
    available, message = check_syn_availability()
    print(f"[*] SYN Scanning: {message}")
    
    if not available:
        print("[!] Exiting...")
        sys.exit(1)
    
    # Initialize scanner
    scanner = SYNScanner(timeout=args.timeout, max_workers=args.workers)
    
    # Perform scan
    print(f"\n[*] Scanning {args.target}...")
    results = scanner.scan_ports(args.target, ports)
    
    # Display results
    print("\n[+] Results:")
    print(f"{'Port':<8} {'State':<12} {'Service':<20} {'TTL':<6} {'Response (ms)'}")
    print("-" * 70)
    
    for result in sorted(results, key=lambda x: x['port']):
        if result['state'] == 'open':
            print(f"{result['port']:<8} {result['state']:<12} {result['service']:<20} "
                  f"{result['ttl'] or 'N/A':<6} {result['response_time'] or 'N/A'}")
    
    # Statistics
    stats = scanner.get_statistics()
    print(f"\n[*] Statistics:")
    print(f"    Packets sent: {stats['sent']}")
    print(f"    Responses: {stats['received']}")
    print(f"    Open: {stats['open']}")
    print(f"    Closed: {stats['closed']}")
    print(f"    Filtered: {stats['filtered']}")
