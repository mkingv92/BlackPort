"""
MayheM-Sec Added

UDP scanning engine for BlackPort.

This module performs non-destructive UDP discovery with protocol-aware probes,
retries, conservative state classification, and JSON reporting. It is intended
for authorized security assessment only.
"""

from __future__ import annotations

import argparse
import errno
import json
import socket
import struct
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path


# MayheM-Sec Added: common UDP service names used in reports and the GUI.
UDP_SERVICES = {
    53: "DNS", 67: "DHCP Server", 68: "DHCP Client", 69: "TFTP",
    88: "Kerberos", 111: "RPCbind", 123: "NTP", 137: "NetBIOS Name Service",
    138: "NetBIOS Datagram", 161: "SNMP", 162: "SNMP Trap", 389: "LDAP",
    500: "IKE/IPsec", 514: "Syslog", 520: "RIP", 623: "IPMI/RMCP",
    1434: "MS SQL Browser", 1701: "L2TP", 1812: "RADIUS Auth",
    1813: "RADIUS Accounting", 1900: "SSDP/UPnP", 4500: "IPsec NAT-T",
    4789: "VXLAN", 5353: "mDNS", 5355: "LLMNR", 11211: "Memcached",
}

# MayheM-Sec Added: practical UDP profiles. Full means 1-65535 and is explicit.
TOP_25_UDP = [
    53, 67, 68, 69, 88, 111, 123, 137, 138, 161, 162, 389, 500,
    514, 520, 623, 1434, 1701, 1812, 1813, 1900, 4500, 4789, 5353, 5355,
]
TOP_50_UDP = sorted(set(TOP_25_UDP + [
    7, 9, 17, 19, 37, 42, 49, 80, 135, 177, 427, 443, 631, 1194, 1645,
    1646, 2000, 2049, 2222, 3478, 5060, 5683, 10000, 11211, 27015,
]))
TOP_100_UDP = sorted(set(TOP_50_UDP + [
    13, 43, 81, 98, 101, 104, 105, 107, 109, 110, 115, 117, 118, 119,
    121, 156, 158, 194, 213, 264, 369, 370, 407, 444, 445, 497, 593,
    750, 751, 752, 998, 999, 1023, 1024, 1080, 1649, 1718, 1719, 1761,
    1782, 1953, 2001, 3283, 3456, 3702, 4000, 4444, 5000, 5061, 5351,
    6000, 7001, 8000, 8080, 9200, 10080, 17185, 20031, 31337, 32768,
]))


def _dns_probe() -> bytes:
    transaction_id = 0x4242
    flags = 0x0100
    header = struct.pack("!HHHHHH", transaction_id, flags, 1, 0, 0, 0)
    question = b"\x00" + struct.pack("!HH", 2, 1)
    return header + question


def _ntp_probe() -> bytes:
    return bytes([0x23]) + (b"\x00" * 47)


def _ssdp_probe() -> bytes:
    return (
        b"M-SEARCH * HTTP/1.1\r\n"
        b"HOST: 239.255.255.250:1900\r\n"
        b"MAN: \"ssdp:discover\"\r\n"
        b"MX: 1\r\n"
        b"ST: ssdp:all\r\n\r\n"
    )


def _mdns_probe() -> bytes:
    name = b"\x09_services\x07_dns-sd\x04_udp\x05local\x00"
    return struct.pack("!HHHHHH", 0, 0, 1, 0, 0, 0) + name + struct.pack("!HH", 12, 1)


def _llmnr_probe() -> bytes:
    name = b"\x09blackport\x00"
    return struct.pack("!HHHHHH", 0x4242, 0, 1, 0, 0, 0) + name + struct.pack("!HH", 1, 1)


def _memcached_probe() -> bytes:
    return b"version\r\n"


# MayheM-Sec Added: protocol-aware packets improve UDP confidence without exploitation.
UDP_PROBES = {
    53: _dns_probe(),
    123: _ntp_probe(),
    1900: _ssdp_probe(),
    5353: _mdns_probe(),
    5355: _llmnr_probe(),
    11211: _memcached_probe(),
}


class UDPScanner:
    """MayheM-Sec Added: concurrent UDP discovery with conservative state labels."""

    def __init__(self, target: str, timeout: float = 1.0, retries: int = 2, workers: int = 80):
        self.target_name = target
        self.target = socket.gethostbyname(target)
        self.timeout = max(0.1, float(timeout))
        self.retries = max(1, int(retries))
        self.workers = max(1, min(int(workers), 256))

    def _probe_payload(self, port: int) -> bytes:
        return UDP_PROBES.get(port, b"\x00")

    def scan_port(self, port: int) -> dict:
        service = UDP_SERVICES.get(port, "Unknown")
        payload = self._probe_payload(port)
        latency_ms = None

        for attempt in range(1, self.retries + 1):
            started = time.perf_counter()
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                sock.settimeout(self.timeout)
                sock.connect((self.target, port))
                sock.send(payload)
                data = sock.recv(4096)
                latency_ms = round((time.perf_counter() - started) * 1000, 2)
                return {
                    "port": port, "protocol": "udp", "state": "open",
                    "service": service, "confidence": 100, "attempts": attempt,
                    "latency_ms": latency_ms, "response_bytes": len(data),
                    "evidence_hex": data[:160].hex(),
                    "probe": "protocol-aware" if port in UDP_PROBES else "generic",
                }
            except ConnectionRefusedError:
                return {
                    "port": port, "protocol": "udp", "state": "closed",
                    "service": service, "confidence": 95, "attempts": attempt,
                    "latency_ms": round((time.perf_counter() - started) * 1000, 2),
                    "response_bytes": 0, "evidence_hex": None,
                    "probe": "protocol-aware" if port in UDP_PROBES else "generic",
                }
            except OSError as exc:
                if getattr(exc, "errno", None) == errno.ECONNREFUSED:
                    return {
                        "port": port, "protocol": "udp", "state": "closed",
                        "service": service, "confidence": 95, "attempts": attempt,
                        "latency_ms": round((time.perf_counter() - started) * 1000, 2),
                        "response_bytes": 0, "evidence_hex": None,
                        "probe": "protocol-aware" if port in UDP_PROBES else "generic",
                    }
            except socket.timeout:
                pass
            finally:
                sock.close()

        # MayheM-Sec Added: silence is ambiguous for UDP and is never called open.
        return {
            "port": port, "protocol": "udp", "state": "open|filtered",
            "service": service, "confidence": 35, "attempts": self.retries,
            "latency_ms": latency_ms, "response_bytes": 0, "evidence_hex": None,
            "probe": "protocol-aware" if port in UDP_PROBES else "generic",
        }

    def scan(self, ports: list[int], include_closed: bool = False, show_progress: bool = True) -> list[dict]:
        ports = sorted({int(p) for p in ports if 1 <= int(p) <= 65535})
        results: list[dict] = []
        total = len(ports)
        done = 0

        with ThreadPoolExecutor(max_workers=min(self.workers, max(1, total))) as pool:
            future_to_port = {pool.submit(self.scan_port, p): p for p in ports}
            for future in as_completed(future_to_port):
                result = future.result()
                done += 1
                if show_progress:
                    print(f"UDP progress: {done}/{total} ({done / total * 100:.1f}%)", end="\r")
                if include_closed or result["state"] != "closed":
                    results.append(result)

        if show_progress:
            print()
        state_order = {"open": 0, "open|filtered": 1, "filtered": 2, "closed": 3}
        return sorted(results, key=lambda r: (state_order.get(r["state"], 9), r["port"]))


def resolve_ports(args: argparse.Namespace) -> list[int]:
    if args.top_25:
        return TOP_25_UDP
    if args.top_50:
        return TOP_50_UDP
    if args.top_100:
        return TOP_100_UDP
    if args.full:
        return list(range(1, 65536))
    if args.start_port is not None and args.end_port is not None:
        if args.start_port < 1 or args.end_port > 65535 or args.start_port > args.end_port:
            raise ValueError("Invalid UDP port range")
        return list(range(args.start_port, args.end_port + 1))
    return TOP_25_UDP


def _safe_target_name(target: str) -> str:
    return "".join(ch if ch.isalnum() or ch in ".-_" else "_" for ch in target)


def write_json_report(target: str, duration: float, results: list[dict], output_dir: str) -> Path:
    """MayheM-Sec Added: persist UDP findings alongside BlackPort reports."""
    directory = Path(output_dir).expanduser()
    directory.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = directory / f"blackport_{_safe_target_name(target)}_{stamp}_udp.json"
    payload = {
        "target": target,
        "protocol": "udp",
        "duration": duration,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "results": results,
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


def main() -> None:
    parser = argparse.ArgumentParser(description="BlackPort UDP scanner - MayheM-Sec Added")
    parser.add_argument("target", help="Target IP or hostname")
    parser.add_argument("start_port", type=int, nargs="?")
    parser.add_argument("end_port", type=int, nargs="?")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--top-25", action="store_true", help="Scan 25 common UDP services")
    group.add_argument("--top-50", action="store_true", help="Scan 50 common UDP services")
    group.add_argument("--top-100", action="store_true", help="Scan 100 common UDP services")
    group.add_argument("--full", action="store_true", help="Scan UDP ports 1-65535")
    parser.add_argument("--timeout", type=float, default=1.0)
    parser.add_argument("--retries", type=int, default=2)
    parser.add_argument("--workers", type=int, default=80)
    parser.add_argument("--include-closed", action="store_true")
    parser.add_argument("--output-dir", default="reports")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    ports = resolve_ports(args)
    scanner = UDPScanner(args.target, timeout=args.timeout, retries=args.retries, workers=args.workers)
    started = time.time()
    results = scanner.scan(ports, include_closed=args.include_closed, show_progress=not args.json)
    duration = round(time.time() - started, 2)
    report = write_json_report(args.target, duration, results, args.output_dir)

    if args.json:
        print(json.dumps({"target": args.target, "protocol": "udp", "duration": duration, "report": str(report), "results": results}, indent=2))
        return

    print(f"\nUDP scan complete: {args.target} in {duration}s")
    for result in results:
        print(f"{result['port']:>5}/udp  {result['state']:<13} {result['service']:<24} confidence={result['confidence']}%")
    print(f"[MayheM-Sec Added] UDP report: {report}")


if __name__ == "__main__":
    main()
