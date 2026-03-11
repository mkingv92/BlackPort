# =====================================================================
# File: blackport/udp_scanner.py
# Notes:
# - This file is part of the BlackPort project.
# - Use only on hosts/networks you own or have explicit permission to test.
# - UDP scanning requires root/administrator privileges on most systems.
# =====================================================================

import socket
import struct
import time
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style, init
init(autoreset=True)

# High-value UDP ports with protocol probes
UDP_PORTS = {
    53:   ("DNS",        "Domain Name System"),
    67:   ("DHCP",       "DHCP Server"),
    68:   ("DHCP",       "DHCP Client"),
    69:   ("TFTP",       "Trivial File Transfer"),
    123:  ("NTP",        "Network Time Protocol"),
    137:  ("NetBIOS-NS", "NetBIOS Name Service"),
    138:  ("NetBIOS-DG", "NetBIOS Datagram"),
    161:  ("SNMP",       "Simple Network Management"),
    162:  ("SNMP-Trap",  "SNMP Trap"),
    500:  ("IKE",        "IPSec Key Exchange"),
    514:  ("Syslog",     "Syslog"),
    1900: ("UPnP",       "Universal Plug and Play"),
    4500: ("NAT-T",      "IPSec NAT Traversal"),
    5353: ("mDNS",       "Multicast DNS"),
    5355: ("LLMNR",      "Link-Local Multicast Name Resolution"),
}

# Protocol-specific probe payloads
UDP_PROBES = {
    53: (
        b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        b"\x07version\x04bind\x00"
        b"\x00\x10\x00\x03"
    ),
    161: (
        b"\x30\x26"
        b"\x02\x01\x00"
        b"\x04\x06public"
        b"\xa0\x19"
        b"\x02\x04\x00\x00\x00\x01"
        b"\x02\x01\x00"
        b"\x02\x01\x00"
        b"\x30\x0b"
        b"\x30\x09"
        b"\x06\x05\x2b\x06\x01\x02\x01"
        b"\x05\x00"
    ),
    123: b"\x1b" + b"\x00" * 47,
    137: (
        b"\xab\xcd\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        b"\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00"
        b"\x00\x21\x00\x01"
    ),
    1900: (
        b"M-SEARCH * HTTP/1.1\r\n"
        b"HOST: 239.255.255.250:1900\r\n"
        b'MAN: "ssdp:discover"\r\n'
        b"MX: 1\r\nST: ssdp:all\r\n\r\n"
    ),
    5353: (
        b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        b"\x09_services\x07_dns-sd\x04_udp\x05local\x00"
        b"\x00\x0c\x00\x01"
    ),
    69: (
        b"\x00\x01/etc/passwd\x00netascii\x00"
    ),
}

HIGH_RISK_UDP  = {161, 69, 137, 5353, 1900}
MEDIUM_RISK_UDP = {53, 123, 500, 4500, 5355}


class UDPScanner:
    def __init__(self, target, timeout=2, threads=50, verbose=False):
        self.target  = target
        self.timeout = timeout
        self.threads = threads
        self.verbose = verbose   # if True, show open|filtered ports too
        self.results = []

    def scan_port(self, port):
        service, desc = UDP_PORTS.get(port, ("Unknown", ""))
        probe = UDP_PROBES.get(port, b"\x00" * 4)

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(self.timeout)
                s.sendto(probe, (self.target, port))

                try:
                    data, addr = s.recvfrom(4096)
                    banner = self._parse_response(port, data)
                    risk   = self._assess_risk(port, data)
                    return {
                        "port": port, "protocol": "UDP", "service": service,
                        "state": "open", "banner": banner, "risk": risk,
                        "raw": data[:64].hex(), "plugins": []
                    }

                except socket.timeout:
                    # Only surface open|filtered if verbose OR high-value port
                    if self.verbose and (port in HIGH_RISK_UDP or port in MEDIUM_RISK_UDP):
                        return {
                            "port": port, "protocol": "UDP", "service": service,
                            "state": "open|filtered", "banner": None,
                            "risk": "LOW", "raw": None, "plugins": []
                        }
                    return None

        except PermissionError:
            print(f"\n[!] UDP scanning requires root privileges. Run with sudo.")
            return None
        except OSError:
            return None
        except Exception:
            return None

    def _parse_response(self, port, data):
        try:
            if port == 53:
                return f"DNS response ({len(data)} bytes)"
            elif port == 161:
                import re
                text = data.decode(errors="ignore")
                strings = re.findall(r'[ -~]{4,}', text)
                return " | ".join(strings[:3]) if strings else f"SNMP response ({len(data)} bytes)"
            elif port == 123:
                stratum = data[1] if len(data) >= 2 else "?"
                return f"NTP stratum {stratum}"
            elif port == 137:
                return f"NetBIOS response ({len(data)} bytes)"
            elif port == 1900:
                text = data.decode(errors="ignore")
                lines = [l.strip() for l in text.split("\n") if l.strip()]
                return " | ".join(lines[:3])
            elif port == 5353:
                return f"mDNS response ({len(data)} bytes)"
            elif port == 69:
                if len(data) >= 2:
                    opcode = struct.unpack(">H", data[:2])[0]
                    if opcode == 3:
                        return "TFTP DATA — file read succeeded (unauthenticated access)"
                    elif opcode == 5:
                        return f"TFTP ERROR: {data[4:].decode(errors='ignore').strip(chr(0))}"
                return f"TFTP response ({len(data)} bytes)"
            else:
                text = data.decode(errors="ignore").strip()
                return text[:100] if text else f"{len(data)} bytes"
        except Exception:
            return f"{len(data)} bytes"

    def _assess_risk(self, port, data):
        if port == 161:
            return "HIGH"
        elif port == 69:
            if len(data) >= 2 and struct.unpack(">H", data[:2])[0] == 3:
                return "CRITICAL"
            return "MEDIUM"
        elif port == 137:
            return "MEDIUM"
        elif port in {53, 123}:
            return "LOW"
        elif port in {1900, 500, 4500, 5353, 5355}:
            return "MEDIUM"
        return "LOW"

    def scan(self):
        ports   = list(UDP_PORTS.keys())
        total   = len(ports)
        scanned = 0

        print(f"\n{Fore.CYAN}[UDP] Scanning {total} high-value UDP ports...{Style.RESET_ALL}\n")

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.scan_port, p): p for p in ports}
            for future in as_completed(futures):
                result = future.result()
                scanned += 1
                print(f"UDP Progress: {scanned}/{total}", end="\r")
                if result:
                    self.results.append(result)

        print()

        risk_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        self.results = sorted(
            self.results,
            key=lambda x: (risk_order.get(x["risk"], 4), x["port"])
        )
        return self.results

    def print_results(self, color_risk_fn):
        if not self.results:
            print(f"{Fore.CYAN}[UDP]{Style.RESET_ALL} No responsive UDP ports found.")
            return

        open_ports = [r for r in self.results if r["state"] == "open"]
        filtered   = [r for r in self.results if r["state"] == "open|filtered"]

        print(f"\n{Fore.CYAN}===== UDP RESULTS ====={Style.RESET_ALL}")
        print(f"Responsive: {Fore.GREEN}{len(open_ports)} open{Style.RESET_ALL}", end="")
        if filtered:
            suffix = "" if self.verbose else " (use --udp-verbose to show)"
            print(f" | {Fore.YELLOW}{len(filtered)} open|filtered{Style.RESET_ALL}{suffix}", end="")
        print("\n")

        # Default: only show confirmed open ports
        # Verbose: show both
        to_print = self.results if self.verbose else open_ports

        if not to_print:
            print(f"  {Fore.YELLOW}No confirmed open UDP ports. Use --udp-verbose to show open|filtered ports.{Style.RESET_ALL}")
            return

        for r in to_print:
            risk        = r["risk"]
            colored_risk = color_risk_fn(risk)
            icon = {"CRITICAL": "💀", "HIGH": "🔥", "MEDIUM": "⚠️"}.get(risk, "✅")

            if r["state"] == "open|filtered":
                state_str = f"{Fore.YELLOW}[open|filtered]{Style.RESET_ALL}"
            else:
                state_str = f"{Fore.GREEN}[open]{Style.RESET_ALL}"

            print(f"[UDP] {r['port']}/udp {r['service']:<14} {state_str} {icon} {colored_risk}")

            if r.get("banner"):
                print(f"      Banner: {r['banner']}")

            for p in r.get("plugins", []):
                if p:
                    print(f"      🔌 {p['plugin']} [{p['risk']}]: {p['notes']}")
                    if p.get("exploit_hint"):
                        print(f"         💡 {p['exploit_hint']}")
