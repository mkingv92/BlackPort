# plugins/udp_dns_plugin.py
from .plugin_base import PluginBase
import socket
import struct

class UDPDNSPlugin(PluginBase):
    name = "DNS Security Check"
    applicable_services = ["DNS"]

    def run(self, target, port, banner=None):
        # Works for both TCP/53 and UDP/53
        notes = []
        risk = "LOW"
        exploit_hint = None

        # --- Step 1: Test for zone transfer (AXFR) ---
        axfr_result = self._test_zone_transfer(target, port)
        if axfr_result == "allowed":
            notes.append("CRITICAL: Zone transfer (AXFR) allowed — full DNS zone data exposed to any requester.")
            risk = "CRITICAL"
            exploit_hint = f"Extract zone: dig @{target} axfr . OR dnsrecon -t axfr -d target.com -n {target}"
        elif axfr_result == "refused":
            notes.append("Zone transfer (AXFR) refused — correctly restricted.")

        # --- Step 2: Test for DNS recursion (open resolver) ---
        recursion_result = self._test_recursion(target, port)
        if recursion_result == "open":
            notes.append("Open DNS resolver detected — can be abused for amplification DDoS attacks.")
            if risk == "LOW":
                risk = "MEDIUM"
            exploit_hint = exploit_hint or f"DNS amplification: nmap -sU -p 53 --script dns-recursion {target}"
        elif recursion_result == "closed":
            notes.append("Recursion disabled or restricted — correctly configured.")

        # --- Step 3: Test for version disclosure ---
        version = self._get_dns_version(target, port)
        if version:
            notes.append(f"DNS version disclosed: {version} — consider hiding with version.bind 'none'.")
            if risk == "LOW":
                risk = "LOW"  # info only

        if not notes:
            notes.append("DNS service detected — no critical misconfigurations found.")

        return {
            "plugin": self.name,
            "risk": risk,
            "notes": " | ".join(notes),
            "exploit_hint": exploit_hint
        }

    def _build_dns_query(self, qtype, qname=b"\x00", chaos=False):
        """Build a minimal DNS query packet."""
        tid = b"\xab\xcd"
        flags = b"\x01\x00"  # standard query, recursion desired
        counts = b"\x00\x01\x00\x00\x00\x00\x00\x00"
        qclass = b"\x00\x03" if chaos else b"\x00\x01"  # CHAOS or IN
        return tid + flags + counts + qname + qtype + qclass

    def _test_zone_transfer(self, target, port):
        """Attempt AXFR zone transfer over TCP (AXFR requires TCP)."""
        try:
            # AXFR query for root zone "."
            query = (
                b"\xab\xcd\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
                b"\x00"           # root zone
                b"\x00\xfc"       # Type: AXFR
                b"\x00\x01"       # Class: IN
            )
            # TCP DNS: prefix with 2-byte length
            tcp_query = struct.pack(">H", len(query)) + query

            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(3)
                s.connect((target, 53))
                s.sendall(tcp_query)
                resp = s.recv(1024)
                if len(resp) > 4:
                    # Check RCODE in response flags (byte 3, lower 4 bits)
                    rcode = resp[5] & 0x0F if len(resp) > 5 else 0xFF
                    if rcode == 0:
                        return "allowed"
                    elif rcode == 5:  # REFUSED
                        return "refused"
                    elif rcode == 9:  # NOTAUTH
                        return "refused"
        except Exception:
            pass
        return "unknown"

    def _test_recursion(self, target, port):
        """Test if the DNS server will resolve external names (open resolver)."""
        try:
            # Query for google.com A record
            query = (
                b"\x12\x34"       # Transaction ID
                b"\x01\x00"       # Flags: recursion desired
                b"\x00\x01\x00\x00\x00\x00\x00\x00"
                b"\x06google\x03com\x00"
                b"\x00\x01"       # Type: A
                b"\x00\x01"       # Class: IN
            )
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(3)
                s.sendto(query, (target, port))
                resp, _ = s.recvfrom(512)
                if len(resp) > 6:
                    rcode = resp[3] & 0x0F
                    ancount = struct.unpack(">H", resp[6:8])[0]
                    if rcode == 0 and ancount > 0:
                        return "open"
                    elif rcode == 5:
                        return "closed"
        except Exception:
            pass
        return "unknown"

    def _get_dns_version(self, target, port):
        """Query version.bind in CHAOS class."""
        try:
            query = (
                b"\xab\xce"
                b"\x01\x00"
                b"\x00\x01\x00\x00\x00\x00\x00\x00"
                b"\x07version\x04bind\x00"
                b"\x00\x10"       # Type: TXT
                b"\x00\x03"       # Class: CHAOS
            )
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(2)
                s.sendto(query, (target, port))
                resp, _ = s.recvfrom(512)
                # Try to find printable version string in response
                import re
                text = resp.decode(errors="ignore")
                matches = re.findall(r'[\x20-\x7e]{4,}', text)
                for m in matches:
                    if any(x in m.lower() for x in ["bind", "named", "unbound", "9.", "8."]):
                        return m.strip()
        except Exception:
            pass
        return None
