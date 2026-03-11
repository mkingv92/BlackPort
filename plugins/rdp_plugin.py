# plugins/rdp_plugin.py
from .plugin_base import PluginBase
import socket
import struct

class RDPPlugin(PluginBase):
    name = "RDP Security Check"
    applicable_services = ["RDP"]

    # RDP connection request (X.224 COTP + RDP negotiation)
    RDP_NEG_REQUEST = (
        b"\x03\x00\x00\x13"  # TPKT header
        b"\x0e\xe0\x00\x00\x00\x00\x00"  # X.224 COTP
        b"\x01\x00\x08\x00\x00\x00\x00"  # RDP negotiation request
    )

    def run(self, target, port, banner=None):
        notes = []
        risk = "HIGH"  # RDP exposed is always at least HIGH
        exploit_hint = None

        notes.append("RDP exposed — remote desktop access surface is high-value attack target.")

        # --- Step 1: Probe RDP for NLA vs classic auth ---
        auth_type = self._probe_rdp_auth(target, port)

        if auth_type == "nla":
            notes.append("Network Level Authentication (NLA) enabled — credential required before session. Reduces attack surface.")
            risk = "MEDIUM"
        elif auth_type == "classic":
            notes.append("Classic RDP authentication (no NLA) — login screen exposed before auth, vulnerable to BlueKeep-class exploits.")
            risk = "CRITICAL"
            exploit_hint = "BlueKeep check: msfconsole -q -x 'use auxiliary/scanner/rdp/cve_2019_0708_bluekeep; set RHOSTS {target}; run'"
        elif auth_type == "ssl":
            notes.append("SSL/TLS RDP detected but NLA status unclear — may still be vulnerable to credential brute-force.")

        # --- Step 2: Flag known critical RDP CVEs based on context ---
        notes.append("Check for: CVE-2019-0708 (BlueKeep), CVE-2019-1182 (DejaBlue), CVE-2012-0002 (MS12-020).")

        if risk in ["HIGH", "CRITICAL"]:
            exploit_hint = exploit_hint or (
                f"Brute-force: hydra -l administrator -P /usr/share/wordlists/rockyou.txt rdp://{target} "
                f"OR use Metasploit: auxiliary/scanner/rdp/cve_2019_0708_bluekeep"
            )

        return {
            "plugin": self.name,
            "risk": risk,
            "notes": " | ".join(notes),
            "exploit_hint": exploit_hint
        }

    def _probe_rdp_auth(self, target, port):
        """
        Send an RDP negotiation request and parse the response to determine
        whether NLA, classic, or SSL auth is in use.
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(3)
                s.connect((target, port))
                s.sendall(self.RDP_NEG_REQUEST)
                data = s.recv(1024)

                if len(data) >= 11:
                    # Parse RDP negotiation response
                    # Byte 11 is the selected protocol flags
                    neg_type = data[7]   # 0x02 = Negotiation Response
                    if neg_type == 0x02:
                        protocol = data[11] if len(data) > 11 else 0
                        if protocol & 0x02:  # CredSSP / NLA
                            return "nla"
                        elif protocol & 0x01:  # SSL
                            return "ssl"
                        else:
                            return "classic"

        except Exception:
            pass

        return "unknown"
