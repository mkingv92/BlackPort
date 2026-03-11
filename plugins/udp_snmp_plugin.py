# plugins/udp_snmp_plugin.py
from .plugin_base import PluginBase
import socket
import re

# Common SNMP community strings to test
COMMON_COMMUNITIES = [
    b"public",
    b"private",
    b"admin",
    b"community",
    b"manager",
    b"monitor",
    b"snmp",
    b"cisco",
    b"secret",
    b"default",
]

def build_snmp_get(community, oid_bytes):
    """Build a minimal SNMPv1 GetRequest packet."""
    oid_seq = b"\x30" + bytes([len(oid_bytes)]) + oid_bytes
    varbind = b"\x30" + bytes([len(oid_seq) + 2]) + oid_seq + b"\x05\x00"
    varbind_list = b"\x30" + bytes([len(varbind)]) + varbind
    pdu = (
        b"\xa0"                          # GetRequest-PDU
        + bytes([len(varbind_list) + 12])
        + b"\x02\x04\x00\x00\x00\x01"   # request-id
        + b"\x02\x01\x00"               # error-status
        + b"\x02\x01\x00"               # error-index
        + varbind_list
    )
    community_field = b"\x04" + bytes([len(community)]) + community
    msg = b"\x02\x01\x00" + community_field + pdu  # version + community + PDU
    return b"\x30" + bytes([len(msg)]) + msg

# OID for sysDescr: 1.3.6.1.2.1.1.1.0
SYSDESCR_OID = b"\x06\x08\x2b\x06\x01\x02\x01\x01\x01\x00"


class UDPSNMPPlugin(PluginBase):
    name = "SNMP Security Check"
    applicable_services = ["SNMP", "SNMP-Trap"]

    def run(self, target, port, banner=None):
        if port not in {161, 162}:
            return None

        notes = []
        risk = "MEDIUM"  # SNMP exposed is always at least MEDIUM
        exploit_hint = None

        notes.append("SNMP service detected — can expose full device configuration if community string guessed.")

        # --- Step 1: Test common community strings ---
        cracked = self._brute_community(target, port)
        if cracked:
            community, sysdescr = cracked
            notes.append(f"CRITICAL: Community string '{community.decode()}' accepted — full SNMP read access.")
            if sysdescr:
                notes.append(f"sysDescr: {sysdescr[:120]}")
            risk = "CRITICAL"
            exploit_hint = (
                f"Enumerate with: snmpwalk -v1 -c {community.decode()} {target} . "
                f"OR: snmp-check {target} -c {community.decode()}"
            )
        else:
            notes.append("Common community strings rejected — non-default string in use.")
            exploit_hint = f"Brute-force: onesixtyone -c /usr/share/doc/onesixtyone/dict.txt {target}"

        # --- Step 2: Check for SNMPv3 (more secure) ---
        v3_result = self._probe_snmpv3(target, port)
        if v3_result:
            notes.append("SNMPv3 also available — check for weak auth/privacy settings.")

        # --- Step 3: Remediation ---
        notes.append("Remediation: Disable SNMPv1/v2c, use SNMPv3 with auth+privacy, restrict to management IPs.")

        return {
            "plugin": self.name,
            "risk": risk,
            "notes": " | ".join(notes),
            "exploit_hint": exploit_hint
        }

    def _brute_community(self, target, port):
        """Test common SNMP community strings and return (community, sysdescr) if found."""
        for community in COMMON_COMMUNITIES:
            try:
                pkt = build_snmp_get(community, SYSDESCR_OID)
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.settimeout(2)
                    s.sendto(pkt, (target, port))
                    try:
                        resp, _ = s.recvfrom(4096)
                        # Check for SNMP response (starts with 0x30, no error)
                        if resp and resp[0] == 0x30:
                            # Try to extract sysDescr text
                            text = resp.decode(errors="ignore")
                            strings = re.findall(r'[ -~]{6,}', text)
                            sysdescr = " | ".join(s for s in strings[:2] if len(s) > 5)
                            return (community, sysdescr)
                    except socket.timeout:
                        continue
            except Exception:
                continue
        return None

    def _probe_snmpv3(self, target, port):
        """Send a minimal SNMPv3 discovery probe."""
        try:
            # SNMPv3 GetRequest with empty credentials (discovery)
            v3_probe = (
                b"\x30\x3a"
                b"\x02\x01\x03"              # version: 3
                b"\x30\x0f"                  # msgGlobalData
                b"\x02\x03\x00\xe2\x04"      # msgID
                b"\x02\x02\x05\xdc"          # msgMaxSize
                b"\x04\x01\x04"              # msgFlags: reportable
                b"\x02\x01\x03"              # msgSecurityModel: USM
                b"\x04\x10"                  # msgSecurityParameters (empty)
                b"\x30\x0e\x04\x00\x02\x01\x00\x02\x01\x00\x04\x00\x04\x00\x04\x00"
                b"\x30\x10"                  # scopedPDU
                b"\x04\x00\x04\x00"
                b"\xa0\x0a\x02\x04\x5f\x8b\x37\x62\x02\x01\x00\x02\x01\x00\x30\x00"
            )
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(2)
                s.sendto(v3_probe, (target, port))
                resp, _ = s.recvfrom(1024)
                if resp and resp[0] == 0x30:
                    return True
        except Exception:
            pass
        return False
