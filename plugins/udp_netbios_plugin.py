# plugins/udp_netbios_plugin.py
from .plugin_base import PluginBase
import socket
import struct

class UDPNetBIOSPlugin(PluginBase):
    name = "NetBIOS Enumeration"
    applicable_services = ["NetBIOS-NS", "NetBIOS"]

    def run(self, target, port, banner=None):
        if port not in {137, 138, 139}:
            return None

        notes = []
        risk = "MEDIUM"
        exploit_hint = None

        # --- Step 1: Send NetBIOS Node Status Request and parse response ---
        info = self._node_status(target)

        if info:
            names     = info.get("names", [])
            mac       = info.get("mac", "")
            workgroup = info.get("workgroup", "")
            hostname  = info.get("hostname", "")

            if hostname:
                notes.append(f"Hostname: {hostname}")
            if workgroup:
                notes.append(f"Workgroup/Domain: {workgroup}")
            if mac and mac != "00:00:00:00:00:00":
                notes.append(f"MAC address: {mac}")
            if names:
                notes.append(f"NetBIOS names: {', '.join(names[:6])}")

            notes.append("NetBIOS exposes hostname, workgroup, and MAC — useful for network mapping and targeting.")
            risk = "MEDIUM"
            exploit_hint = (
                f"Enumerate further: nbtscan {target} "
                f"OR nmap -sU -p 137 --script nbstat {target}"
            )
        else:
            notes.append("NetBIOS port responding but node status request returned no parseable data.")
            notes.append("Try: nbtscan {target} for manual enumeration.")

        return {
            "plugin": self.name,
            "risk": risk,
            "notes": " | ".join(notes),
            "exploit_hint": exploit_hint
        }

    def _node_status(self, target):
        """
        Send a NetBIOS Node Status Request (NBSTAT) and parse the response.
        Returns dict with hostname, workgroup, names, mac — or None on failure.
        """
        try:
            # NetBIOS Node Status Request
            # Wildcard name "*" encoded as 32 'CA' nibble pairs
            request = (
                b"\xab\xcd"          # Transaction ID
                b"\x00\x00"          # Flags: query
                b"\x00\x01"          # Questions: 1
                b"\x00\x00"          # Answer RRs
                b"\x00\x00"          # Authority RRs
                b"\x00\x00"          # Additional RRs
                b"\x20"              # Name length: 32
                b"CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"  # Wildcard "*" encoded
                b"\x00"              # Name terminator
                b"\x00\x21"          # Type: NBSTAT
                b"\x00\x01"          # Class: IN
            )

            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(3)
                s.sendto(request, (target, 137))
                data, _ = s.recvfrom(4096)

            return self._parse_node_status(data)

        except Exception:
            return None

    def _parse_node_status(self, data):
        """Parse a NetBIOS NBSTAT response into useful fields."""
        try:
            # Response header is 12 bytes, then name entries start
            if len(data) < 57:
                return None

            # Number of names is at offset 56
            num_names = data[56]
            if num_names == 0 or len(data) < 57 + num_names * 18:
                return None

            names     = []
            hostname  = ""
            workgroup = ""

            for i in range(num_names):
                offset = 57 + i * 18
                # Name is 15 bytes, type is byte 15, flags are bytes 16-17
                raw_name = data[offset:offset + 15].decode(errors="ignore").rstrip()
                name_type = data[offset + 15]
                flags = struct.unpack(">H", data[offset + 16:offset + 18])[0]

                # Skip group names with <1e> or <00> type for workgroup detection
                is_group = bool(flags & 0x8000)

                clean = raw_name.strip()
                if clean:
                    names.append(f"{clean}<{name_type:02x}>")

                # Hostname: type 0x00, not a group
                if name_type == 0x00 and not is_group and not hostname:
                    hostname = clean

                # Workgroup/domain: type 0x00, is a group
                if name_type == 0x00 and is_group and not workgroup:
                    workgroup = clean

                # Also catch domain controller name type 0x1c
                if name_type == 0x1c and not workgroup:
                    workgroup = clean

            # MAC address is the last 6 bytes of the stats section
            stats_offset = 57 + num_names * 18
            if len(data) >= stats_offset + 6:
                mac_bytes = data[stats_offset:stats_offset + 6]
                mac = ":".join(f"{b:02x}" for b in mac_bytes)
            else:
                mac = ""

            return {
                "names":     names,
                "hostname":  hostname,
                "workgroup": workgroup,
                "mac":       mac,
            }

        except Exception:
            return None
