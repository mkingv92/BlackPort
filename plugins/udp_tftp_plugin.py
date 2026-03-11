# plugins/udp_tftp_plugin.py
from .plugin_base import PluginBase
import socket
import struct

# Files to attempt reading — ordered by impact
TFTP_PROBE_FILES = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/hostname",
    "boot/grub/grub.cfg",
    "startup-config",      # Cisco
    "running-config",      # Cisco
]

class UDPTFTPPlugin(PluginBase):
    name = "TFTP Security Check"
    applicable_services = ["TFTP"]

    def run(self, target, port, banner=None):
        if port != 69:
            return None

        notes = []
        risk = "MEDIUM"  # TFTP open is always at least MEDIUM — no auth by design
        exploit_hint = None

        notes.append("TFTP service detected — protocol has no authentication by design.")

        # --- Step 1: Try reading sensitive files ---
        readable = self._probe_read_files(target, port)
        if readable:
            for filename, preview in readable:
                notes.append(f"CRITICAL: File readable without auth — {filename}: {preview}")
            risk = "CRITICAL"
            exploit_hint = (
                f"Read files: tftp {target} -c get /etc/passwd "
                f"OR: atftp --get --remote-file /etc/passwd --local-file out.txt {target}"
            )
        else:
            notes.append("File read attempts returned errors — may be restricted or empty TFTP root.")

        # --- Step 2: Test write access ---
        write_result = self._probe_write(target, port)
        if write_result:
            notes.append("CRITICAL: TFTP write access confirmed — arbitrary file upload possible.")
            if risk != "CRITICAL":
                risk = "CRITICAL"
            exploit_hint = exploit_hint or f"Write files: tftp {target} -c put malicious.sh /tmp/malicious.sh"

        # --- Step 3: Remediation ---
        notes.append("Remediation: Disable TFTP if unused, or restrict to specific IP ranges with firewall rules.")

        return {
            "plugin": self.name,
            "risk": risk,
            "notes": " | ".join(notes),
            "exploit_hint": exploit_hint
        }

    def _build_rrq(self, filename):
        """Build a TFTP Read Request packet."""
        return (
            b"\x00\x01"                              # Opcode: RRQ
            + filename.encode() + b"\x00"            # Filename
            + b"netascii\x00"                        # Mode
        )

    def _build_wrq(self, filename):
        """Build a TFTP Write Request packet."""
        return (
            b"\x00\x02"                              # Opcode: WRQ
            + filename.encode() + b"\x00"
            + b"netascii\x00"
        )

    def _probe_read_files(self, target, port):
        """Attempt to read a list of sensitive files via TFTP."""
        readable = []
        for filename in TFTP_PROBE_FILES:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.settimeout(2)
                    rrq = self._build_rrq(filename)
                    s.sendto(rrq, (target, port))
                    resp, addr = s.recvfrom(4096)

                    if len(resp) >= 2:
                        opcode = struct.unpack(">H", resp[:2])[0]
                        if opcode == 3:  # DATA packet — file exists and is readable
                            preview = resp[4:].decode(errors="ignore").strip()[:60]
                            readable.append((filename, preview.replace("\n", " ") if preview else "(binary data)"))
                            # Send ACK to be polite
                            block = resp[2:4]
                            ack = b"\x00\x04" + block
                            s.sendto(ack, addr)
                        elif opcode == 5:  # ERROR
                            pass  # File not found or access denied

            except socket.timeout:
                pass
            except Exception:
                pass

        return readable

    def _probe_write(self, target, port):
        """Attempt to write a test file via TFTP."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(2)
                wrq = self._build_wrq("blackport_test.txt")
                s.sendto(wrq, (target, port))
                resp, addr = s.recvfrom(512)

                if len(resp) >= 2:
                    opcode = struct.unpack(">H", resp[:2])[0]
                    if opcode == 4:  # ACK — server accepted write request
                        # Send empty data block to complete transfer
                        data_pkt = b"\x00\x03\x00\x01"  # DATA block 1, empty
                        s.sendto(data_pkt, addr)
                        return True
        except Exception:
            pass
        return False
