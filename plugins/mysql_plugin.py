# plugins/mysql_plugin.py
from .plugin_base import PluginBase
import socket
import re

class MySQLPlugin(PluginBase):
    name = "MySQL Security Check"
    applicable_services = ["MySQL"]

    def run(self, target, port, banner=None):
        notes = []
        risk = "HIGH"  # MySQL exposed externally is always at least HIGH
        exploit_hint = None

        notes.append("MySQL exposed on network — database should never be directly internet-facing.")

        # --- Step 1: Parse MySQL handshake banner for version ---
        mysql_version = None
        if banner:
            version_match = re.search(r"(\d+\.\d+\.\d+)", banner)
            if version_match:
                mysql_version = version_match.group(1)
                notes.append(f"MySQL version: {mysql_version}")

                parts = mysql_version.split(".")
                major, minor = int(parts[0]), int(parts[1])

                if major == 5 and minor <= 1:
                    notes.append("MySQL 5.1 or older — end of life, multiple critical CVEs including auth bypass.")
                    risk = "CRITICAL"
                    exploit_hint = f"Auth bypass: CVE-2012-2122 — searchsploit mysql 5.1"
                elif major == 5 and minor <= 5:
                    notes.append("MySQL 5.5 — end of life since 2018, unpatched vulnerabilities exist.")
                    risk = "HIGH"
                elif major == 5 and minor <= 7:
                    notes.append("MySQL 5.7 — end of life since October 2023.")
                    risk = "MEDIUM"

        # --- Step 2: Attempt anonymous/root login ---
        anon_result = self._test_root_no_password(target, port)
        if anon_result == "open":
            notes.append("CRITICAL: Root login with no password accepted — full database access without credentials.")
            risk = "CRITICAL"
            exploit_hint = f"Connect directly: mysql -h {target} -u root --port {port}"
        elif anon_result == "auth_required":
            notes.append("Authentication required — susceptible to brute-force.")
            exploit_hint = exploit_hint or f"Brute-force: hydra -l root -P /usr/share/wordlists/rockyou.txt mysql://{target}"

        # --- Step 3: Flag external exposure ---
        notes.append("Remediation: Bind MySQL to 127.0.0.1 only (bind-address = 127.0.0.1 in my.cnf).")

        return {
            "plugin": self.name,
            "risk": risk,
            "notes": " | ".join(notes),
            "exploit_hint": exploit_hint
        }

    def _test_root_no_password(self, target, port):
        """
        Attempt to read the MySQL server handshake and send a minimal
        auth packet for root with no password. Checks response code only —
        does not execute any queries.
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(3)
                s.connect((target, port))

                # Read server greeting
                greeting = s.recv(4096)
                if not greeting or len(greeting) < 5:
                    return "unknown"

                # MySQL protocol: byte 4 is packet type
                # 0xff = error, 0x0a = handshake v10
                packet_type = greeting[4]
                if packet_type == 0xff:
                    return "unknown"

                # Build minimal client auth packet (root, no password, MySQL 4.1+)
                # Capability flags: CLIENT_LONG_PASSWORD | CLIENT_PROTOCOL_41
                caps = (0x0001 | 0x0200).to_bytes(4, "little")
                max_packet = (16777216).to_bytes(4, "little")
                charset = b"\x21"  # utf8
                reserved = b"\x00" * 23
                username = b"root\x00"
                auth_response = b"\x00"  # empty password

                payload = caps + max_packet + charset + reserved + username + auth_response
                length = len(payload).to_bytes(3, "little")
                seq = b"\x01"
                packet = length + seq + payload

                s.sendall(packet)
                response = s.recv(1024)

                if response and len(response) > 4:
                    resp_type = response[4]
                    if resp_type == 0x00:  # OK packet
                        return "open"
                    elif resp_type == 0xff:  # Error packet
                        return "auth_required"

        except Exception:
            pass

        return "unknown"
