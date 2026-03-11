# plugins/telnet_plugin.py
from .plugin_base import PluginBase
import socket
import re

class TelnetPlugin(PluginBase):
    name = "Telnet Security Check"
    applicable_services = ["Telnet"]

    def run(self, target, port, banner=None):
        notes = []
        risk = "HIGH"  # Telnet is always at least HIGH — cleartext protocol
        exploit_hint = None

        # Telnet is cleartext by definition
        notes.append("Telnet transmits all data including credentials in plaintext — trivially intercepted.")
        exploit_hint = f"Capture credentials with: tcpdump -i any port {port} -A OR use Wireshark"

        # --- Step 1: Parse banner for OS/device hints ---
        if banner:
            banner_lower = banner.lower()

            if "linux" in banner_lower or "ubuntu" in banner_lower or "debian" in banner_lower:
                notes.append("Linux-based Telnet detected — likely accepts OS user credentials over cleartext.")
            elif "cisco" in banner_lower:
                notes.append("Cisco device Telnet — network infrastructure exposed over cleartext.")
                risk = "CRITICAL"
                exploit_hint = "Cisco Telnet brute-force: hydra -l admin -P /usr/share/wordlists/rockyou.txt telnet://target"
            elif "windows" in banner_lower:
                notes.append("Windows Telnet service detected — extremely unusual, likely misconfigured.")
                risk = "CRITICAL"

        # --- Step 2: Attempt login probe to check if auth is required ---
        auth_required = self._check_auth_required(target, port)
        if auth_required is False:
            notes.append("CRITICAL: Telnet accepted connection with NO authentication — open shell access.")
            risk = "CRITICAL"
            exploit_hint = f"No auth required — connect directly: telnet {target} {port}"
        elif auth_required is True:
            notes.append("Authentication prompt detected — susceptible to brute-force over cleartext.")
            exploit_hint = exploit_hint or f"Brute-force: hydra -l root -P /usr/share/wordlists/rockyou.txt telnet://{target}"

        # --- Step 3: Recommend replacement ---
        notes.append("Remediation: Disable Telnet immediately and replace with SSH.")

        return {
            "plugin": self.name,
            "risk": risk,
            "notes": " | ".join(notes),
            "exploit_hint": exploit_hint
        }

    def _check_auth_required(self, target, port):
        """
        Connect to Telnet and check if a login prompt appears.
        Returns True if auth prompt seen, False if shell given directly, None if inconclusive.
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(3)
                s.connect((target, port))
                data = b""
                try:
                    while True:
                        chunk = s.recv(1024)
                        if not chunk:
                            break
                        data += chunk
                        if len(data) > 2048:
                            break
                except Exception:
                    pass

                decoded = data.decode(errors="ignore").lower()

                if "login:" in decoded or "username:" in decoded or "password:" in decoded:
                    return True
                if "$" in decoded or "#" in decoded or ">" in decoded:
                    return False  # shell prompt without auth

        except Exception:
            pass

        return None
