# plugins/smtp_plugin.py
from .plugin_base import PluginBase
import socket
import re

class SMTPPlugin(PluginBase):
    name = "SMTP Open Relay Check"
    applicable_services = ["SMTP"]

    def run(self, target, port, banner=None):
        notes = []
        risk = "LOW"
        exploit_hint = None

        # --- Step 1: Parse banner for software/version ---
        if banner:
            banner_lower = banner.lower()

            if "postfix" in banner_lower:
                notes.append("Postfix SMTP detected.")
            elif "sendmail" in banner_lower:
                notes.append("Sendmail detected — historically vulnerable, check version.")
                risk = "MEDIUM"
            elif "exim" in banner_lower:
                notes.append("Exim detected — check for CVE-2019-10149 (remote root RCE).")
                risk = "HIGH"
                exploit_hint = "Exim RCE: searchsploit exim OR Metasploit: exploit/linux/smtp/exim4_string_format"

            # Check for hostname/domain info disclosure
            hostname_match = re.search(r"220\s+(\S+)", banner)
            if hostname_match:
                hostname = hostname_match.group(1)
                notes.append(f"Banner discloses hostname: {hostname} — consider hiding with smtpd_banner.")

        # --- Step 2: Test for open relay ---
        relay_result = self._test_open_relay(target, port)
        if relay_result == "open":
            notes.append("OPEN RELAY CONFIRMED — server will forward mail for any sender/recipient. Abuse risk: spam, phishing campaigns.")
            risk = "CRITICAL"
            exploit_hint = exploit_hint or f"Open relay abuse: swaks --to victim@external.com --from spoofed@legit.com --server {target}"
        elif relay_result == "restricted":
            notes.append("Relay restricted — server rejected unauthorized relay attempt.")
        else:
            notes.append("Could not fully test relay — manual verification recommended.")

        # --- Step 3: Test for VRFY user enumeration ---
        vrfy_result = self._test_vrfy(target, port)
        if vrfy_result:
            notes.append("VRFY command enabled — allows username enumeration without authentication.")
            if risk == "LOW":
                risk = "MEDIUM"
            exploit_hint = exploit_hint or f"Enumerate users: smtp-user-enum -M VRFY -U /usr/share/wordlists/metasploit/unix_users.txt -t {target}"

        if not notes:
            notes.append("No significant SMTP issues detected.")

        return {
            "plugin": self.name,
            "risk": risk,
            "notes": " | ".join(notes),
            "exploit_hint": exploit_hint
        }

    def _test_open_relay(self, target, port):
        """
        Attempt a relay test by sending MAIL FROM / RCPT TO with external domains.
        Does NOT send an actual email body — stops after RCPT TO response.
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(4)
                s.connect((target, port))
                s.recv(1024)  # banner

                s.sendall(b"EHLO blackport.test\r\n")
                s.recv(1024)

                s.sendall(b"MAIL FROM:<test@external-sender.com>\r\n")
                resp1 = s.recv(1024).decode(errors="ignore")

                s.sendall(b"RCPT TO:<victim@external-recipient.com>\r\n")
                resp2 = s.recv(1024).decode(errors="ignore")

                s.sendall(b"QUIT\r\n")

                if resp2.startswith("250"):
                    return "open"
                elif "relay" in resp2.lower() or "denied" in resp2.lower() or resp2.startswith("5"):
                    return "restricted"

        except Exception:
            pass

        return "unknown"

    def _test_vrfy(self, target, port):
        """Test if VRFY command is enabled for user enumeration."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(3)
                s.connect((target, port))
                s.recv(1024)

                s.sendall(b"EHLO blackport.test\r\n")
                s.recv(1024)

                s.sendall(b"VRFY root\r\n")
                resp = s.recv(1024).decode(errors="ignore")
                s.sendall(b"QUIT\r\n")

                # 250 or 252 = VRFY works, 502/500 = disabled
                if resp.startswith("250") or resp.startswith("252"):
                    return True

        except Exception:
            pass

        return False
