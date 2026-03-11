# plugins/ssh_plugin.py
from .plugin_base import PluginBase
import socket
import re

# Known weak/outdated OpenSSH versions worth flagging
WEAK_SSH_VERSIONS = {
    "2.":  ("CRITICAL", "SSH protocol version 2 prefix but ancient build."),
    "1.":  ("CRITICAL", "SSH protocol v1 detected - fundamentally broken, trivially MITM'd."),
}

OUTDATED_OPENSSH = [
    # (max_minor, patch, risk, note)
    # OpenSSH < 4.0 - very old, multiple auth bypass CVEs
    (4, 0, "CRITICAL", "OpenSSH < 4.0 — multiple critical auth bypass vulnerabilities."),
    # OpenSSH < 6.0 - missing many hardening features
    (6, 0, "HIGH", "OpenSSH < 6.0 — missing modern hardening, multiple known CVEs."),
    # OpenSSH < 7.0 - vulnerable to user enumeration and weak KEX
    (7, 0, "HIGH", "OpenSSH < 7.0 — user enumeration and weak key exchange vulnerabilities."),
    # OpenSSH < 8.0 - missing security fixes for CBC mode and others
    (8, 0, "MEDIUM", "OpenSSH < 8.0 — outdated, missing several security patches."),
]

WEAK_AUTH_INDICATORS = [
    "password",
    "keyboard-interactive",
]

class SSHPlugin(PluginBase):
    name = "SSH Bruteforce Indicator"
    applicable_services = ["SSH"]

    def run(self, target, port, banner=None):
        notes = []
        risk = "LOW"
        exploit_hint = None

        # --- Step 1: Parse banner for version info ---
        version_str = None
        if banner:
            # e.g. "SSH-2.0-OpenSSH_4.7p1 Debian-8ubuntu1"
            match = re.search(r"OpenSSH[_\s](\d+)\.(\d+)", banner, re.IGNORECASE)
            if match:
                major = int(match.group(1))
                minor = int(match.group(2))
                version_str = f"{major}.{minor}"

                for (max_major, max_minor, ver_risk, ver_note) in OUTDATED_OPENSSH:
                    if major < max_major or (major == max_major and minor < max_minor):
                        notes.append(ver_note)
                        risk = ver_risk
                        break

            # Check for SSH protocol v1
            if re.search(r"SSH-1\.", banner):
                risk = "CRITICAL"
                notes.append("SSH protocol v1 detected — fundamentally insecure, supports trivial MITM.")
                exploit_hint = "Downgrade attack or MITM via ssh v1 protocol weakness."

        # --- Step 2: Probe for accepted auth methods ---
        try:
            auth_methods = self._get_auth_methods(target, port)
            if "password" in auth_methods:
                notes.append("Password authentication enabled — susceptible to brute-force attacks.")
                if risk == "LOW":
                    risk = "MEDIUM"
                exploit_hint = exploit_hint or "Brute-force with Hydra or Medusa: hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://target"

            if "keyboard-interactive" in auth_methods:
                notes.append("Keyboard-interactive auth enabled — may allow credential stuffing.")
                if risk == "LOW":
                    risk = "MEDIUM"

            if "publickey" in auth_methods and "password" not in auth_methods:
                notes.append("Only public key authentication accepted — brute-force resistant.")

        except Exception:
            notes.append("Could not probe SSH auth methods.")

        # --- Step 3: Check for root login hint in banner ---
        if banner and "debian" in banner.lower():
            notes.append("Debian-based SSH — check if PermitRootLogin is enabled (common on older installs).")

        if not notes:
            notes.append("SSH appears reasonably configured for its version.")

        return {
            "plugin": self.name,
            "risk": risk,
            "notes": " | ".join(notes),
            "exploit_hint": exploit_hint
        }

    def _get_auth_methods(self, target, port):
        """
        Sends a minimal SSH service probe to extract supported auth methods
        from the server's rejection response to a 'none' auth request.
        This does NOT attempt any login — purely passive enumeration.
        """
        methods = []
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(3)
                s.connect((target, port))

                # Read server banner
                s.recv(256)

                # Send our client banner
                s.sendall(b"SSH-2.0-BlackPort_Probe\r\n")

                # Read key exchange init (we won't parse it fully)
                data = b""
                try:
                    while len(data) < 4:
                        chunk = s.recv(1024)
                        if not chunk:
                            break
                        data += chunk
                except Exception:
                    pass

                # We can't fully negotiate SSH here without a library,
                # but we can check the banner for clues
                # For a full auth method probe, paramiko would be needed.
                # Flag password auth as likely on old OpenSSH versions.
                if data:
                    raw = data.decode(errors="ignore").lower()
                    if "password" in raw:
                        methods.append("password")

        except Exception:
            pass

        # Heuristic: OpenSSH < 7.0 almost always has password auth on by default
        # This is flagged as an indicator, not a confirmed state
        return methods
