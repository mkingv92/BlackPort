# plugins/unrealircd_plugin.py
# =====================================================================
# File: plugins/unrealircd_plugin.py
# Notes:
# - This file is part of the BlackPort project.
# - UnrealIRCd 3.2.8.1 contains a compiled-in backdoor (CVE-2010-2075).
# - The backdoor calls system() — output goes to process stdout, NOT back
#   over the TCP socket. Cannot confirm RCE via output inspection.
# - Instead: confirm version via IRC VERSION command, flag 3.2.8.1 as
#   the exact backdoored release.
# - Use only on hosts/networks you own or have explicit permission to test.
# =====================================================================

from .plugin_base import PluginBase
import socket
import re
import time


class UnrealIRCdPlugin(PluginBase):
    name = "UnrealIRCd Backdoor Check"
    applicable_services = ["IRC", "IRC-SSL", "UnrealIRCd"]

    IRC_PORTS = {6667, 6697, 6660, 6661, 6662, 6663, 6664, 6665, 6666, 7000}

    # The exact backdoored version string
    BACKDOORED_VERSION = "3.2.8.1"

    def run(self, target, port, banner=None):
        if port not in self.IRC_PORTS:
            return None

        notes        = []
        risk         = "MEDIUM"
        exploit_hint = None

        is_metasploitable = banner and "metasploitable" in banner.lower()

        version, is_unreal = self._get_version(target, port)

        if version and self.BACKDOORED_VERSION in version:
            notes.append(
                f"CRITICAL: UnrealIRCd {version} detected — "
                f"this is the EXACT backdoored release (CVE-2010-2075). "
                f"The backdoor executes arbitrary commands via 'AB;' prefix trigger. "
                f"Distributed Nov 2009 – Jun 2010."
            )
            risk = "CRITICAL"
            exploit_hint = (
                f"Metasploit: use exploit/unix/irc/unreal_ircd_3281_backdoor "
                f"set RHOSTS {target} set RPORT {port} run"
            )

        elif version and is_unreal:
            notes.append(
                f"UnrealIRCd {version} detected. "
                f"Not the backdoored 3.2.8.1 release — but verify manually."
            )
            risk = "MEDIUM"

        elif is_unreal or is_metasploitable:
            notes.append(
                "UnrealIRCd detected on Metasploitable host — "
                "very likely version 3.2.8.1 with CVE-2010-2075 backdoor. "
                "VERSION query inconclusive."
            )
            risk = "HIGH"
            exploit_hint = (
                f"Metasploit: use exploit/unix/irc/unreal_ircd_3281_backdoor "
                f"set RHOSTS {target} set RPORT {port} run"
            )

        else:
            notes.append(
                f"IRC service on port {port}. "
                "Check for UnrealIRCd 3.2.8.1 backdoor (CVE-2010-2075)."
            )
            risk = "MEDIUM"

        notes.append(
            "Note: CVE-2010-2075 uses system() — output goes to server stdout, "
            "not back over TCP. Use Metasploit for active exploitation."
        )
        notes.append("Disable IRC if not required. Patch to >= 3.2.8.2 if needed.")

        return {
            "plugin":       self.name,
            "risk":         risk,
            "notes":        " | ".join(notes),
            "exploit_hint": exploit_hint,
        }

    def _get_version(self, target, port, timeout=6):
        """
        Send IRC VERSION command and parse the response.
        Returns (version_string, is_unreal).
        IRC VERSION response format:
          :server 351 <nick> <version> <server> :<comments>
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect((target, port))

                # Register a minimal IRC session so VERSION works
                # NICK + USER required before server processes commands
                s.sendall(b"NICK blackport\r\nUSER bp 0 * :BlackPort\r\n")

                # Read responses including the MOTD/welcome sequence
                response = b""
                s.settimeout(3)
                deadline = time.time() + 5
                while time.time() < deadline:
                    try:
                        chunk = s.recv(2048)
                        if not chunk:
                            break
                        response += chunk
                        # 376 = End of MOTD, 422 = No MOTD — registration complete
                        if b" 376 " in response or b" 422 " in response:
                            break
                        # Also stop if we see 433 (nick in use) — send alternate
                        if b" 433 " in response:
                            s.sendall(b"NICK blackport_\r\n")
                    except socket.timeout:
                        break

                # Now send VERSION
                s.sendall(b"VERSION\r\n")
                s.settimeout(3)
                ver_data = b""
                try:
                    deadline = time.time() + 3
                    while time.time() < deadline:
                        chunk = s.recv(1024)
                        if not chunk:
                            break
                        ver_data += chunk
                        if b" 351 " in ver_data:
                            break
                except socket.timeout:
                    pass

                combined = (response + ver_data).decode(errors="ignore")

                # Parse version from 351 response
                # :irc.server 351 nick Unreal3.2.8.1. server :comment
                match = re.search(r"351\s+\S+\s+(\S+)", combined)
                if match:
                    ver_str  = match.group(1)
                    is_unreal = "unreal" in ver_str.lower()
                    # Extract numeric version
                    num_match = re.search(r"(\d+\.\d+\.\d+[\.\d]*)", ver_str)
                    version   = num_match.group(1) if num_match else ver_str
                    return version, is_unreal

                # Fallback: check if UnrealIRCd mentioned anywhere
                is_unreal = "unreal" in combined.lower()
                return None, is_unreal

        except ConnectionRefusedError:
            return None, False
        except Exception:
            pass

        return None, False
