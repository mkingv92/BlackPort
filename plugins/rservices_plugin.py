# plugins/rservices_plugin.py
# =====================================================================
# File: plugins/rservices_plugin.py
# Notes:
# - This file is part of the BlackPort project.
# - Covers rexec (512), rlogin (513), rsh (514) — Berkeley r-services.
# - These are unauthenticated remote execution services from the 1980s.
# - Almost always exploitable on any system still running them.
# - Use only on hosts/networks you own or have explicit permission to test.
# =====================================================================

from .plugin_base import PluginBase
import socket


class RServicesPlugin(PluginBase):
    name = "R-Services Security Check"
    applicable_services = ["rexec", "rlogin", "rsh", "Unknown"]

    # Only fire on known r-service ports
    RSERVICE_PORTS = {
        512: ("rexec",  "Remote Execution"),
        513: ("rlogin", "Remote Login"),
        514: ("rsh",    "Remote Shell"),
    }

    def run(self, target, port, banner=None):
        if port not in self.RSERVICE_PORTS:
            return None

        service_name, service_desc = self.RSERVICE_PORTS[port]
        notes = []
        risk  = "HIGH"  # r-services are always at least HIGH — no modern justification
        exploit_hint = None

        notes.append(
            f"{service_desc} ({service_name}) detected — Berkeley r-services are "
            f"legacy unauthenticated remote access protocols from the 1980s."
        )

        # --- Active verification by port ---
        if port == 512:
            result = self._probe_rexec(target)
        elif port == 513:
            result = self._probe_rlogin(target)
        elif port == 514:
            result = self._probe_rsh(target)
        else:
            result = None

        if result == "open_no_auth":
            notes.append(
                "CRITICAL: r-service accepted connection with no authentication — "
                "direct command execution possible."
            )
            risk = "CRITICAL"
            if port == 512:
                exploit_hint = (
                    f"Execute commands: rexec {target} -l root id "
                    f"OR: use Metasploit exploit/unix/rservices/rexec"
                )
            elif port == 513:
                exploit_hint = (
                    f"Login directly: rlogin -l root {target} "
                    f"OR: use Metasploit exploit/unix/rservices/rlogin"
                )
            elif port == 514:
                exploit_hint = (
                    f"Execute commands: rsh -l root {target} id "
                    f"OR: use Metasploit exploit/unix/rservices/rsh"
                )

        elif result == "open_auth_required":
            notes.append(
                "Service requires authentication — but r-services use .rhosts "
                "trust relationships which are trivially bypassable."
            )
            risk = "HIGH"
            exploit_hint = (
                f"Check .rhosts trust: rsh -l root {target} id "
                f"OR test with: Metasploit auxiliary/scanner/rservices/rsh_login"
            )

        elif result == "banner_only":
            notes.append(
                "Service responded but could not determine auth state — "
                "manual verification required."
            )
            risk = "HIGH"

        else:
            notes.append(
                "Service port open but probe inconclusive — "
                "r-services are high-risk regardless of probe result."
            )

        # Always add context regardless of probe result
        notes.append(
            "R-services transmit all data including credentials in plaintext. "
            "No legitimate use case in modern environments."
        )
        notes.append(
            "Remediation: Disable rexec/rlogin/rsh immediately. "
            "Replace with SSH. Remove .rhosts and hosts.equiv files."
        )

        return {
            "plugin":       self.name,
            "risk":         risk,
            "notes":        " | ".join(notes),
            "exploit_hint": exploit_hint,
        }

    def _probe_rexec(self, target, timeout=3):
        """
        Probe rexec (512/tcp).
        rexec expects: port\0user\0password\0command\0
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect((target, 512))
                s.send(b"\x00root\x00\x00id\x00")
                resp = s.recv(512)
                resp_str = resp.decode(errors="ignore").lower()
                if "uid=" in resp_str or "root" in resp_str:
                    return "open_no_auth"
                elif "password" in resp_str or "login incorrect" in resp_str:
                    return "open_auth_required"
                elif resp:
                    # Any response at all means service is live and accepting connections
                    return "open_auth_required"
        except socket.timeout:
            return "open_auth_required"
        except Exception:
            pass
        return None

    def _probe_rlogin(self, target, timeout=3):
        """
        Probe rlogin (513/tcp).
        Any response that isn't a hard refusal = unauthenticated access risk.
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect((target, 513))
                s.send(b"\x00root\x00root\x00vt100/9600\x00")
                resp = s.recv(512)
                resp_str = resp.decode(errors="ignore").lower()
                if "last login" in resp_str or "#" in resp_str or "$" in resp_str:
                    return "open_no_auth"
                elif "password" in resp_str:
                    return "open_auth_required"
                elif resp:
                    # rlogin responding at all = no host-based auth blocking us
                    return "open_no_auth"
        except socket.timeout:
            # Timeout after sending = service likely processing our request
            return "open_no_auth"
        except ConnectionRefusedError:
            return None
        except Exception:
            pass
        return None

    def _probe_rsh(self, target, timeout=3):
        """
        Probe rsh (514/tcp).
        rsh: stderr_port\0client_user\0server_user\0command\0
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect((target, 514))
                s.send(b"\x00root\x00root\x00id\x00")
                resp = s.recv(512)
                resp_str = resp.decode(errors="ignore").lower()
                if "uid=" in resp_str:
                    return "open_no_auth"
                elif "permission denied" in resp_str or "refused" in resp_str:
                    return "open_auth_required"
                elif resp:
                    # Any response = service live, likely accepting
                    return "open_no_auth"
        except socket.timeout:
            return "open_no_auth"
        except ConnectionRefusedError:
            return None
        except Exception:
            pass
        return None
