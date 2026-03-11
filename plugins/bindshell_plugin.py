# plugins/bindshell_plugin.py
# =====================================================================
# File: plugins/bindshell_plugin.py
# Notes:
# - This file is part of the BlackPort project.
# - Port 1524 (Ingreslock) is used by Metasploitable as a root backdoor.
# - Any banner containing shell prompt indicators = confirmed root shell.
# - Use only on hosts/networks you own or have explicit permission to test.
# =====================================================================

from .plugin_base import PluginBase
import socket


class BindshellPlugin(PluginBase):
    name = "Bindshell Backdoor Check"
    applicable_services = ["Bindshell", "Unknown", "Ingreslock"]

    BINDSHELL_PORTS = {1524, 31337, 4444, 5554, 9999, 1234}

    SHELL_INDICATORS = [
        "#",          # root prompt
        "$",          # user prompt
        "root@",
        "sh-",
        "bash",
        "/#",
        "/bin/sh",
        "command not found",
        "uid=",
    ]

    def run(self, target, port, banner=None):
        if port not in self.BINDSHELL_PORTS and port != 1524:
            return None

        notes = []
        risk  = "CRITICAL"
        exploit_hint = None

        # Check banner first — fastest path
        if banner:
            banner_lower = banner.lower()
            for indicator in self.SHELL_INDICATORS:
                if indicator in banner:
                    notes.append(
                        f"CONFIRMED BACKDOOR: Port {port} is a live root shell — "
                        f"banner shows: '{banner[:80].strip()}'"
                    )
                    notes.append(
                        "Direct unauthenticated root access. "
                        "This is a deliberately planted backdoor (Metasploitable Ingreslock)."
                    )
                    exploit_hint = f"Connect directly: nc {target} {port}"
                    return {
                        "plugin":       self.name,
                        "risk":         "CRITICAL",
                        "notes":        " | ".join(notes),
                        "exploit_hint": exploit_hint,
                    }

        # Active probe — send a command and check response
        result = self._probe_shell(target, port)

        if result == "shell_confirmed":
            notes.append(
                f"CONFIRMED BACKDOOR: Port {port} executed 'id' command — "
                "unauthenticated root shell access confirmed."
            )
            risk = "CRITICAL"
            exploit_hint = f"Connect directly: nc {target} {port}"

        elif result == "shell_likely":
            notes.append(
                f"PROBABLE BACKDOOR: Port {port} responded to shell input — "
                "likely unauthenticated shell access."
            )
            risk = "CRITICAL"
            exploit_hint = f"Connect directly: nc {target} {port}"

        elif result == "responding":
            notes.append(
                f"Port {port} (Ingreslock/Bindshell) is open and responding. "
                "This port is commonly used for backdoor shells."
            )
            risk = "CRITICAL"
            exploit_hint = f"Connect directly: nc {target} {port}"

        else:
            notes.append(
                f"Port {port} open — associated with backdoor/bind shells. "
                "Manual verification required."
            )
            risk = "HIGH"

        notes.append(
            "Remediation: Immediately identify and remove the process listening "
            "on this port. Check for persistence mechanisms (cron, rc.local, systemd)."
        )

        return {
            "plugin":       self.name,
            "risk":         risk,
            "notes":        " | ".join(notes),
            "exploit_hint": exploit_hint,
        }

    def _probe_shell(self, target, port, timeout=4):
        """Send 'id' command and check if we get uid= back."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect((target, port))

                # Try reading initial banner first
                try:
                    s.settimeout(1.5)
                    banner = s.recv(512).decode(errors="ignore")
                    for indicator in self.SHELL_INDICATORS:
                        if indicator in banner:
                            return "shell_confirmed"
                except socket.timeout:
                    pass

                # Send id command
                s.settimeout(timeout)
                s.sendall(b"id\n")
                resp = s.recv(512).decode(errors="ignore")

                if "uid=" in resp:
                    return "shell_confirmed"
                elif any(i in resp for i in ["#", "$", "root", "bash", "sh"]):
                    return "shell_likely"
                elif resp:
                    return "responding"

        except ConnectionRefusedError:
            return None
        except Exception:
            pass
        return None
