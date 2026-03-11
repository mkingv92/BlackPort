# plugins/x11_plugin.py
# =====================================================================
# File: plugins/x11_plugin.py
# Notes:
# - This file is part of the BlackPort project.
# - Tests X11 display server for unauthenticated access.
# - Metasploitable runs X11 with no xhost restrictions on port 6000.
# - Unauthenticated X11 = screenshot capture, keystroke injection,
#   credential theft from any application on the display.
# - Use only on hosts/networks you own or have explicit permission to test.
# =====================================================================

from .plugin_base import PluginBase
import socket
import struct


class X11Plugin(PluginBase):
    name = "X11 Auth Check"
    applicable_services = ["X11", "Unknown"]

    X11_PORTS = {6000, 6001, 6002, 6003, 6004, 6005}

    # X11 connection setup constants
    X11_LITTLE_ENDIAN = b'l'
    X11_BIG_ENDIAN    = b'B'
    X11_PROTOCOL_MAJOR = 11
    X11_PROTOCOL_MINOR = 0

    # Server reply codes
    REPLY_FAILED  = 0
    REPLY_SUCCESS = 1
    REPLY_AUTHENTICATE = 2

    def run(self, target, port, banner=None):
        if port not in self.X11_PORTS:
            return None

        display_num = port - 6000
        notes        = []
        risk         = "LOW"
        exploit_hint = None

        notes.append(f"X11 display server detected on port {port} (display :{display_num}).")

        result = self._probe_x11(target, port)

        if result == "no_auth":
            notes.append(
                "CRITICAL: X11 accepts connections with NO authentication. "
                "Full graphical display access without credentials. "
                "Attacker can: capture screenshots, inject keystrokes, steal "
                "passwords typed in any application, and hijack the session."
            )
            risk = "CRITICAL"
            exploit_hint = (
                f"Capture screenshot: DISPLAY={target}:{display_num} xwd -root -silent | "
                f"convert xwd:- /tmp/screen.png "
                f"OR Metasploit: use auxiliary/scanner/x11/open_x11 "
                f"then: use exploit/multi/handler (x11 keylogger)"
            )

        elif result == "auth_required":
            notes.append(
                "X11 requires authentication (MIT-MAGIC-COOKIE or similar). "
                "Access controlled — but verify cookie strength."
            )
            risk = "LOW"

        elif result == "responding":
            notes.append(
                "X11 port responding but auth state unclear. "
                "Manual verification: xdpyinfo -display " + f"{target}:{display_num}"
            )
            risk = "MEDIUM"

        notes.append(
            "Remediation: Disable X11 TCP listening (use Unix sockets only). "
            "Add '-nolisten tcp' to X server startup. "
            "Use 'xhost -' to remove all host-based access. "
            "Prefer SSH X11 forwarding for remote display needs."
        )

        return {
            "plugin":       self.name,
            "risk":         risk,
            "notes":        " | ".join(notes),
            "exploit_hint": exploit_hint,
        }

    def _probe_x11(self, target, port, timeout=5):
        """
        Perform X11 connection setup handshake.

        X11 ClientConnectionSetup message (big-endian):
          byte-order(1) + pad(1) + major(2) + minor(2)
          + auth-name-len(2) + auth-data-len(2) + pad(2)
          + auth-name + auth-data

        Server replies with:
          0 = Failed (auth rejected)
          1 = Success (no auth or auth accepted)
          2 = Authenticate (need credentials)
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect((target, port))

                # Send X11 connection setup with NO auth (empty name/data)
                # Big-endian byte order marker = 'B' (0x42)
                setup = struct.pack(
                    ">cBHHHHH",
                    b'B',   # byte-order: big-endian
                    0,      # pad
                    self.X11_PROTOCOL_MAJOR,   # 11
                    self.X11_PROTOCOL_MINOR,   # 0
                    0,      # auth-protocol-name length (0 = no auth)
                    0,      # auth-protocol-data length
                    0,      # pad
                )
                s.sendall(setup)

                resp = s.recv(64)
                if not resp:
                    return None

                reply_code = resp[0]

                if reply_code == self.REPLY_SUCCESS:
                    return "no_auth"
                elif reply_code == self.REPLY_FAILED:
                    return "auth_required"
                elif reply_code == self.REPLY_AUTHENTICATE:
                    return "auth_required"
                elif resp:
                    return "responding"

        except ConnectionRefusedError:
            return None
        except socket.timeout:
            return "responding"
        except Exception:
            pass

        return None
