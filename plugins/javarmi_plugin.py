# plugins/javarmi_plugin.py
# =====================================================================
# File: plugins/javarmi_plugin.py
# Notes:
# - This file is part of the BlackPort project.
# - Java RMI on port 1099 is frequently exploitable via deserialization.
# - Metasploitable runs a vulnerable RMI registry with no auth.
# - Use only on hosts/networks you own or have explicit permission to test.
# =====================================================================

from .plugin_base import PluginBase
import socket
import struct


class JavaRMIPlugin(PluginBase):
    name = "Java RMI Security Check"
    applicable_services = ["Java-RMI", "Java RMI", "Unknown"]

    RMI_PORT = 1099

    # Java RMI handshake magic bytes
    # The RMI protocol starts with: 0x4a 0x52 0x4d 0x49 (JRMI)
    RMI_MAGIC = b"\x4a\x52\x4d\x49"

    def run(self, target, port, banner=None):
        if port != self.RMI_PORT:
            return None

        notes = []
        risk  = "HIGH"
        exploit_hint = None

        notes.append(
            "Java RMI registry detected on port 1099."
        )

        result, registry_objects = self._probe_rmi(target)

        if result == "registry_open":
            notes.append(
                "CRITICAL: RMI registry is accessible with no authentication. "
                "Remote method invocation without credentials is possible."
            )
            if registry_objects:
                notes.append(
                    f"Registered objects: {', '.join(registry_objects[:5])} — "
                    f"these are remotely invokable without authentication."
                )
            notes.append(
                "Deserialization attacks via ysoserial payloads are likely effective. "
                "CVE-2011-3556, CVE-2017-3241 class vulnerabilities."
            )
            risk = "CRITICAL"
            exploit_hint = (
                f"Enumerate: nmap -p 1099 {target} --script rmi-dumpregistry "
                f"OR Metasploit: use exploit/multi/misc/java_rmi_server"
            )

        elif result == "responding":
            notes.append(
                "RMI service is responding. "
                "Unauthenticated registry access and deserialization attacks likely. "
                "Java RMI without authentication is a known critical vulnerability class."
            )
            risk = "CRITICAL"
            exploit_hint = (
                f"Metasploit: use exploit/multi/misc/java_rmi_server "
                f"OR auxiliary/scanner/misc/java_rmi_registry"
            )

        elif result == "tls_required":
            notes.append(
                "RMI service requires SSL/TLS — authentication may be enforced. "
                "Still vulnerable to credential brute force and misconfiguration."
            )
            risk = "MEDIUM"

        else:
            notes.append(
                "Java RMI port open. Probe inconclusive — "
                "manual verification recommended."
            )

        notes.append(
            "Remediation: Disable Java RMI if not required. "
            "If needed: enable SSL, firewall port 1099, and use SecurityManager."
        )

        return {
            "plugin":       self.name,
            "risk":         risk,
            "notes":        " | ".join(notes),
            "exploit_hint": exploit_hint,
        }

    def _probe_rmi(self, target, timeout=5):
        """
        Probe Java RMI registry.
        Send RMI handshake and attempt to list registered objects.
        Returns (status, [object_names])
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect((target, self.RMI_PORT))

                # RMI stream protocol header
                # Magic: 0x4a524d49 (JRMI)
                # Version: 0x0002
                # Protocol: 0x4b (StreamProtocol)
                handshake = b"\x4a\x52\x4d\x49\x00\x02\x4b"
                s.sendall(handshake)

                resp = s.recv(256)

                if not resp:
                    return "no_response", []

                resp_str = resp.decode(errors="ignore")

                # Check for TLS/SSL requirement
                if b"\x15\x03" in resp or b"\x16\x03" in resp:
                    return "tls_required", []

                # RMI protocol ack: 0x4e = ProtocolAck
                if b"\x4e" in resp or self.RMI_MAGIC in resp:
                    # Try to list registry contents
                    objects = self._list_registry(s, target)
                    return "registry_open", objects

                # Any response = RMI is live
                if resp:
                    return "responding", []

        except ConnectionRefusedError:
            return None, []
        except socket.timeout:
            return "responding", []
        except Exception:
            pass

        return None, []

    def _list_registry(self, sock, target, timeout=3):
        """
        Attempt to call registry.list() to enumerate registered objects.
        Uses minimal RMI call format.
        """
        try:
            # RMI call to list() on the registry (object ID 0)
            # This is a simplified probe — looks for string data in response
            list_call = (
                b"\x50"         # Call
                b"\xac\xed"     # Java serialization magic
                b"\x00\x05"     # serialization version
                b"\x77\x22"     # TC_BLOCKDATA, length 34
                b"\x00\x00\x00\x00\x00\x00\x00\x00"   # object ID (registry = 0)
                b"\x00\x00\x00\x00\x00\x00\x00\x00"   # uid
                b"\x00\x00\x00\x00"                     # time
                b"\x00\x00\x00\x00"                     # count
                b"\x00\x00\x00\x00\x00\x00\x00\x00"   # padding
            )
            sock.sendall(list_call)
            sock.settimeout(timeout)
            resp = sock.recv(2048).decode(errors="ignore")

            # Extract readable strings (registered object names)
            objects = []
            parts = resp.split("\x00")
            for part in parts:
                cleaned = "".join(c for c in part if c.isprintable() and c not in "\r\n")
                if 3 < len(cleaned) < 60 and "/" not in cleaned:
                    objects.append(cleaned)

            return objects[:5]  # cap at 5

        except Exception:
            return []
