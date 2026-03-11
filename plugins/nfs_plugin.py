# plugins/nfs_plugin.py
# =====================================================================
# File: plugins/nfs_plugin.py
# Notes:
# - This file is part of the BlackPort project.
# - Queries the RPC portmapper and NFS mountd for export list.
# - World-readable exports (to * or 0.0.0.0/0) = unauthenticated
#   filesystem access, often including /etc/passwd, SSH keys, etc.
# - Use only on hosts/networks you own or have explicit permission to test.
# =====================================================================

from .plugin_base import PluginBase
import socket
import struct
import random


class NFSPlugin(PluginBase):
    name = "NFS Export Check"
    applicable_services = ["NFS", "nfs"]

    NFS_PORT       = 2049
    PORTMAP_PORT   = 111
    MOUNTD_PROGRAM = 100005  # mountd
    PORTMAP_PROGRAM = 100000

    # RPC constants
    RPC_CALL    = 0
    RPC_REPLY   = 1
    AUTH_NULL   = 0

    def run(self, target, port, banner=None):
        if port != self.NFS_PORT:
            return None

        notes        = []
        risk         = "LOW"
        exploit_hint = None

        notes.append("NFS service detected on port 2049.")

        # Step 1: Get mountd port from portmapper
        mountd_port = self._get_mountd_port(target)

        # Step 2: Query export list from mountd
        exports = self._get_exports(target, mountd_port or 0)

        if exports is None:
            # Fallback: try common mountd ports directly
            for p in [635, 1024, 2048, 20048, 32771]:
                exports = self._get_exports(target, p)
                if exports is not None:
                    mountd_port = p
                    break

        if not exports and exports is not None:
            notes.append(
                "NFS mountd reachable but no exports configured. "
                "Low risk in current state."
            )
            risk = "LOW"

        elif exports:
            world_exports  = []
            local_exports  = []
            other_exports  = []

            for path, clients in exports:
                if not clients or "*" in clients or "0.0.0.0" in clients or "(everyone)" in clients:
                    world_exports.append(path)
                elif any(c in clients for c in ["192.168.", "10.", "172."]):
                    local_exports.append(f"{path} ({clients})")
                else:
                    other_exports.append(f"{path} ({clients})")

            if world_exports:
                notes.append(
                    f"CRITICAL: {len(world_exports)} NFS export(s) accessible to EVERYONE (*): "
                    + ", ".join(world_exports)
                )
                if "/" in world_exports or "/root" in world_exports:
                    notes.append(
                        "Root filesystem exported — full read access to /etc/passwd, "
                        "/etc/shadow, SSH keys, and all files."
                    )
                elif "/home" in world_exports or any("/home" in e for e in world_exports):
                    notes.append(
                        "Home directories exported — SSH keys and user files accessible."
                    )
                risk = "CRITICAL"
                paths_str = " ".join(world_exports[:3])
                exploit_hint = (
                    f"Mount directly: mkdir /tmp/nfs && mount -t nfs {target}:{world_exports[0]} /tmp/nfs "
                    f"OR: showmount -e {target}"
                )

            elif local_exports:
                notes.append(
                    f"NFS exports restricted to local network: {'; '.join(local_exports[:3])}"
                )
                notes.append(
                    "Restricted exports still risky on internal networks — "
                    "IP spoofing or compromised host on LAN gives full access."
                )
                risk = "MEDIUM"
                exploit_hint = f"Enumerate: showmount -e {target}"

            elif other_exports:
                notes.append(
                    f"NFS exports with access controls: {'; '.join(other_exports[:3])}"
                )
                risk = "LOW"

            if mountd_port:
                notes.append(f"mountd listening on port {mountd_port}.")

        else:
            notes.append(
                "NFS port open but export list could not be retrieved. "
                "Manual check: showmount -e " + target
            )
            risk = "LOW"
            exploit_hint = f"Manual: showmount -e {target}"

        notes.append(
            "Remediation: Export only to specific IPs in /etc/exports. "
            "Use 'ro,root_squash,no_subtree_check' options. "
            "Firewall port 2049 from untrusted networks."
        )

        return {
            "plugin":       self.name,
            "risk":         risk,
            "notes":        " | ".join(notes),
            "exploit_hint": exploit_hint,
        }

    def _make_rpc_call(self, program, version, procedure, data=b""):
        """Build a minimal RPC call message."""
        xid = random.randint(1, 0xFFFFFFFF)
        msg = struct.pack(
            "!IIIIIIIIII",
            xid,
            self.RPC_CALL,   # msg_type = CALL
            2,               # rpc_version = 2
            program,
            version,
            procedure,
            self.AUTH_NULL,  # credentials flavor
            0,               # credentials length
            self.AUTH_NULL,  # verifier flavor
            0,               # verifier length
        ) + data
        # Prepend record mark (last fragment bit set + length)
        record_mark = struct.pack("!I", 0x80000000 | len(msg))
        return record_mark + msg, xid

    def _recv_rpc_reply(self, sock, timeout=4):
        """Read an RPC reply with record marking."""
        sock.settimeout(timeout)
        try:
            # Read record mark
            mark_data = self._recv_exact(sock, 4)
            if not mark_data:
                return None
            length = struct.unpack("!I", mark_data)[0] & 0x7FFFFFFF
            if length == 0 or length > 65536:
                return None
            return self._recv_exact(sock, length)
        except Exception:
            return None

    def _recv_exact(self, sock, n):
        """Read exactly n bytes."""
        data = b""
        while len(data) < n:
            chunk = sock.recv(n - len(data))
            if not chunk:
                return None
            data += chunk
        return data

    def _get_mountd_port(self, target, timeout=4):
        """
        Query the RPC portmapper (port 111) for the mountd port.
        Portmap GETPORT: program=100005, version=1, protocol=TCP(6)
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect((target, self.PORTMAP_PORT))

                # GETPORT request body: program, version, protocol(6=TCP), port(0)
                body = struct.pack("!IIII", self.MOUNTD_PROGRAM, 1, 6, 0)
                msg, xid = self._make_rpc_call(self.PORTMAP_PROGRAM, 2, 3, body)
                s.sendall(msg)

                reply = self._recv_rpc_reply(s, timeout)
                if not reply or len(reply) < 24:
                    # Try UDP mountd port query too
                    return None

                # Reply: xid(4) + REPLY(4) + accepted(4) + verifier(8) + port(4)
                port = struct.unpack("!I", reply[-4:])[0]
                return port if 0 < port < 65536 else None

        except Exception:
            return None

    def _get_exports(self, target, mountd_port, timeout=5):
        """
        Query mountd EXPORT procedure (procedure 5) for the export list.
        Returns list of (path, clients) tuples, or None on failure.
        """
        if not mountd_port or mountd_port <= 0:
            return None

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect((target, mountd_port))

                # EXPORT procedure = 5, no arguments
                msg, xid = self._make_rpc_call(self.MOUNTD_PROGRAM, 1, 5)
                s.sendall(msg)

                reply = self._recv_rpc_reply(s, timeout)
                if not reply:
                    return None

                return self._parse_exports(reply)

        except ConnectionRefusedError:
            return None
        except Exception:
            return None

    def _parse_exports(self, data):
        """
        Parse mountd EXPORT reply.
        Format: value_follows(4) + [path_len(4) + path + groups...] + ...
        Returns list of (path, clients_str) tuples.
        """
        exports = []
        try:
            # RPC reply header:
            # xid(4) + msg_type(4) + reply_stat(4) + verifier_flavor(4)
            # + verifier_len(4) + accept_stat(4) = 24 bytes
            offset = 24

            while offset < len(data) - 4:
                value_follows = struct.unpack("!I", data[offset:offset+4])[0]
                offset += 4

                if value_follows == 0:
                    break

                # Read export path (XDR string: length + data + padding)
                if offset + 4 > len(data):
                    break
                path_len = struct.unpack("!I", data[offset:offset+4])[0]
                offset += 4

                if path_len == 0 or offset + path_len > len(data):
                    break
                path = data[offset:offset+path_len].decode(errors="ignore").rstrip("\x00")
                offset += path_len
                # XDR padding to 4-byte boundary
                offset += (4 - path_len % 4) % 4

                # Read groups list
                groups = []
                while offset < len(data) - 4:
                    grp_follows = struct.unpack("!I", data[offset:offset+4])[0]
                    offset += 4
                    if grp_follows == 0:
                        break
                    if offset + 4 > len(data):
                        break
                    grp_len = struct.unpack("!I", data[offset:offset+4])[0]
                    offset += 4
                    if grp_len == 0:
                        groups.append("*")
                        continue
                    if offset + grp_len > len(data):
                        break
                    grp = data[offset:offset+grp_len].decode(errors="ignore").rstrip("\x00")
                    offset += grp_len
                    offset += (4 - grp_len % 4) % 4
                    groups.append(grp)

                clients = ", ".join(groups) if groups else "*"
                exports.append((path, clients))

        except Exception:
            pass

        return exports if exports else []
