# plugins/postgres_plugin.py
from .plugin_base import PluginBase
import socket
import struct

# Common default credential pairs to test
DEFAULT_CREDS = [
    (b"postgres", b"postgres"),
    (b"postgres", b""),
    (b"postgres", b"password"),
    (b"admin", b"admin"),
    (b"root", b"root"),
    (b"root", b""),
]

class PostgreSQLPlugin(PluginBase):
    name = "PostgreSQL Security Check"
    applicable_services = ["Unknown"]  # fingerprinted as Unknown on non-standard config

    def run(self, target, port, banner=None):
        # Only run on port 5432
        if port != 5432:
            return None

        notes = []
        risk = "HIGH"
        exploit_hint = None

        notes.append("PostgreSQL exposed on network — database should not be directly accessible.")

        # --- Step 1: Confirm PostgreSQL is running and get version ---
        pg_version = self._get_pg_version(target, port)
        if pg_version:
            notes.append(f"PostgreSQL version: {pg_version}")
        else:
            notes.append("Could not confirm PostgreSQL version — service may require SSL.")

        # --- Step 2: Test default credentials ---
        cracked = self._test_default_creds(target, port)
        if cracked:
            user, password = cracked
            pwd_display = password.decode() if password else "(empty)"
            notes.append(f"CRITICAL: Default credentials accepted — user '{user.decode()}' with password '{pwd_display}'.")
            risk = "CRITICAL"
            exploit_hint = (
                f"Connect directly: psql -h {target} -U {user.decode()} -p {port} "
                f"OR use Metasploit: auxiliary/scanner/postgres/postgres_login"
            )
        else:
            notes.append("Default credentials rejected — custom password in use.")
            exploit_hint = f"Brute-force: hydra -l postgres -P /usr/share/wordlists/rockyou.txt postgres://{target}"

        # --- Step 3: Remediation ---
        notes.append("Remediation: Restrict pg_hba.conf to localhost only and disable remote superuser login.")

        return {
            "plugin": self.name,
            "risk": risk,
            "notes": " | ".join(notes),
            "exploit_hint": exploit_hint
        }

    def _build_startup_message(self, user, database=b"template1"):
        """Build a PostgreSQL startup message packet."""
        params = b"user\x00" + user + b"\x00database\x00" + database + b"\x00\x00"
        # Protocol version 3.0
        protocol = struct.pack(">I", 196608)
        body = protocol + params
        length = struct.pack(">I", len(body) + 4)
        return length + body

    def _get_pg_version(self, target, port):
        """Attempt to read PostgreSQL version from error response."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(3)
                s.connect((target, port))
                s.sendall(self._build_startup_message(b"postgres"))
                data = s.recv(4096).decode(errors="ignore")

                # Look for version string in error or auth response
                import re
                match = re.search(r"PostgreSQL (\d+\.\d+[\.\d]*)", data)
                if match:
                    return match.group(1)

                # Check if we got an auth request (R packet) — means server is alive
                if data and data[0] == 'R':
                    return "unknown version"

        except Exception:
            pass
        return None

    def _test_default_creds(self, target, port):
        """
        Test a list of default credential pairs using the PostgreSQL wire protocol.
        Only tests cleartext password auth (AuthenticationCleartextPassword).
        Returns (user, password) tuple if successful, None otherwise.
        """
        for user, password in DEFAULT_CREDS:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(3)
                    s.connect((target, port))

                    # Send startup message
                    s.sendall(self._build_startup_message(user))
                    data = s.recv(1024)

                    if not data:
                        continue

                    msg_type = chr(data[0])

                    if msg_type == 'R':  # Authentication request
                        auth_type = struct.unpack(">I", data[5:9])[0]

                        if auth_type == 0:
                            # AuthenticationOk — no password needed
                            return (user, b"")

                        elif auth_type == 3:
                            # AuthenticationCleartextPassword
                            pwd_msg = b"p" + struct.pack(">I", len(password) + 5) + password + b"\x00"
                            s.sendall(pwd_msg)
                            resp = s.recv(1024)
                            if resp and chr(resp[0]) == 'R':
                                auth_resp = struct.unpack(">I", resp[5:9])[0]
                                if auth_resp == 0:
                                    return (user, password)

                        elif auth_type == 5:
                            # MD5 password — skip for now (would need MD5 implementation)
                            continue

                    elif msg_type == 'E':
                        # Error — wrong creds or access denied
                        continue

            except Exception:
                continue

        return None
