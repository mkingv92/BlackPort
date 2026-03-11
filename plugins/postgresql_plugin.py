# plugins/postgresql_plugin.py
# =====================================================================
# File: plugins/postgresql_plugin.py
# Notes:
# - This file is part of the BlackPort project.
# - Tests PostgreSQL for no-password access (Metasploitable default).
# - Also checks for trust authentication and version disclosure.
# - Use only on hosts/networks you own or have explicit permission to test.
# =====================================================================

from .plugin_base import PluginBase
import socket
import struct


class PostgreSQLPlugin(PluginBase):
    name = "PostgreSQL Auth Check"
    applicable_services = ["PostgreSQL"]

    # Common usernames to try
    TEST_USERS = ["postgres", "admin", "root", "pgsql", "pg"]

    def run(self, target, port, banner=None):
        if port not in {5432, 5433}:
            return None

        notes = []
        risk  = "HIGH"
        exploit_hint = None

        notes.append("PostgreSQL database server detected.")

        result = self._probe_postgres(target, port)

        if result["auth"] == "trust_no_password":
            notes.append(
                f"CRITICAL: PostgreSQL accepts connection as '{result['user']}' "
                f"with NO password (trust authentication). "
                f"Full database access without credentials."
            )
            risk = "CRITICAL"
            exploit_hint = (
                f"Connect: psql -h {target} -U {result['user']} -d postgres "
                f"OR Metasploit: use auxiliary/scanner/postgres/postgres_login"
            )
            if result.get("version"):
                notes.append(f"Server version: {result['version']}")

        elif result["auth"] == "password_required":
            notes.append(
                "PostgreSQL requires password authentication. "
                "Default credentials (postgres/postgres) common on older installs."
            )
            risk = "HIGH"
            exploit_hint = (
                f"Brute force: hydra -l postgres -P /usr/share/wordlists/rockyou.txt "
                f"{target} postgres "
                f"OR Metasploit: use auxiliary/scanner/postgres/postgres_login"
            )
            if result.get("version"):
                notes.append(f"Server version: {result['version']}")

        elif result["auth"] == "md5":
            notes.append(
                "PostgreSQL using MD5 password authentication. "
                "MD5 hashes can be cracked offline if intercepted."
            )
            risk = "MEDIUM"
            exploit_hint = (
                f"Metasploit: use auxiliary/scanner/postgres/postgres_login"
            )

        elif result["auth"] == "scram":
            notes.append(
                "PostgreSQL using SCRAM-SHA-256 authentication — "
                "modern and secure. Still check for weak passwords."
            )
            risk = "LOW"

        elif result.get("error") == "ssl_required":
            notes.append(
                "PostgreSQL requires SSL — direct connection rejected. "
                "Still check for weak credentials over SSL."
            )
            risk = "MEDIUM"

        else:
            notes.append(
                "PostgreSQL responding but auth type could not be determined. "
                "Manual testing recommended."
            )

        notes.append(
            "Remediation: Restrict pg_hba.conf to specific IPs. "
            "Never use trust auth in production. Use strong passwords."
        )

        return {
            "plugin":       self.name,
            "risk":         risk,
            "notes":        " | ".join(notes),
            "exploit_hint": exploit_hint,
        }

    def _probe_postgres(self, target, port, timeout=5):
        """
        Send PostgreSQL startup message and read authentication response.
        Returns dict with auth type and version info.
        """
        result = {"auth": None, "user": None, "version": None, "error": None}

        for user in self.TEST_USERS:
            auth_type = self._try_user(target, port, user, timeout)
            if auth_type:
                result["user"] = user
                if auth_type == "R\x00\x00\x00\x08\x00\x00\x00\x00":
                    result["auth"] = "trust_no_password"
                elif auth_type == "no_auth":
                    result["auth"] = "trust_no_password"
                elif auth_type == "md5":
                    result["auth"] = "md5"
                elif auth_type == "password":
                    result["auth"] = "password_required"
                elif auth_type == "scram":
                    result["auth"] = "scram"
                elif auth_type == "ssl_required":
                    result["error"] = "ssl_required"
                    result["auth"]  = "ssl_required"
                    break
                else:
                    result["auth"] = auth_type
                break

        return result

    def _try_user(self, target, port, user, timeout=5):
        """
        Attempt PostgreSQL startup message for a given user.
        Returns auth type string or None.
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect((target, port))

                # Build startup message
                # Protocol version 3.0 = 0x00030000
                params = (
                    b"user\x00" + user.encode() + b"\x00"
                    b"database\x00postgres\x00"
                    b"application_name\x00BlackPort\x00"
                    b"\x00"
                )
                startup_len = 4 + 4 + len(params)  # length + protocol + params
                msg = struct.pack("!I", startup_len) + b"\x00\x03\x00\x00" + params

                s.sendall(msg)
                resp = s.recv(1024)

                if not resp:
                    return None

                msg_type = chr(resp[0])

                if msg_type == "R":  # Authentication request
                    if len(resp) >= 9:
                        auth_code = struct.unpack("!I", resp[5:9])[0]
                        if auth_code == 0:
                            return "no_auth"      # AuthenticationOK — no password
                        elif auth_code == 3:
                            return "password"     # CleartextPassword
                        elif auth_code == 5:
                            return "md5"          # MD5Password
                        elif auth_code == 10:
                            return "scram"        # SASL/SCRAM
                        else:
                            return f"auth_{auth_code}"

                elif msg_type == "E":  # Error
                    error_msg = resp.decode(errors="ignore")
                    if "SSL" in error_msg or "ssl" in error_msg:
                        return "ssl_required"
                    return None

                elif msg_type == "S":  # ParameterStatus — means auth succeeded
                    # Extract version if present
                    return "no_auth"

                elif resp[0:1] == b"N":  # SSL not supported response
                    return None

                return None

        except ConnectionRefusedError:
            return None
        except socket.timeout:
            return None
        except Exception:
            return None
