# plugins/vnc_plugin.py
# =====================================================================
# File: plugins/vnc_plugin.py
# Notes:
# - This file is part of the BlackPort project.
# - Checks VNC for no-authentication, weak auth, and version disclosure.
# - Metasploitable runs VNC with no password on port 5900.
# - Use only on hosts/networks you own or have explicit permission to test.
# =====================================================================

from .plugin_base import PluginBase
import socket
import struct


class VNCPlugin(PluginBase):
    name = "VNC Auth Check"
    applicable_services = ["VNC", "RFB"]

    # VNC security type constants
    SEC_NONE        = 1   # No authentication
    SEC_VNC_AUTH    = 2   # VNC password auth
    SEC_RA2         = 5
    SEC_RA2NE       = 6
    SEC_TIGHT       = 16
    SEC_ULTRA       = 17
    SEC_TLS         = 18
    SEC_VENCRYPT    = 19
    SEC_SASL        = 20
    SEC_MS_LOGON    = 35

    SEC_NAMES = {
        1:  "None (no auth)",
        2:  "VNC Authentication",
        5:  "RA2",
        6:  "RA2ne",
        16: "Tight",
        17: "Ultra",
        18: "TLS",
        19: "VeNCrypt",
        20: "SASL",
        35: "MS Logon",
    }

    def run(self, target, port, banner=None):
        if port not in {5900, 5901, 5902, 5903}:
            return None

        notes = []
        risk  = "MEDIUM"
        exploit_hint = None

        # Extract RFB version from banner
        rfb_version = None
        if banner and banner.startswith("RFB"):
            rfb_version = banner.strip()
            notes.append(f"VNC RFB protocol: {rfb_version}")

        result = self._probe_vnc_auth(target, port)

        if result["auth_type"] == self.SEC_NONE:
            notes.append(
                "CRITICAL: VNC configured with NO authentication — "
                "direct desktop access without any password."
            )
            risk = "CRITICAL"
            exploit_hint = (
                f"Connect directly: vncviewer {target}:{port} "
                f"OR: remmina vnc://{target}:{port}"
            )

        elif result["auth_type"] == self.SEC_VNC_AUTH:
            notes.append(
                "VNC password authentication required. "
                "VNC passwords are limited to 8 characters and trivially brute-forced."
            )
            if result.get("weak_password"):
                notes.append(
                    f"CRITICAL: Default/weak password accepted: '{result['weak_password']}'"
                )
                risk = "CRITICAL"
                exploit_hint = (
                    f"Connect: vncviewer -passwd <(echo -n '{result['weak_password']}') {target}:{port}"
                )
            else:
                risk = "HIGH"
                exploit_hint = (
                    f"Brute force: hydra -P /usr/share/wordlists/rockyou.txt "
                    f"-s {port} {target} vnc "
                    f"OR Metasploit: use auxiliary/scanner/vnc/vnc_login"
                )

        elif result["auth_type"] is not None:
            sec_name = self.SEC_NAMES.get(result["auth_type"], f"type {result['auth_type']}")
            notes.append(f"VNC security type: {sec_name}")
            risk = "MEDIUM"

        elif result.get("error"):
            notes.append(
                "VNC port responding but auth probe failed — "
                "service may require specific client version."
            )
            risk = "MEDIUM"

        else:
            notes.append("VNC detected — manual auth verification recommended.")
            risk = "HIGH"

        # Always flag VNC exposure
        notes.append(
            "VNC exposes full desktop graphical access. "
            "Restrict with firewall rules and require strong authentication."
        )

        if result.get("security_types"):
            type_names = [self.SEC_NAMES.get(t, str(t)) for t in result["security_types"]]
            notes.append(f"Supported auth types: {', '.join(type_names)}")

        return {
            "plugin":       self.name,
            "risk":         risk,
            "notes":        " | ".join(notes),
            "exploit_hint": exploit_hint,
        }

    def _probe_vnc_auth(self, target, port, timeout=5):
        """
        Perform VNC handshake to determine authentication type.
        Handles both RFB 3.3 and RFB 3.7/3.8 handshake formats.
        Returns dict with auth_type, security_types, weak_password.
        """
        result = {
            "auth_type":     None,
            "security_types": [],
            "weak_password": None,
            "error":         None,
        }

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect((target, port))

                # Receive server version
                server_ver = s.recv(12).decode(errors="ignore").strip()
                if not server_ver.startswith("RFB"):
                    result["error"] = "not_vnc"
                    return result

                # Send client version — match server or use 3.8
                if "003.008" in server_ver or "3.8" in server_ver:
                    s.sendall(b"RFB 003.008\n")
                    proto = "3.8"
                elif "003.007" in server_ver or "3.7" in server_ver:
                    s.sendall(b"RFB 003.007\n")
                    proto = "3.7"
                else:
                    s.sendall(b"RFB 003.003\n")
                    proto = "3.3"

                # Read security types
                if proto == "3.3":
                    # RFB 3.3: server sends 4-byte security type directly
                    sec_data = s.recv(4)
                    if len(sec_data) < 4:
                        result["error"] = "short_read"
                        return result
                    sec_type = struct.unpack("!I", sec_data)[0]
                    result["auth_type"]      = sec_type
                    result["security_types"] = [sec_type]

                else:
                    # RFB 3.7/3.8: server sends list of security types
                    count_data = s.recv(1)
                    if not count_data:
                        result["error"] = "short_read"
                        return result
                    count = count_data[0]

                    if count == 0:
                        # Server sent error
                        result["error"] = "server_error"
                        return result

                    sec_types = list(s.recv(count))
                    result["security_types"] = sec_types

                    # Choose the weakest type (prefer None > VNC auth)
                    if self.SEC_NONE in sec_types:
                        chosen = self.SEC_NONE
                    elif self.SEC_VNC_AUTH in sec_types:
                        chosen = self.SEC_VNC_AUTH
                    else:
                        chosen = sec_types[0]

                    result["auth_type"] = chosen

                    # Send chosen security type
                    s.sendall(bytes([chosen]))

                # If no auth selected, check server response
                if result["auth_type"] == self.SEC_NONE:
                    # RFB 3.8: server sends SecurityResult
                    if proto == "3.8":
                        try:
                            sec_result = s.recv(4)
                            if sec_result == b"\x00\x00\x00\x00":
                                pass  # OK — confirmed no auth
                        except Exception:
                            pass
                    # No auth = confirmed, already set

                elif result["auth_type"] == self.SEC_VNC_AUTH:
                    # Try common weak passwords
                    result["weak_password"] = self._try_vnc_passwords(s)

        except ConnectionRefusedError:
            result["error"] = "refused"
        except socket.timeout:
            result["error"] = "timeout"
        except Exception as e:
            result["error"] = str(e)

        return result

    def _try_vnc_passwords(self, sock, timeout=3):
        """
        Attempt VNC DES challenge-response with common weak passwords.
        VNC uses a DES challenge where the password is the key.
        Returns the password if successful, None otherwise.
        """
        COMMON_PASSWORDS = ["", "password", "vnc", "admin", "1234", "123456", "secret"]

        try:
            # Receive 16-byte DES challenge
            challenge = sock.recv(16)
            if len(challenge) != 16:
                return None

            for pwd in COMMON_PASSWORDS:
                try:
                    response = self._vnc_des_response(challenge, pwd)
                    sock.sendall(response)
                    result = sock.recv(4)
                    if result == b"\x00\x00\x00\x00":
                        return pwd if pwd else "(empty/no password)"
                except Exception:
                    continue

        except Exception:
            pass

        return None

    def _vnc_des_response(self, challenge, password):
        """
        Compute VNC DES challenge response.
        VNC reverses bit order of each byte in the password key.
        """
        # Pad/truncate password to 8 bytes
        key = password.encode("latin-1")[:8].ljust(8, b"\x00")

        # VNC reverses the bit order of each byte in the key
        reversed_key = bytes(int(f"{b:08b}"[::-1], 2) for b in key)

        try:
            from Crypto.Cipher import DES
            cipher = DES.new(reversed_key, DES.MODE_ECB)
            return cipher.encrypt(challenge)
        except ImportError:
            # pycryptodome not available — return dummy response
            return b"\x00" * 16
