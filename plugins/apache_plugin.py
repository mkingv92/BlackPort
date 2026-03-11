# plugins/apache_plugin.py
from .plugin_base import PluginBase
import socket
import re

# PHP versions with known critical issues
VULNERABLE_PHP = {
    "5.2": ("CRITICAL", "PHP 5.2.x — end of life since 2011, numerous RCE and injection CVEs."),
    "5.3": ("HIGH",     "PHP 5.3.x — end of life since 2014, multiple known vulnerabilities."),
    "5.4": ("HIGH",     "PHP 5.4.x — end of life since 2015, multiple known vulnerabilities."),
    "5.5": ("MEDIUM",   "PHP 5.5.x — end of life since 2016."),
    "5.6": ("MEDIUM",   "PHP 5.6.x — end of life since 2018, security fixes only period long over."),
    "7.0": ("MEDIUM",   "PHP 7.0.x — end of life since 2018."),
    "7.1": ("MEDIUM",   "PHP 7.1.x — end of life since 2019."),
    "7.2": ("LOW",      "PHP 7.2.x — end of life since 2020."),
}

# Apache versions known to be outdated/vulnerable
VULNERABLE_APACHE = {
    "2.2": ("HIGH",   "Apache 2.2.x — end of life since 2018, multiple unpatched CVEs."),
    "2.0": ("CRITICAL","Apache 2.0.x — extremely outdated, critical vulnerabilities exist."),
    "1.3": ("CRITICAL","Apache 1.3.x — ancient, should never be internet-facing."),
}

class ApachePlugin(PluginBase):
    name = "Apache CVE Expander"
    applicable_services = ["HTTP", "HTTPS"]

    def run(self, target, port, banner=None):
        notes = []
        risk = "LOW"
        exploit_hint = None

        if not banner:
            return None

        # --- Step 1: Parse Apache version from banner ---
        apache_match = re.search(r"Apache/(\d+\.\d+)\.?(\d*)", banner, re.IGNORECASE)
        if apache_match:
            apache_major_minor = apache_match.group(1)
            apache_full = apache_match.group(0).replace("Apache/", "")

            for vuln_ver, (ver_risk, ver_note) in VULNERABLE_APACHE.items():
                if apache_major_minor.startswith(vuln_ver):
                    notes.append(f"Apache {apache_full}: {ver_note}")
                    risk = ver_risk
                    break

        # --- Step 2: Parse PHP version from banner ---
        php_match = re.search(r"PHP/(\d+\.\d+)\.?(\d*)", banner, re.IGNORECASE)
        if php_match:
            php_major_minor = php_match.group(1)
            php_full = php_match.group(0).replace("PHP/", "")

            for vuln_ver, (ver_risk, ver_note) in VULNERABLE_PHP.items():
                if php_major_minor.startswith(vuln_ver):
                    notes.append(f"PHP {php_full}: {ver_note}")
                    # Escalate risk if PHP is worse
                    risk_order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
                    if risk_order[ver_risk] > risk_order[risk]:
                        risk = ver_risk
                    if ver_risk == "CRITICAL":
                        exploit_hint = (
                            f"PHP {php_full} has known RCE vectors. "
                            "Check: searchsploit php " + php_full
                        )
                    break

        # --- Step 3: Check for WebDAV (DAV/2 in banner) ---
        if "dav/2" in banner.lower() or "dav/1" in banner.lower():
            notes.append("WebDAV enabled — may allow unauthenticated file upload (CVE-2017-9798 class).")
            if risk in ["LOW", "MEDIUM"]:
                risk = "HIGH"
            exploit_hint = exploit_hint or "WebDAV file upload: davtest -url http://target/ OR cadaver http://target/"

        # --- Step 4: Probe for server-status page (info disclosure) ---
        status_exposed = self._check_server_status(target, port)
        if status_exposed:
            notes.append("Apache /server-status exposed — leaks active connections, IPs, and request URIs.")
            if risk == "LOW":
                risk = "MEDIUM"

        # --- Step 5: Check for directory listing ---
        listing_exposed = self._check_directory_listing(target, port)
        if listing_exposed:
            notes.append("Directory listing enabled — file enumeration possible without authentication.")
            if risk == "LOW":
                risk = "MEDIUM"

        if not notes:
            return None

        return {
            "plugin": self.name,
            "risk": risk,
            "notes": " | ".join(notes),
            "exploit_hint": exploit_hint
        }

    def _check_server_status(self, target, port):
        """Check if /server-status is publicly accessible."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(3)
                s.connect((target, port))
                request = b"GET /server-status HTTP/1.0\r\nHost: " + target.encode() + b"\r\n\r\n"
                s.sendall(request)
                response = s.recv(4096).decode(errors="ignore")
                if "200" in response and "server status" in response.lower():
                    return True
        except Exception:
            pass
        return False

    def _check_directory_listing(self, target, port):
        """Check if directory listing is enabled on the root."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(3)
                s.connect((target, port))
                request = b"GET / HTTP/1.0\r\nHost: " + target.encode() + b"\r\n\r\n"
                s.sendall(request)
                response = s.recv(4096).decode(errors="ignore")
                if "index of /" in response.lower():
                    return True
        except Exception:
            pass
        return False
