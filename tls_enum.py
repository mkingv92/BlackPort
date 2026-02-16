# =====================================================================
# File: tls_enum.py
# Purpose:
# - Lightweight TLS intelligence for BlackPort (certificate + cipher details)
# - Designed to be safe to call after a port is confirmed open.
# - Use only on hosts/networks you own or have explicit permission to test.
# =====================================================================

from __future__ import annotations
import tempfile
import ipaddress
import socket
import ssl
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple


# Ports that often speak TLS even if they aren't "web" ports.
TLS_LIKELY_PORTS = {
    443, 444, 465, 563, 585, 587,
    636, 989, 990, 992, 993, 994, 995,
    8443, 9443
}

# Very simple "weak cipher" heuristics. This is intentionally conservative.
WEAK_CIPHER_KEYWORDS = (
    "RC4", "3DES", "DES", "NULL", "EXPORT", "MD5", "IDEA"
)


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except Exception:
        return False


def _parse_cert_time(value: str) -> Optional[str]:
    """
    Convert OpenSSL-style time strings into ISO-ish UTC string.
    Example: 'Jun  1 12:00:00 2026 GMT'
    """
    if not value:
        return None

    # Common OpenSSL format
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b  %d %H:%M:%S %Y %Z"):
        try:
            dt = datetime.strptime(value, fmt).replace(tzinfo=timezone.utc)
            return dt.isoformat().replace("+00:00", "Z")
        except Exception:
            pass

    return value


def _cert_subject_str(cert: Dict[str, Any]) -> str:
    parts = []
    for rdn in cert.get("subject", []):
        for (k, v) in rdn:
            parts.append(f"{k}={v}")
    return ", ".join(parts)


def _cert_issuer_str(cert: Dict[str, Any]) -> str:
    parts = []
    for rdn in cert.get("issuer", []):
        for (k, v) in rdn:
            parts.append(f"{k}={v}")
    return ", ".join(parts)


def _hostname_matches(cert: Dict[str, Any], hostname: str) -> bool:
    """
    Use Python's built-in match logic when possible.
    """
    if not hostname or _is_ip(hostname):
        # If target is an IP, hostname matching isn't meaningful (unless cert has IP SANs,
        # but scanners typically evaluate hostname-based deployments).
        return True

    try:
        ssl.match_hostname(cert, hostname)
        return True
    except Exception:
        return False


def _is_self_signed(cert: Dict[str, Any]) -> bool:
    try:
        return cert.get("subject") == cert.get("issuer")
    except Exception:
        return False


def _cipher_is_weak(cipher_tuple: Optional[Tuple[str, str, int]]) -> bool:
    if not cipher_tuple:
        return False
    name = cipher_tuple[0] or ""
    up = name.upper()
    return any(k in up for k in WEAK_CIPHER_KEYWORDS)

def probe_tls_versions(host, port, server_name=None, timeout=2.5):
    supported = []

    versions_to_test = [
        ssl.TLSVersion.TLSv1,
        ssl.TLSVersion.TLSv1_1,
        ssl.TLSVersion.TLSv1_2,
        ssl.TLSVersion.TLSv1_3,
    ]

    for version in versions_to_test:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_OPTIONAL
            ctx.minimum_version = version
            ctx.maximum_version = version

            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=server_name):
                    supported.append(version.name)
        except Exception:
            continue

    return supported


def get_tls_details(
    host: str,
    port: int,
    server_name: Optional[str] = None,
    timeout: float = 2.5,
) -> Optional[Dict[str, Any]]:

    """
    Returns TLS intelligence dict, or None if TLS handshake fails.

    Includes:
      - cert subject, issuer, notBefore/notAfter, SANs
      - expired/self-signed/hostname mismatch flags
      - negotiated cipher + TLS version
    """
    # If caller did not provide SNI, use host when it's a hostname.
    if server_name is None and host and not _is_ip(host):
        server_name = host

    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

        # We want to *collect* details even if trust is sketchy.
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.load_default_certs()

        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=server_name) as ssock:
                der_cert = ssock.getpeercert(binary_form=True)
                cert = {}

                if der_cert:
                    try:
                        pem_cert = ssl.DER_cert_to_PEM_cert(der_cert)


                        with tempfile.NamedTemporaryFile(delete=False) as tmp:
                            tmp.write(pem_cert.encode())
                            tmp.flush()
                            cert = ssl._ssl._test_decode_cert(tmp.name)
                    except Exception:
                        cert = {}

                cipher = ssock.cipher()
                tls_version = ssock.version()

                # Hostname validation
                hostname_match = True
                if server_name and cert:
                    try:
                        # Check SAN first
                        san_list = cert.get("subjectAltName", [])
                        dns_names = [val for typ, val in san_list if typ == "DNS"]

                        if dns_names:
                            hostname_match = any(
                                server_name == name or
                                (name.startswith("*.") and server_name.endswith(name[1:]))
                                for name in dns_names
                            )
                        else:
                            # Fallback to common name
                            subject = cert.get("subject", [])
                            for rdn in subject:
                                for key, value in rdn:
                                    if key == "commonName":
                                        if server_name == value or (
                                            value.startswith("*.") and server_name.endswith(value[1:])
                                        ):
                                            hostname_match = True
                                            break
                                        hostname_match = False
                    except Exception:
                        hostname_match = False


        supported_versions = probe_tls_versions(host, port, server_name)

        weak_protocols = any(v in supported_versions for v in ["TLSv1", "TLSv1_1"])

        downgrade_risk = (
            "TLSv1_3" in supported_versions and
            ("TLSv1" in supported_versions or "TLSv1_1" in supported_versions)
        )

        # Core fields
        subject = _cert_subject_str(cert)
        issuer = _cert_issuer_str(cert)
        not_before_raw = cert.get("notBefore")
        not_after_raw = cert.get("notAfter")

        not_before = _parse_cert_time(not_before_raw) if not_before_raw else None
        not_after = _parse_cert_time(not_after_raw) if not_after_raw else None

        # SANs
        sans = []
        for typ, val in cert.get("subjectAltName", []):
            sans.append(f"{typ}:{val}")

        # Flags
        self_signed = _is_self_signed(cert)

        expired = False
        if not_after_raw:
            try:
                # Try parse, then compare to now UTC
                for fmt in ("%b %d %H:%M:%S %Y %Z", "%b  %d %H:%M:%S %Y %Z"):
                    try:
                        exp = datetime.strptime(not_after_raw, fmt).replace(tzinfo=timezone.utc)
                        expired = exp < datetime.now(timezone.utc)
                        break
                    except Exception:
                        continue
            except Exception:
                pass

        weak_cipher = _cipher_is_weak(cipher)

        return {
            "tls_version": tls_version,
            "cipher": {
                "name": cipher[0] if cipher else None,
                "protocol": cipher[1] if cipher else None,
                "bits": cipher[2] if cipher else None,
            },
            "certificate": {
                "subject": subject or None,
                "issuer": issuer or None,
                "not_before": not_before,
                "not_after": not_after,
                "sans": sans or None,
            },
            "flags": {
                "expired": expired,
                "hostname_match": bool(hostname_match),
                "self_signed": bool(self_signed),
                "weak_cipher": bool(weak_cipher),
                "weak_protocols": weak_protocols,
                "downgrade_risk": downgrade_risk,

            },
            "server_name_used": server_name,
            "supported_tls_versions": supported_versions,
        }

    except Exception as e:
        print(f"[TLS ERROR] {host}:{port} -> {repr(e)}")
        return None
