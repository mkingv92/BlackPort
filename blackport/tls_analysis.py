"""
MayheM-Sec Added

Interpret TLS details already collected by BlackPort and turn them into concise,
non-destructive security findings. This module does not make network requests.
"""

from __future__ import annotations

from datetime import datetime, timezone


def _days_until(value: str | None) -> int | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return (dt - datetime.now(timezone.utc)).days
    except Exception:
        return None


def analyze_tls(tls: dict | None) -> dict | None:
    """MayheM-Sec Added: summarize TLS posture from upstream enumeration data."""
    if not isinstance(tls, dict):
        return None

    flags = tls.get("flags") or {}
    cert = tls.get("certificate") or {}
    versions = tls.get("supported_tls_versions") or []
    findings: list[dict] = []

    def add(severity: str, code: str, title: str, detail: str) -> None:
        findings.append({
            "severity": severity,
            "code": code,
            "title": title,
            "detail": detail,
        })

    if flags.get("expired"):
        add("HIGH", "TLS_CERT_EXPIRED", "Expired TLS certificate", "The certificate is past its not-after date.")

    days = _days_until(cert.get("not_after"))
    if days is not None and 0 <= days <= 30:
        severity = "MEDIUM" if days <= 14 else "LOW"
        add(severity, "TLS_CERT_EXPIRING", "TLS certificate expires soon", f"Certificate expiry is approximately {days} day(s) away.")

    if flags.get("hostname_match") is False:
        add("MEDIUM", "TLS_HOSTNAME_MISMATCH", "Certificate hostname mismatch", "The certificate identity does not match the requested server name.")

    if flags.get("self_signed"):
        add("LOW", "TLS_SELF_SIGNED", "Self-signed TLS certificate", "The endpoint presented a certificate whose subject and issuer are the same.")

    if flags.get("weak_cipher"):
        add("HIGH", "TLS_WEAK_CIPHER", "Weak negotiated cipher", "The negotiated cipher matched BlackPort's conservative weak-cipher indicators.")

    weak_versions = [v for v in versions if v in {"TLSv1", "TLSv1_1"}]
    if weak_versions:
        add("HIGH", "TLS_LEGACY_PROTOCOL", "Legacy TLS protocol enabled", "Supported legacy versions: " + ", ".join(weak_versions))

    if flags.get("downgrade_risk"):
        add("MEDIUM", "TLS_DOWNGRADE_SURFACE", "Broad TLS version range", "The endpoint supports TLS 1.3 while also accepting legacy TLS versions.")

    grade = "A"
    severities = {item["severity"] for item in findings}
    if "HIGH" in severities or "CRITICAL" in severities:
        grade = "C"
    elif "MEDIUM" in severities:
        grade = "B"
    elif findings:
        grade = "B+"

    return {
        "grade": grade,
        "days_until_expiry": days,
        "supported_versions": versions,
        "findings": findings,
    }
