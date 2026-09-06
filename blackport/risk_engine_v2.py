"""
MayheM-Sec Added

Second-generation confidence and risk scoring for BlackPort findings.

The upstream risk field is preserved. This module adds separate MayheM-Sec
scores so the fork can improve prioritization without changing upstream logic.
"""

from __future__ import annotations


def confidence_score(result: dict) -> int:
    """MayheM-Sec Added: estimate confidence using evidence already collected."""
    score = 20
    if result.get("service") and str(result.get("service")).lower() != "unknown":
        score += 15
    if result.get("banner"):
        score += 15
    if result.get("product"):
        score += 15
    if result.get("version"):
        score += 10
    upstream = result.get("confidence")
    if isinstance(upstream, (int, float)):
        score += min(15, max(0, int(upstream) // 7))
    if result.get("cve_info"):
        score += 5
    if result.get("plugins"):
        score += 15
    if result.get("verified_by") == "syn":
        score += 5
    return max(0, min(100, score))


def risk_score(result: dict, intelligence: list[dict] | None = None) -> dict:
    """MayheM-Sec Added: calculate a 0-10 exposure score for one finding."""
    intelligence = intelligence or []
    base = {"LOW": 2.0, "MEDIUM": 4.5, "HIGH": 7.0, "CRITICAL": 9.0}.get(
        str(result.get("risk", "LOW")).upper(), 2.0
    )

    cve_info = result.get("cve_info") or {}
    cvss = cve_info.get("cvss")
    if isinstance(cvss, (int, float)):
        base = max(base, min(10.0, float(cvss)))

    kev = any(item.get("cisa_kev") for item in intelligence)
    epss_values = [
        item.get("epss", {}).get("epss")
        for item in intelligence
        if isinstance(item.get("epss"), dict)
    ]
    epss_values = [float(v) for v in epss_values if isinstance(v, (int, float))]
    max_epss = max(epss_values, default=0.0)

    if kev:
        base += 0.8
    if max_epss >= 0.9:
        base += 0.8
    elif max_epss >= 0.5:
        base += 0.4
    elif max_epss >= 0.1:
        base += 0.2

    plugins = result.get("plugins") or []
    if plugins:
        base += 0.5
        if any(str(p.get("risk", "")).upper() == "CRITICAL" for p in plugins if isinstance(p, dict)):
            base += 0.4

    confidence = confidence_score(result)
    adjusted = min(10.0, base * (0.65 + (confidence / 100.0) * 0.35))
    score = round(adjusted, 1)

    if score >= 9.0:
        severity = "CRITICAL"
    elif score >= 7.0:
        severity = "HIGH"
    elif score >= 4.0:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    return {
        "score": score,
        "severity": severity,
        "confidence": confidence,
        "cisa_kev": kev,
        "max_epss": round(max_epss, 6),
    }
