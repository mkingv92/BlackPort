"""
MayheM-Sec Added

Threat-intelligence helpers for BlackPort.

Adds cached lookups for CISA Known Exploited Vulnerabilities (KEV) and FIRST
EPSS. Network failures are non-fatal and always fall back to cached data when
available.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

CACHE_DIR = Path(os.path.expanduser("~/.blackport"))
KEV_CACHE = CACHE_DIR / "kev_catalog.json"
EPSS_CACHE = CACHE_DIR / "epss_cache.json"

# MayheM-Sec Added: official public data endpoints.
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
USER_AGENT = "BlackPort-MayheM-Sec/1.0 authorized-security-assessment"


def _read_json(path: Path, default):
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except Exception:
        return default


def _write_json(path: Path, value) -> None:
    try:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2)
    except Exception:
        pass


def _fresh(path: Path, ttl_seconds: int) -> bool:
    try:
        return (time.time() - path.stat().st_mtime) < ttl_seconds
    except OSError:
        return False


def load_kev_catalog(force_refresh: bool = False) -> dict[str, dict]:
    """MayheM-Sec Added: return KEV entries indexed by CVE ID."""
    cached = _read_json(KEV_CACHE, {})
    if cached and not force_refresh and _fresh(KEV_CACHE, 24 * 60 * 60):
        return cached

    try:
        req = urllib.request.Request(KEV_URL, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=12) as response:
            payload = json.loads(response.read().decode("utf-8"))
        indexed = {}
        for item in payload.get("vulnerabilities", []):
            cve = str(item.get("cveID", "")).upper().strip()
            if cve:
                indexed[cve] = {
                    "cve": cve,
                    "vendor": item.get("vendorProject"),
                    "product": item.get("product"),
                    "name": item.get("vulnerabilityName"),
                    "date_added": item.get("dateAdded"),
                    "due_date": item.get("dueDate"),
                    "known_ransomware_use": item.get("knownRansomwareCampaignUse"),
                    "required_action": item.get("requiredAction"),
                }
        _write_json(KEV_CACHE, indexed)
        return indexed
    except Exception:
        return cached


def _load_epss_cache() -> dict:
    return _read_json(EPSS_CACHE, {})


def lookup_epss(cve_id: str, force_refresh: bool = False) -> dict | None:
    """MayheM-Sec Added: return EPSS score/percentile for a CVE."""
    cve = cve_id.upper().strip()
    cache = _load_epss_cache()
    entry = cache.get(cve)
    if entry and not force_refresh:
        fetched = float(entry.get("fetched_at", 0))
        if time.time() - fetched < 24 * 60 * 60:
            return entry.get("data")

    try:
        query = urllib.parse.urlencode({"cve": cve})
        req = urllib.request.Request(f"{EPSS_URL}?{query}", headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=10) as response:
            payload = json.loads(response.read().decode("utf-8"))
        rows = payload.get("data") or []
        if not rows:
            return None
        row = rows[0]
        data = {
            "cve": cve,
            "epss": float(row.get("epss", 0.0)),
            "percentile": float(row.get("percentile", 0.0)),
            "date": row.get("date"),
        }
        cache[cve] = {"fetched_at": time.time(), "data": data}
        _write_json(EPSS_CACHE, cache)
        return data
    except Exception:
        return entry.get("data") if entry else None


def enrich_cve(cve_id: str, kev_catalog: dict[str, dict] | None = None) -> dict:
    """MayheM-Sec Added: combine KEV and EPSS into one stable structure."""
    cve = cve_id.upper().strip()
    kev_catalog = kev_catalog if kev_catalog is not None else load_kev_catalog()
    epss = lookup_epss(cve)
    kev = kev_catalog.get(cve)
    return {
        "cve": cve,
        "cisa_kev": bool(kev),
        "kev": kev,
        "epss": epss,
    }


def enrich_many(cve_ids: list[str]) -> dict[str, dict]:
    """MayheM-Sec Added: enrich a de-duplicated set of CVEs."""
    kev = load_kev_catalog()
    results = {}
    for cve in sorted({c.upper().strip() for c in cve_ids if c}):
        results[cve] = enrich_cve(cve, kev_catalog=kev)
    return results
