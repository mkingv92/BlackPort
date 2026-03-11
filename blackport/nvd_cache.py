# =====================================================================
# File: blackport/nvd_cache.py
# Notes:
# - This file is part of the BlackPort project.
# - Fetches CVE data from NVD API v2. Caches locally to avoid repeat calls.
# - Cache lives in ~/.blackport/cve_cache.json
# - Rate limit: NVD allows 5 req/30s without API key, 50 req/30s with key.
# - Use only on hosts/networks you own or have explicit permission to test.
# =====================================================================

import json
import os
import time
import re
import urllib.request
import urllib.parse
import urllib.error
from datetime import datetime, timedelta

CACHE_DIR  = os.path.expanduser("~/.blackport")
CACHE_FILE = os.path.join(CACHE_DIR, "cve_cache.json")
CACHE_TTL_DAYS = 7   # Re-fetch CVEs older than this

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Map product names to NVD keyword search terms
PRODUCT_SEARCH_MAP = {
    "vsftpd":         "vsftpd",
    "openssh":        "openssh",
    "apache":         "apache http server",
    "nginx":          "nginx",
    "php":            "php",
    "mysql":          "mysql",
    "mariadb":        "mariadb",
    "postgresql":     "postgresql",
    "samba":          "samba",
    "postfix":        "postfix",
    "sendmail":       "sendmail",
    "exim":           "exim",
    "bind":           "bind dns",
    "tomcat":         "apache tomcat",
    "proftpd":        "proftpd",
    "unrealircd":     "unrealircd",
    "openssl":        "openssl",
    "redis":          "redis",
    "mongodb":        "mongodb",
    "memcached":      "memcached",
    "elasticsearch":  "elasticsearch",
    "docker":         "docker engine",
    "wordpress":      "wordpress",
    "drupal":         "drupal",
    "joomla":         "joomla",
    "weblogic":       "oracle weblogic",
    "jboss":          "jboss",
    "glassfish":      "glassfish",
    "iis":            "microsoft iis",
    "rdp":            "remote desktop services",
    "vnc":            "vnc",
    "telnet":         "telnet",
    "snmp":           "snmp",
    "tftp":           "tftp",
    "rsync":          "rsync",
    "distccd":        "distcc",
}


def _load_cache():
    """Load the local CVE cache from disk."""
    os.makedirs(CACHE_DIR, exist_ok=True)
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, "r") as f:
                return json.load(f)
        except Exception:
            pass
    return {}


def _save_cache(cache):
    """Save the CVE cache to disk."""
    os.makedirs(CACHE_DIR, exist_ok=True)
    try:
        with open(CACHE_FILE, "w") as f:
            json.dump(cache, f, indent=2)
    except Exception:
        pass


def _cache_key(product, version):
    """Generate a cache key for a product/version pair."""
    prod = (product or "").lower().strip()
    ver  = (version or "").strip()
    return f"{prod}::{ver}"


def _is_cache_fresh(entry):
    """Return True if a cache entry is within TTL."""
    try:
        fetched = datetime.fromisoformat(entry.get("fetched_at", "2000-01-01"))
        return datetime.now() - fetched < timedelta(days=CACHE_TTL_DAYS)
    except Exception:
        return False


def _fetch_nvd(product, version, api_key=None):
    """
    Fetch CVEs from NVD API v2 for a product/version.
    Returns a list of CVE dicts: {id, cvss, description, published}
    """
    search_term = PRODUCT_SEARCH_MAP.get(product.lower(), product.lower())

    params = {
        "keywordSearch": search_term,
        "resultsPerPage": 20,
        "startIndex": 0,
    }

    if version:
        # Add version to narrow results
        params["keywordSearch"] = f"{search_term} {version}"

    url = f"{NVD_API_URL}?{urllib.parse.urlencode(params)}"

    headers = {"User-Agent": "BlackPort Security Scanner"}
    if api_key:
        headers["apiKey"] = api_key

    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=8) as resp:
            data = json.loads(resp.read().decode())

        cves = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id", "")

            # Get CVSS score (prefer v3.1 > v3.0 > v2)
            metrics = cve.get("metrics", {})
            cvss_score = None
            severity = "UNKNOWN"

            for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if key in metrics and metrics[key]:
                    m = metrics[key][0]
                    if "cvssData" in m:
                        cvss_score = m["cvssData"].get("baseScore")
                        severity   = m["cvssData"].get("baseSeverity", "UNKNOWN")
                        break

            # Get description (English preferred)
            desc = ""
            for d in cve.get("descriptions", []):
                if d.get("lang") == "en":
                    desc = d.get("value", "")[:200]
                    break

            published = cve.get("published", "")[:10]

            if cve_id:
                cves.append({
                    "id":          cve_id,
                    "cvss":        cvss_score,
                    "severity":    severity,
                    "description": desc,
                    "published":   published,
                })

        # Sort by CVSS score descending
        cves.sort(key=lambda x: x.get("cvss") or 0, reverse=True)
        return cves[:10]  # cap at top 10

    except urllib.error.URLError:
        return None  # Network unavailable — caller uses static DB
    except Exception:
        return None


def lookup_cves(product, version, api_key=None, offline=False):
    """
    Main entry point: look up CVEs for a product/version.

    1. Check local cache (fresh within TTL)
    2. If stale/missing and not offline → fetch from NVD
    3. Cache result
    4. Return list of CVE dicts, or [] if none found

    Args:
        product:  Product name e.g. "Apache", "OpenSSH"
        version:  Version string e.g. "2.2.8", "4.7p1"
        api_key:  Optional NVD API key for higher rate limits
        offline:  If True, only use cache — never hit network
    """
    if not product:
        return []

    cache = _load_cache()
    key   = _cache_key(product, version)

    # Cache hit — return if fresh
    if key in cache and _is_cache_fresh(cache[key]):
        return cache[key].get("cves", [])

    if offline:
        return cache.get(key, {}).get("cves", [])

    # Fetch from NVD
    cves = _fetch_nvd(product, version, api_key)

    if cves is not None:
        cache[key] = {
            "product":    product,
            "version":    version,
            "cves":       cves,
            "fetched_at": datetime.now().isoformat(),
        }
        _save_cache(cache)
        return cves

    # Network failed — return stale cache if available
    return cache.get(key, {}).get("cves", [])


def get_top_cve(cves):
    """
    From a list of CVE dicts, return the highest-severity one
    as a BlackPort-compatible cve_info dict.
    Returns None if cves is empty.
    """
    if not cves:
        return None

    top = cves[0]  # already sorted by CVSS descending

    cvss = top.get("cvss") or 0
    if cvss >= 9.0:
        bp_severity = "CRITICAL"
    elif cvss >= 7.0:
        bp_severity = "HIGH"
    elif cvss >= 4.0:
        bp_severity = "MEDIUM"
    else:
        bp_severity = "LOW"

    return {
        "cve":         top["id"],
        "cvss":        cvss,
        "severity":    bp_severity,
        "description": top["description"],
        "exploit":     cvss >= 9.0,  # assume exploitable if CVSS >= 9
    }


def clear_cache():
    """Remove the local CVE cache file."""
    if os.path.exists(CACHE_FILE):
        os.remove(CACHE_FILE)
        print(f"[*] CVE cache cleared: {CACHE_FILE}")


def cache_stats():
    """Print cache statistics."""
    cache = _load_cache()
    total = len(cache)
    fresh = sum(1 for v in cache.values() if _is_cache_fresh(v))
    print(f"[*] CVE cache: {total} entries, {fresh} fresh, {total-fresh} stale")
    print(f"    Location: {CACHE_FILE}")
