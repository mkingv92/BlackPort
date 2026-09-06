"""
MayheM-Sec Added

Passive web-technology hints derived from data BlackPort already collected.
This module performs no network requests and does not alter upstream scanning.
"""

from __future__ import annotations

import re


PATTERNS = [
    ("nginx", re.compile(r"\bnginx(?:/([\w.\-]+))?", re.I)),
    ("Apache HTTP Server", re.compile(r"\bApache(?:/([\w.\-]+))?", re.I)),
    ("Microsoft IIS", re.compile(r"\bMicrosoft-IIS(?:/([\w.\-]+))?", re.I)),
    ("OpenResty", re.compile(r"\bopenresty(?:/([\w.\-]+))?", re.I)),
    ("Caddy", re.compile(r"\bCaddy\b", re.I)),
    ("PHP", re.compile(r"\bPHP(?:/([\w.\-]+))?", re.I)),
    ("ASP.NET", re.compile(r"\bASP\.NET\b|X-AspNet-Version", re.I)),
    ("Express", re.compile(r"X-Powered-By:\s*Express", re.I)),
    ("Cloudflare", re.compile(r"\bcloudflare\b|server:\s*cloudflare", re.I)),
    ("WordPress", re.compile(r"\bwp-content\b|\bwp-includes\b|WordPress", re.I)),
    ("Drupal", re.compile(r"\bDrupal\b|X-Generator:\s*Drupal", re.I)),
    ("Joomla", re.compile(r"\bJoomla!?\b", re.I)),
    ("Tomcat", re.compile(r"\bApache-Coyote\b|\bTomcat\b", re.I)),
    ("Jetty", re.compile(r"\bJetty(?:\(([\w.\-]+)\))?", re.I)),
    ("Werkzeug", re.compile(r"\bWerkzeug(?:/([\w.\-]+))?", re.I)),
    ("gunicorn", re.compile(r"\bgunicorn(?:/([\w.\-]+))?", re.I)),
]


def analyze_web(result: dict) -> dict | None:
    """MayheM-Sec Added: return technology hints for HTTP-like results."""
    service = str(result.get("service") or "").upper()
    port = result.get("port")
    if service not in {"HTTP", "HTTPS"} and port not in {80, 443, 8000, 8008, 8080, 8081, 8180, 8443, 8888, 9443}:
        return None

    banner = str(result.get("banner") or "")
    title = str(result.get("http_title") or "")
    source = "\n".join([banner, title])
    technologies = []

    for name, pattern in PATTERNS:
        match = pattern.search(source)
        if not match:
            continue
        version = None
        try:
            version = match.group(1)
        except (IndexError, AttributeError):
            pass
        technologies.append({"name": name, "version": version, "confidence": 80 if banner else 60})

    # MayheM-Sec Added: de-duplicate by product name while keeping the strongest hint.
    deduped = {}
    for item in technologies:
        current = deduped.get(item["name"])
        if current is None or item["confidence"] > current["confidence"]:
            deduped[item["name"]] = item

    return {
        "title": title or None,
        "technologies": sorted(deduped.values(), key=lambda item: item["name"].lower()),
    }
