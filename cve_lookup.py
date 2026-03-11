# =====================================================================
# File: cve_lookup.py
# Notes:
# - This file is part of the BlackPort project.
# - The comments added here are for readability only (no behavior change).
# - Use only on hosts/networks you own or have explicit permission to test.
# =====================================================================

import json

# NOTE: load_cve_db() - helper/entry function. Read the body for the exact steps.
def load_cve_db():
    with open("cve_db.json", "r") as f:
        return json.load(f)

# NOTE: match_cves() - helper/entry function. Read the body for the exact steps.
def match_cves(banner, cve_db):
    matches = []
    for software, data in cve_db.items():
        if banner and software.lower() in banner.lower():
            matches.append({
                "software": software,
                "cves": data["cves"],
                "severity": data["severity"],
                "notes": data["notes"]
            })
    return matches
