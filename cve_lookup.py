import json

def load_cve_db():
    with open("cve_db.json", "r") as f:
        return json.load(f)

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
