# =====================================================================
# File: cve_db.py
# Notes:
# - This file is part of the BlackPort project.
# - The comments added here are for readability only (no behavior change).
# - Use only on hosts/networks you own or have explicit permission to test.
# =====================================================================

CVE_DATABASE = {
    "vsFTPd 2.3.4": {
        "cve": "CVE-2011-2523",
        "cvss": 9.8,
        "severity": "CRITICAL",
        "exploit": True,
        "description": "Backdoor command execution vulnerability"
    },
    "Apache 2.2": {
        "cve": "Multiple CVEs",
        "cvss": 8.5,
        "severity": "HIGH",
        "exploit": True,
        "description": "Outdated Apache 2.2.x vulnerabilities"
    },
    "OpenSSH 4.7": {
        "cve": "CVE-2008-4109",
        "cvss": 7.5,
        "severity": "HIGH",
        "exploit": False,
        "description": "User enumeration vulnerability"
    }
}


# NOTE: check_cve() - helper/entry function. Read the body for the exact steps.
def check_cve(product, version):
    full_string = f"{product} {version}"

    for key in CVE_DATABASE:
        if key in full_string:
            return CVE_DATABASE[key]

    return None
