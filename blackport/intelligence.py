# =====================================================================
# File: intelligence.py
# Notes:
# - This file is part of the BlackPort project.
# - The comments added here are for readability only (no behavior change).
# - Use only on hosts/networks you own or have explicit permission to test.
# =====================================================================

LOCAL_CVE_DB = {
    "ftp": ["CVE-2015-3306", "CVE-2011-2523"],
    "ssh": ["CVE-2018-15473"],
    "http": ["CVE-2021-41773"],
    "smb": ["CVE-2017-0144"]
}


# NOTE: get_cves() - helper/entry function. Read the body for the exact steps.
def get_cves(service):
    if not service:
        return []
    return LOCAL_CVE_DB.get(service.lower(), [])
