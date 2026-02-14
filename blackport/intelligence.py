LOCAL_CVE_DB = {
    "ftp": ["CVE-2015-3306", "CVE-2011-2523"],
    "ssh": ["CVE-2018-15473"],
    "http": ["CVE-2021-41773"],
    "smb": ["CVE-2017-0144"]
}


def get_cves(service):
    if not service:
        return []
    return LOCAL_CVE_DB.get(service.lower(), [])
