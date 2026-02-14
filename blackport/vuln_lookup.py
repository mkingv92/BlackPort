def lookup_vulnerabilities(banner):
    vulns = []

    if "vsftpd 2.3.4" in banner:
        vulns.append("CVE-2011-2523 - Backdoor Command Execution")

    if "OpenSSH 4.7" in banner:
        vulns.append("CVE-2008-4109 - OpenSSH Username Enumeration")

    return vulns
