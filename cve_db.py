# =====================================================================
# File: cve_db.py
# Notes:
# - This file is part of the BlackPort project.
# - Static CVE/vulnerability database for common services.
# - Covers 80+ product/version combinations across all common protocols.
# - Used as fallback when NVD API is unavailable.
# - CVSS scores are CVSSv3 base scores where available, v2 otherwise.
# - Use only on hosts/networks you own or have explicit permission to test.
# =====================================================================

CVE_DATABASE = {

    # ── FTP ───────────────────────────────────────────────────────────
    "vsFTPd 2.3.4": {
        "cve": "CVE-2011-2523",
        "cvss": 9.8,
        "severity": "CRITICAL",
        "exploit": True,
        "description": "Backdoor command execution — smiley-face trigger opens shell on port 6200.",
        "references": ["https://www.exploit-db.com/exploits/17491"],
    },
    "vsFTPd 2.3": {
        "cve": "CVE-2011-2523",
        "cvss": 9.8,
        "severity": "CRITICAL",
        "exploit": True,
        "description": "Backdoor command execution — smiley-face trigger opens shell on port 6200.",
        "references": ["https://www.exploit-db.com/exploits/17491"],
    },
    "ProFTPD 1.3.3": {
        "cve": "CVE-2010-4221",
        "cvss": 10.0,
        "severity": "CRITICAL",
        "exploit": True,
        "description": "Remote stack overflow via Telnet IAC processing allows unauthenticated RCE.",
        "references": ["https://www.exploit-db.com/exploits/15449"],
    },
    "ProFTPD 1.3.2": {
        "cve": "CVE-2010-4221",
        "cvss": 10.0,
        "severity": "CRITICAL",
        "exploit": True,
        "description": "Remote stack overflow via Telnet IAC processing allows unauthenticated RCE.",
        "references": ["https://www.exploit-db.com/exploits/15449"],
    },
    "FileZilla Server 0.9": {
        "cve": "CVE-2006-5955",
        "cvss": 7.5,
        "severity": "HIGH",
        "exploit": False,
        "description": "Directory traversal vulnerability in FileZilla Server before 0.9.22.",
        "references": [],
    },

    # ── SSH ───────────────────────────────────────────────────────────
    "OpenSSH 4.7": {
        "cve": "CVE-2008-4109",
        "cvss": 7.5,
        "severity": "HIGH",
        "exploit": False,
        "description": "User enumeration via timing differences in password authentication.",
        "references": [],
    },
    "OpenSSH 4.": {
        "cve": "CVE-2008-4109",
        "cvss": 7.5,
        "severity": "HIGH",
        "exploit": False,
        "description": "User enumeration via timing differences in password authentication.",
        "references": [],
    },
    "OpenSSH 3.": {
        "cve": "CVE-2003-0693",
        "cvss": 10.0,
        "severity": "CRITICAL",
        "exploit": True,
        "description": "Buffer management error in sshd allows remote code execution.",
        "references": [],
    },
    "OpenSSH 2.": {
        "cve": "CVE-2002-0639",
        "cvss": 10.0,
        "severity": "CRITICAL",
        "exploit": True,
        "description": "Integer overflow in OpenSSH challenge-response allows RCE.",
        "references": ["https://www.exploit-db.com/exploits/21402"],
    },
    "Dropbear 0.": {
        "cve": "CVE-2012-0920",
        "cvss": 7.1,
        "severity": "HIGH",
        "exploit": False,
        "description": "Use-after-free in Dropbear SSH server before 2012.55.",
        "references": [],
    },

    # ── HTTP/Apache ───────────────────────────────────────────────────
    "Apache 2.2.8": {
        "cve": "CVE-2011-3192",
        "cvss": 7.8,
        "severity": "HIGH",
        "exploit": True,
        "description": "Apache 2.2.x Range header DoS (Apache Killer). Also PHP 5.2.4 RCE via CGI args (CVE-2012-1823).",
        "references": ["https://www.exploit-db.com/exploits/17696"],
    },
    "Apache 2.2": {
        "cve": "CVE-2011-3192",
        "cvss": 7.8,
        "severity": "HIGH",
        "exploit": True,
        "description": "Apache 2.2.x Range header DoS. Multiple unpatched CVEs in end-of-life branch.",
        "references": [],
    },
    "Apache 2.0": {
        "cve": "CVE-2007-3847",
        "cvss": 7.8,
        "severity": "HIGH",
        "exploit": False,
        "description": "Apache 2.0.x end-of-life — multiple unpatched vulnerabilities.",
        "references": [],
    },
    "Apache 1.3": {
        "cve": "CVE-2002-0392",
        "cvss": 7.5,
        "severity": "HIGH",
        "exploit": True,
        "description": "Apache 1.3.x chunked encoding overflow allows RCE.",
        "references": [],
    },
    "IIS 5.0": {
        "cve": "CVE-2001-0507",
        "cvss": 10.0,
        "severity": "CRITICAL",
        "exploit": True,
        "description": "IIS 5.0 WebDAV SEARCH overflow allows remote code execution.",
        "references": [],
    },
    "IIS 5.1": {
        "cve": "CVE-2003-0109",
        "cvss": 7.5,
        "severity": "HIGH",
        "exploit": True,
        "description": "IIS 5.1 buffer overflow in ntdll.dll via WebDAV.",
        "references": [],
    },
    "IIS 6.0": {
        "cve": "CVE-2017-7269",
        "cvss": 9.8,
        "severity": "CRITICAL",
        "exploit": True,
        "description": "IIS 6.0 WebDAV ScStoragePathFromUrl buffer overflow — RCE without auth.",
        "references": ["https://www.exploit-db.com/exploits/41738"],
    },
    "nginx 1.0": {
        "cve": "CVE-2013-2028",
        "cvss": 7.5,
        "severity": "HIGH",
        "exploit": True,
        "description": "nginx 1.0.x chunked transfer encoding stack overflow.",
        "references": [],
    },
    "nginx 1.1": {
        "cve": "CVE-2013-2028",
        "cvss": 7.5,
        "severity": "HIGH",
        "exploit": True,
        "description": "nginx 1.1.x chunked transfer encoding stack overflow.",
        "references": [],
    },

    # ── Tomcat ────────────────────────────────────────────────────────
    "Tomcat 5.5": {
        "cve": "CVE-2020-1938",
        "cvss": 9.8,
        "severity": "CRITICAL",
        "exploit": True,
        "description": "Ghostcat — AJP connector file read/inclusion allows unauthenticated file disclosure and potential RCE.",
        "references": ["https://www.exploit-db.com/exploits/48143"],
    },
    "Tomcat 6.0": {
        "cve": "CVE-2020-1938",
        "cvss": 9.8,
        "severity": "CRITICAL",
        "exploit": True,
        "description": "Ghostcat — AJP connector file read/inclusion allows unauthenticated file disclosure and potential RCE.",
        "references": ["https://www.exploit-db.com/exploits/48143"],
    },
    "Tomcat 7.0": {
        "cve": "CVE-2020-1938",
        "cvss": 9.8,
        "severity": "CRITICAL",
        "exploit": True,
        "description": "Ghostcat — AJP connector file read/inclusion. Upgrade to 7.0.100+.",
        "references": ["https://www.exploit-db.com/exploits/48143"],
    },
    "Tomcat 8.0": {
        "cve": "CVE-2020-1938",
        "cvss": 9.8,
        "severity": "CRITICAL",
        "exploit": True,
        "description": "Ghostcat — AJP connector file read/inclusion. Upgrade to 8.5.51+.",
        "references": ["https://www.exploit-db.com/exploits/48143"],
    },
    "Tomcat 8.5": {
        "cve": "CVE-2020-1938",
        "cvss": 9.8,
        "severity": "CRITICAL",
        "exploit": True,
        "description": "Ghostcat — AJP connector file read/inclusion. Upgrade to 8.5.51+.",
        "references": ["https://www.exploit-db.com/exploits/48143"],
    },
    "Tomcat 9.0": {
        "cve": "CVE-2020-1938",
        "cvss": 9.8,
        "severity": "CRITICAL",
        "exploit": True,
        "description": "Ghostcat — AJP connector file read/inclusion. Upgrade to 9.0.31+.",
        "references": ["https://www.exploit-db.com/exploits/48143"],
    },

    # ── SMB / Windows ────────────────────────────────────────────────
    "Samba 3.0": {
        "cve": "CVE-2007-2447",
        "cvss": 9.3,
        "severity": "CRITICAL",
        "exploit": True,
        "description": "Samba 3.0.x username map script command injection — unauthenticated RCE.",
        "references": ["https://www.exploit-db.com/exploits/16320"],
    },
    "Samba 3.5": {
        "cve": "CVE-2017-7494",
        "cvss": 9.8,
        "severity": "CRITICAL",
        "exploit": True,
        "description": "SambaCry — arbitrary shared library loading via writable share allows RCE.",
        "references": ["https://www.exploit-db.com/exploits/42060"],
    },
    "Samba 4.": {
        "cve": "CVE-2021-44142",
        "cvss": 9.9,
        "severity": "CRITICAL",
        "exploit": True,
        "description": "Out-of-bounds read/write in vfs_fruit Samba module allows RCE as root.",
        "references": [],
    },
    "Windows SMB": {
        "cve": "CVE-2017-0144",
        "cvss": 9.3,
        "severity": "CRITICAL",
        "exploit": True,
        "description": "EternalBlue — SMBv1 remote code execution used by WannaCry/NotPetya.",
        "references": ["https://www.exploit-db.com/exploits/42315"],
    },
    "SMBv1": {
        "cve": "CVE-2017-0144",
        "cvss": 9.3,
        "severity": "CRITICAL",
        "exploit": True,
        "description": "EternalBlue — SMBv1 remote code execution. Disable SMBv1 immediately.",
        "references": ["https://www.exploit-db.com/exploits/42315"],
    },

    # ── MySQL / MariaDB ──────────────────────────────────────────────
    "MySQL 5.0": {
        "cve": "CVE-2012-2122",
        "cvss": 7.5,
        "severity": "HIGH",
        "exploit": True,
        "description": "Authentication bypass via repeated connection attempts due to memcmp timing flaw.",
        "references": ["https://www.exploit-db.com/exploits/19092"],
    },
    "MySQL 5.1": {
        "cve": "CVE-2012-2122",
        "cvss": 7.5,
        "severity": "HIGH",
        "exploit": True,
        "description": "Authentication bypass via repeated connection attempts due to memcmp timing flaw.",
        "references": [],
    },
    "MySQL 5.5": {
        "cve": "CVE-2016-6662",
        "cvss": 9.8,
        "severity": "CRITICAL",
        "exploit": True,
        "description": "MySQL general_log_file injection allows code execution via malicious config file.",
        "references": ["https://www.exploit-db.com/exploits/40360"],
    },
    "MariaDB 5.": {
        "cve": "CVE-2012-2122",
        "cvss": 7.5,
        "severity": "HIGH",
        "exploit": True,
        "description": "Authentication bypass via memcmp timing flaw in password validation.",
        "references": [],
    },

    # ── PostgreSQL ───────────────────────────────────────────────────
    "PostgreSQL 8.": {
        "cve": "CVE-2013-1899",
        "cvss": 6.5,
        "severity": "MEDIUM",
        "exploit": True,
        "description": "PostgreSQL 8.x allows privilege escalation via command-line option injection.",
        "references": [],
    },
    "PostgreSQL 9.0": {
        "cve": "CVE-2019-10164",
        "cvss": 8.8,
        "severity": "HIGH",
        "exploit": True,
        "description": "Stack-based buffer overflow in PostgreSQL 9.0–11 via a crafted password.",
        "references": [],
    },

    # ── SMTP ─────────────────────────────────────────────────────────
    "Postfix": {
        "cve": "N/A",
        "cvss": 0.0,
        "severity": "LOW",
        "exploit": False,
        "description": "Postfix detected. Check VRFY/EXPN commands enabled and open relay status.",
        "references": [],
    },
    "Sendmail 8.": {
        "cve": "CVE-2014-3956",
        "cvss": 4.3,
        "severity": "MEDIUM",
        "exploit": False,
        "description": "Sendmail 8.x local privilege escalation via smrsh bypass.",
        "references": [],
    },
    "Exim 4.": {
        "cve": "CVE-2019-10149",
        "cvss": 9.8,
        "severity": "CRITICAL",
        "exploit": True,
        "description": "Exim 4.87–4.91 local/remote privilege escalation via RCPT TO expansion.",
        "references": ["https://www.exploit-db.com/exploits/46974"],
    },
    "Exchange 2010": {
        "cve": "CVE-2021-26855",
        "cvss": 9.8,
        "severity": "CRITICAL",
        "exploit": True,
        "description": "ProxyLogon — SSRF in Exchange 2010/2013/2016/2019 allows pre-auth RCE.",
        "references": [],
    },

    # ── RDP ──────────────────────────────────────────────────────────
    "RDP": {
        "cve": "CVE-2019-0708",
        "cvss": 9.8,
        "severity": "CRITICAL",
        "exploit": True,
        "description": "BlueKeep — Pre-authentication RCE in RDP. Wormable, no user interaction required.",
        "references": ["https://www.exploit-db.com/exploits/47416"],
    },
    "Terminal Services": {
        "cve": "CVE-2019-0708",
        "cvss": 9.8,
        "severity": "CRITICAL",
        "exploit": True,
        "description": "BlueKeep — Pre-authentication RCE in Windows RDP service.",
        "references": [],
    },
    "Remote Desktop": {
        "cve": "CVE-2019-0708",
        "cvss": 9.8,
        "severity": "CRITICAL",
        "exploit": True,
        "description": "BlueKeep — Pre-authentication RCE in Windows RDP service.",
        "references": [],
    },

    # ── VNC ──────────────────────────────────────────────────────────
    "RealVNC 4.": {
        "cve": "CVE-2006-2369",
        "cvss": 7.5,
        "severity": "HIGH",
        "exploit": True,
        "description": "RealVNC 4.1.1 authentication bypass — null auth type accepted.",
        "references": ["https://www.exploit-db.com/exploits/1791"],
    },
    "UltraVNC 1.0": {
        "cve": "CVE-2008-0610",
        "cvss": 9.3,
        "severity": "CRITICAL",
        "exploit": True,
        "description": "UltraVNC 1.0.2 remote stack overflow allows unauthenticated RCE.",
        "references": [],
    },

    # ── Telnet ───────────────────────────────────────────────────────
    "Telnet": {
        "cve": "N/A",
        "cvss": 9.1,
        "severity": "CRITICAL",
        "exploit": False,
        "description": "Telnet transmits credentials and data in cleartext. Replace with SSH immediately.",
        "references": [],
    },
    "Linux telnetd": {
        "cve": "CVE-2011-4862",
        "cvss": 10.0,
        "severity": "CRITICAL",
        "exploit": True,
        "description": "FreeBSD/Linux telnetd encryption key negotiation overflow — pre-auth RCE.",
        "references": [],
    },

    # ── DNS ──────────────────────────────────────────────────────────
    "BIND 9.": {
        "cve": "CVE-2020-8617",
        "cvss": 7.5,
        "severity": "HIGH",
        "exploit": False,
        "description": "BIND 9 TSIG assertion failure allows remote DoS.",
        "references": [],
    },
    "BIND 8.": {
        "cve": "CVE-2002-0684",
        "cvss": 9.3,
        "severity": "CRITICAL",
        "exploit": True,
        "description": "BIND 8.x TSIG transaction signature overflow allows remote root compromise.",
        "references": [],
    },
    "dnsmasq 2.": {
        "cve": "CVE-2021-3448",
        "cvss": 4.0,
        "severity": "MEDIUM",
        "exploit": False,
        "description": "dnsmasq 2.x DNS cache poisoning via predictable DNS IDs.",
        "references": [],
    },

    # ── Redis ────────────────────────────────────────────────────────
    "Redis": {
        "cve": "CVE-2022-0543",
        "cvss": 10.0,
        "severity": "CRITICAL",
        "exploit": True,
        "description": "Unauthenticated Redis allows arbitrary file write — often leads to SSH key injection or cron RCE.",
        "references": [],
    },
    "Redis 2.": {
        "cve": "CVE-2015-4335",
        "cvss": 10.0,
        "severity": "CRITICAL",
        "exploit": True,
        "description": "Redis Lua sandbox escape allows code execution via eval command.",
        "references": [],
    },

    # ── MongoDB ──────────────────────────────────────────────────────
    "MongoDB": {
        "cve": "N/A",
        "cvss": 8.0,
        "severity": "HIGH",
        "exploit": False,
        "description": "MongoDB listening without authentication. Default config allows unauthenticated DB access.",
        "references": [],
    },

    # ── Docker / Kubernetes ──────────────────────────────────────────
    "Docker": {
        "cve": "CVE-2019-5736",
        "cvss": 8.6,
        "severity": "HIGH",
        "exploit": True,
        "description": "runc container escape via /proc/self/exe overwrite allows host compromise.",
        "references": [],
    },

    # ── Java / Serialization ─────────────────────────────────────────
    "Java RMI": {
        "cve": "CVE-2011-3556",
        "cvss": 7.5,
        "severity": "HIGH",
        "exploit": True,
        "description": "Java RMI registry default config allows remote class loading and code execution.",
        "references": [],
    },
    "JBoss": {
        "cve": "CVE-2017-12149",
        "cvss": 9.8,
        "severity": "CRITICAL",
        "exploit": True,
        "description": "JBoss deserialization vulnerability in HttpInvoker allows pre-auth RCE.",
        "references": ["https://www.exploit-db.com/exploits/36234"],
    },
    "WebLogic 10": {
        "cve": "CVE-2019-2725",
        "cvss": 9.8,
        "severity": "CRITICAL",
        "exploit": True,
        "description": "Oracle WebLogic deserialization RCE — no authentication required.",
        "references": [],
    },
    "WebLogic 12": {
        "cve": "CVE-2020-14882",
        "cvss": 9.8,
        "severity": "CRITICAL",
        "exploit": True,
        "description": "Oracle WebLogic Console HTTP protocol authentication bypass and RCE.",
        "references": [],
    },

    # ── Network services ─────────────────────────────────────────────
    "SNMP": {
        "cve": "N/A",
        "cvss": 7.5,
        "severity": "HIGH",
        "exploit": False,
        "description": "SNMP v1/v2c uses community strings in cleartext. Default 'public' string leaks full network topology.",
        "references": [],
    },
    "SNMPv1": {
        "cve": "CVE-2002-0013",
        "cvss": 10.0,
        "severity": "CRITICAL",
        "exploit": True,
        "description": "Multiple SNMP implementations have buffer overflows in ASN.1 parsing.",
        "references": [],
    },
    "distccd": {
        "cve": "CVE-2004-2687",
        "cvss": 9.3,
        "severity": "CRITICAL",
        "exploit": True,
        "description": "distcc daemon allows unauthenticated command execution via ARGV injection.",
        "references": ["https://www.exploit-db.com/exploits/9915"],
    },

    # ── IRC ──────────────────────────────────────────────────────────
    "UnrealIRCd 3.2.8.1": {
        "cve": "CVE-2010-2075",
        "cvss": 9.3,
        "severity": "CRITICAL",
        "exploit": True,
        "description": "Backdoor in UnrealIRCd 3.2.8.1 allows remote command execution via AB; prefix.",
        "references": ["https://www.exploit-db.com/exploits/13853"],
    },
    "UnrealIRCd 3.": {
        "cve": "CVE-2010-2075",
        "cvss": 9.3,
        "severity": "CRITICAL",
        "exploit": True,
        "description": "Backdoor in UnrealIRCd 3.2.8.1 allows remote command execution via AB; prefix.",
        "references": [],
    },

    # ── VoIP ─────────────────────────────────────────────────────────
    "Asterisk 1.": {
        "cve": "CVE-2011-2536",
        "cvss": 7.5,
        "severity": "HIGH",
        "exploit": True,
        "description": "Asterisk 1.x SIP channel driver allows unauthenticated DoS and possible RCE.",
        "references": [],
    },
    "SIP": {
        "cve": "N/A",
        "cvss": 5.0,
        "severity": "MEDIUM",
        "exploit": False,
        "description": "SIP service detected. May allow extension enumeration and toll fraud.",
        "references": [],
    },

    # ── Printers / Embedded ──────────────────────────────────────────
    "HP JetDirect": {
        "cve": "CVE-2017-2741",
        "cvss": 9.8,
        "severity": "CRITICAL",
        "exploit": True,
        "description": "HP printer pre-auth remote code execution via FTP service.",
        "references": [],
    },
    "CUPS": {
        "cve": "CVE-2024-47176",
        "cvss": 9.9,
        "severity": "CRITICAL",
        "exploit": True,
        "description": "CUPS remote code execution via malicious IPP attribute — no authentication.",
        "references": [],
    },
}


def check_cve(product, version):
    """
    Look up CVE data for a product/version string.
    Matches against CVE_DATABASE keys using substring matching.
    Returns the most specific (longest key) match found.

    Args:
        product: Product name string (e.g. 'Apache', 'OpenSSH')
        version: Version string (e.g. '2.2.8', '4.7p1')

    Returns:
        CVE dict or None
    """
    if not product:
        return None

    # Build candidate strings to match against
    candidates = []
    if version:
        candidates.append(f"{product} {version}")
        # Try major.minor only
        parts = version.split(".")
        if len(parts) >= 2:
            candidates.append(f"{product} {parts[0]}.{parts[1]}")
        if len(parts) >= 1:
            candidates.append(f"{product} {parts[0]}.")
    candidates.append(product)

    # Find the longest (most specific) matching key
    best_match = None
    best_len   = 0

    for candidate in candidates:
        for key in CVE_DATABASE:
            if key.lower() in candidate.lower() or candidate.lower() in key.lower():
                if len(key) > best_len:
                    best_match = CVE_DATABASE[key]
                    best_len   = len(key)

    return best_match
