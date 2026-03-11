# =====================================================================
# File: blackport/fingerprint_db.py
# Notes:
# - This file is part of the BlackPort project.
# - Use only on hosts/networks you own or have explicit permission to test.
# =====================================================================

import re

# -------------------------------------------------------------------
# Fingerprint database: banner pattern → service/product/version
# Each entry: pattern matched against banner text (case-insensitive)
# Port hints: optional list of ports to narrow false positive risk
# -------------------------------------------------------------------
FINGERPRINT_DB = [
    # === FTP ===
    {"service": "FTP",   "product": "vsFTPd",        "pattern": r"vsFTPd[\s/]+([0-9.]+)",            "confidence": 97},
    {"service": "FTP",   "product": "ProFTPD",        "pattern": r"ProFTPD[\s/]+([0-9.]+)",           "confidence": 97},
    {"service": "FTP",   "product": "Pure-FTPd",      "pattern": r"Pure-FTPd",                        "confidence": 90},
    {"service": "FTP",   "product": "FileZilla Server","pattern": r"FileZilla Server",                 "confidence": 95},
    {"service": "FTP",   "product": "WU-FTPD",        "pattern": r"WU-FTPD|wu-[0-9]",                "confidence": 90},
    {"service": "FTP",   "product": "Microsoft FTP",  "pattern": r"Microsoft FTP Service",            "confidence": 95},
    {"service": "FTP",   "product": "Generic FTP",    "pattern": r"^220",                             "confidence": 50},

    # === SSH ===
    {"service": "SSH",   "product": "OpenSSH",        "pattern": r"OpenSSH[_\s/]+([0-9.p]+)",        "confidence": 97},
    {"service": "SSH",   "product": "Dropbear",       "pattern": r"dropbear[_\s/]+([0-9.]+)",        "confidence": 95},
    {"service": "SSH",   "product": "Cisco SSH",      "pattern": r"Cisco[_\s]SSH",                   "confidence": 92},
    {"service": "SSH",   "product": "libssh",         "pattern": r"libssh[_\s/]+([0-9.]+)",          "confidence": 90},

    # === HTTP / Web ===
    {"service": "HTTP",  "product": "Apache",         "pattern": r"Apache[/\s]+([0-9.]+)",            "confidence": 95},
    {"service": "HTTP",  "product": "nginx",          "pattern": r"nginx[/\s]+([0-9.]+)",             "confidence": 95},
    {"service": "HTTP",  "product": "Microsoft IIS",  "pattern": r"Microsoft-IIS[/\s]+([0-9.]+)",    "confidence": 95},
    {"service": "HTTP",  "product": "LiteSpeed",      "pattern": r"LiteSpeed[/\s]+([0-9.]+)",        "confidence": 93},
    {"service": "HTTP",  "product": "Tomcat",         "pattern": r"Apache Tomcat[/\s]+([0-9.]+)",    "confidence": 95},
    {"service": "HTTP",  "product": "Jetty",          "pattern": r"Jetty[/\s]+([0-9.]+)",            "confidence": 92},
    {"service": "HTTP",  "product": "Caddy",          "pattern": r"Caddy",                            "confidence": 88},
    {"service": "HTTP",  "product": "Gunicorn",       "pattern": r"gunicorn[/\s]+([0-9.]+)",         "confidence": 90},
    {"service": "HTTP",  "product": "Cherokee",       "pattern": r"Cherokee[/\s]+([0-9.]+)",         "confidence": 88},
    {"service": "HTTP",  "product": "Lighttpd",       "pattern": r"lighttpd[/\s]+([0-9.]+)",         "confidence": 93},
    {"service": "HTTP",  "product": "PHP",            "pattern": r"PHP[/\s]+([0-9.]+)",              "confidence": 90},
    {"service": "HTTP",  "product": "WordPress",      "pattern": r"WordPress[/\s]+([0-9.]+)",        "confidence": 88},
    {"service": "HTTP",  "product": "Drupal",         "pattern": r"Drupal[/\s]+([0-9.]+)",           "confidence": 85},
    {"service": "HTTP",  "product": "Joomla",         "pattern": r"Joomla[!/\s]+([0-9.]+)",         "confidence": 83},

    # === SMTP ===
    {"service": "SMTP",  "product": "Postfix",        "pattern": r"Postfix",                          "confidence": 95},
    {"service": "SMTP",  "product": "Sendmail",       "pattern": r"Sendmail[/\s]+([0-9.]+)",         "confidence": 95},
    {"service": "SMTP",  "product": "Exim",           "pattern": r"Exim[/\s]+([0-9.]+)",             "confidence": 95},
    {"service": "SMTP",  "product": "Microsoft ESMTP","pattern": r"Microsoft ESMTP",                  "confidence": 93},
    {"service": "SMTP",  "product": "Lotus Domino",   "pattern": r"Lotus Domino",                    "confidence": 90},
    {"service": "SMTP",  "product": "qmail",          "pattern": r"qmail",                            "confidence": 90},

    # === DNS ===
    {"service": "DNS",   "product": "BIND",           "pattern": r"BIND[\s/]+([0-9.]+)",             "confidence": 93},
    {"service": "DNS",   "product": "dnsmasq",        "pattern": r"dnsmasq[/\s]+([0-9.]+)",         "confidence": 90},
    {"service": "DNS",   "product": "Unbound",        "pattern": r"unbound[/\s]+([0-9.]+)",         "confidence": 90},
    {"service": "DNS",   "product": "PowerDNS",       "pattern": r"PowerDNS[/\s]+([0-9.]+)",        "confidence": 92},

    # === Database ===
    {"service": "MySQL", "product": "MySQL",          "pattern": r"([0-9]+\.[0-9]+\.[0-9]+[^\s]*)",  "confidence": 90, "ports": [3306]},
    {"service": "MySQL", "product": "MariaDB",        "pattern": r"([0-9]+\.[0-9]+\.[0-9]+-MariaDB[^\s]*)", "confidence": 95},
    {"service": "PostgreSQL", "product": "PostgreSQL","pattern": r"PostgreSQL[\s/]+([0-9.]+)",       "confidence": 93},
    {"service": "Redis", "product": "Redis",          "pattern": r"Redis[\s/]+([0-9.]+)",            "confidence": 93},
    {"service": "MongoDB","product": "MongoDB",       "pattern": r"MongoDB[\s/]+([0-9.]+)",          "confidence": 90},
    {"service": "Memcached","product":"Memcached",    "pattern": r"VERSION ([0-9.]+)",               "confidence": 88, "ports": [11211]},
    {"service": "MSSQL", "product": "MSSQL",          "pattern": r"Microsoft SQL Server",            "confidence": 95},
    {"service": "Oracle","product": "Oracle DB",      "pattern": r"Oracle.*Database",               "confidence": 90},

    # === Remote Access ===
    {"service": "Telnet","product": "Telnet",         "pattern": r"login:|Welcome|Debian|Ubuntu",    "confidence": 60},
    {"service": "VNC",   "product": "RFB",            "pattern": r"RFB\s+([0-9]+\.[0-9]+)",         "confidence": 97},
    {"service": "RDP",   "product": "RDP",            "pattern": r"\x03\x00",                        "confidence": 70, "ports": [3389]},

    # === SMB / Windows ===
    {"service": "SMB",   "product": "Samba",          "pattern": r"Samba[\s/]+([0-9.]+)",            "confidence": 93},
    {"service": "NetBIOS","product":"NetBIOS",        "pattern": r"WORKGROUP|DOMAIN",                "confidence": 75},

    # === Mail ===
    {"service": "POP3",  "product": "Dovecot POP3",   "pattern": r"Dovecot",                         "confidence": 92},
    {"service": "IMAP",  "product": "Dovecot IMAP",   "pattern": r"Dovecot.*IMAP",                  "confidence": 93},
    {"service": "IMAP",  "product": "Cyrus IMAP",     "pattern": r"Cyrus IMAP",                     "confidence": 92},
    {"service": "IMAP",  "product": "UW-IMAP",        "pattern": r"IMAP.*University",               "confidence": 88},

    # === Network Infrastructure ===
    {"service": "SNMP",  "product": "SNMP",           "pattern": r"public|private|community",        "confidence": 60, "ports": [161]},
    {"service": "TFTP",  "product": "TFTP",           "pattern": r"\x00\x03|\x00\x05",              "confidence": 80, "ports": [69]},
    {"service": "NTP",   "product": "NTP",            "pattern": r"\x1b",                            "confidence": 70, "ports": [123]},
    {"service": "LDAP",  "product": "OpenLDAP",       "pattern": r"OpenLDAP[\s/]+([0-9.]+)",        "confidence": 90},
    {"service": "LDAP",  "product": "Active Directory","pattern": r"Microsoft.*LDAP",               "confidence": 90},

    # === Application Servers ===
    {"service": "HTTP",  "product": "Glassfish",      "pattern": r"GlassFish[\s/]+([0-9.]+)",       "confidence": 90},
    {"service": "HTTP",  "product": "WebLogic",       "pattern": r"WebLogic[\s/]+([0-9.]+)",        "confidence": 92},
    {"service": "HTTP",  "product": "JBoss",          "pattern": r"JBoss[\s/]+([0-9.]+)",           "confidence": 92},
    {"service": "HTTP",  "product": "Wildfly",        "pattern": r"WildFly[\s/]+([0-9.]+)",         "confidence": 90},
    {"service": "AJP",   "product": "Tomcat AJP",     "pattern": r"\x12\x34\x00",                   "confidence": 85, "ports": [8009]},

    # === Messaging ===
    {"service": "IRC",   "product": "UnrealIRCd",     "pattern": r"UnrealIRCd[\s/]+([0-9.]+)",      "confidence": 97},
    {"service": "IRC",   "product": "InspIRCd",       "pattern": r"InspIRCd[\s/]+([0-9.]+)",       "confidence": 95},
    {"service": "AMQP",  "product": "RabbitMQ",       "pattern": r"RabbitMQ[\s/]+([0-9.]+)",        "confidence": 92},

    # === Security ===
    {"service": "Rsync", "product": "rsync",          "pattern": r"@RSYNCD:[\s]+([0-9.]+)",         "confidence": 97},
    {"service": "VPN",   "product": "OpenVPN",        "pattern": r"OpenVPN",                         "confidence": 90},
    {"service": "Proxy", "product": "Squid",          "pattern": r"Squid[\s/]+([0-9.]+)",           "confidence": 93},
    {"service": "Proxy", "product": "HAProxy",        "pattern": r"HAProxy[\s/]+([0-9.]+)",         "confidence": 90},

    # === IoT / Embedded ===
    {"service": "HTTP",  "product": "Cisco IOS HTTP", "pattern": r"Cisco IOS",                       "confidence": 93},
    {"service": "Telnet","product": "Cisco Telnet",   "pattern": r"Cisco|IOS",                       "confidence": 70},
    {"service": "HTTP",  "product": "MikroTik",       "pattern": r"MikroTik",                        "confidence": 93},
    {"service": "HTTP",  "product": "Ubiquiti",       "pattern": r"Ubiquiti|UBNT",                   "confidence": 90},
    {"service": "HTTP",  "product": "DD-WRT",         "pattern": r"DD-WRT",                          "confidence": 92},
    {"service": "HTTP",  "product": "OpenWRT",        "pattern": r"OpenWrt",                         "confidence": 92},

    # === Java ===
    {"service": "Java RMI","product":"Java RMI",      "pattern": r"JRMI|java\.rmi",                 "confidence": 88, "ports": [1099]},

    # === Backup / Storage ===
    {"service": "NFS",   "product": "NFS",            "pattern": r"nfs",                             "confidence": 70, "ports": [2049]},
    {"service": "Rsync", "product": "rsync",          "pattern": r"RSYNCD",                          "confidence": 95, "ports": [873]},
    {"service": "Bacula","product": "Bacula",         "pattern": r"Bacula",                          "confidence": 90},

    # === Distccd ===
    {"service": "distccd","product":"distccd",        "pattern": r"DIST",                            "confidence": 70, "ports": [3632]},
]


def fingerprint_banner(port, banner, service_hint=None):
    """
    Match a banner string against the fingerprint database.

    Returns (service, product, version, confidence) tuple.
    Falls back to service_hint if no match found.
    """
    if not banner:
        return service_hint, None, None, 0

    best_match = None
    best_confidence = 0

    for fp in FINGERPRINT_DB:
        # Optional port restriction
        if "ports" in fp and port not in fp["ports"]:
            continue

        try:
            match = re.search(fp["pattern"], banner, re.IGNORECASE | re.DOTALL)
        except re.error:
            continue

        if match:
            version = None
            if match.lastindex and match.lastindex >= 1:
                try:
                    version = match.group(1)
                except IndexError:
                    pass

            confidence = fp["confidence"]

            # Boost confidence if product name matches service_hint
            if service_hint and fp["service"].lower() in service_hint.lower():
                confidence = min(confidence + 5, 100)

            if confidence > best_confidence:
                best_confidence = confidence
                best_match = (fp["service"], fp["product"], version, confidence)

    if best_match:
        return best_match

    # No match — return hint or Unknown
    return (service_hint or "Unknown"), None, None, 10


# Port → service name mapping (used when no banner is available)
PORT_SERVICE_MAP = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet",
    25: "SMTP", 53: "DNS", 67: "DHCP", 68: "DHCP",
    69: "TFTP", 79: "Finger", 80: "HTTP", 88: "Kerberos",
    110: "POP3", 111: "RPC", 119: "NNTP", 123: "NTP",
    135: "MSRPC", 137: "NetBIOS-NS", 138: "NetBIOS-DG",
    139: "NetBIOS", 143: "IMAP", 161: "SNMP", 162: "SNMP-Trap",
    179: "BGP", 194: "IRC", 389: "LDAP", 443: "HTTPS",
    445: "SMB", 465: "SMTPS", 500: "IKE", 502: "Modbus",
    512: "rexec", 513: "rlogin", 514: "rsh", 515: "LPD",
    554: "RTSP", 587: "SMTP-sub", 593: "MSRPC-HTTP",
    631: "IPP", 636: "LDAPS", 873: "rsync", 902: "VMware",
    993: "IMAPS", 995: "POP3S", 1080: "SOCKS", 1099: "Java-RMI",
    1194: "OpenVPN", 1433: "MSSQL", 1521: "Oracle",
    1524: "Bindshell", 1723: "PPTP", 1883: "MQTT",
    1900: "UPnP", 2049: "NFS", 2121: "FTP-alt", 2181: "Zookeeper",
    2375: "Docker", 2376: "Docker-TLS", 3000: "Grafana",
    3306: "MySQL", 3389: "RDP", 3632: "distccd",
    4444: "Meterpreter", 4500: "NAT-T", 5000: "UPnP",
    5353: "mDNS", 5355: "LLMNR", 5432: "PostgreSQL",
    5900: "VNC", 5984: "CouchDB", 6000: "X11",
    6379: "Redis", 6667: "IRC", 6697: "IRC-SSL",
    7000: "IRC", 8080: "HTTP-alt", 8443: "HTTPS-alt",
    8009: "AJP", 8180: "HTTP-alt", 8787: "drb",
    9000: "SonarQube", 9090: "Openfire", 9200: "Elasticsearch",
    9300: "Elasticsearch", 11211: "Memcached",
    27017: "MongoDB", 27018: "MongoDB", 50000: "SAP",
}


def service_from_port(port):
    """Return a service name from port number, or 'Unknown'."""
    return PORT_SERVICE_MAP.get(port, "Unknown")
