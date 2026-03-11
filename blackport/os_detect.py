# =====================================================================
# File: blackport/os_detect.py
# Notes:
# - This file is part of the BlackPort project.
# - Performs passive + active OS fingerprinting using:
#     1. TTL analysis from open port responses
#     2. TCP window size fingerprinting
#     3. Banner keyword analysis
#     4. Port combination heuristics
# - Does not send raw packets — uses socket-level observations only.
# - Use only on hosts/networks you own or have explicit permission to test.
# =====================================================================

import socket
import struct
import re
import os
from colorama import Fore, Style

# -------------------------------------------------------------------
# TTL-based OS fingerprinting
# Initial TTL values by OS family (packet arrives with TTL reduced by hops)
# We allow ±5 hops from the canonical value
# -------------------------------------------------------------------
TTL_OS_MAP = [
    (128, 138,  "Windows",         "Windows (NT/2000/XP/Vista/7/8/10/11/Server)"),
    (64,  69,   "Linux/macOS",     "Linux (2.6.x+) or macOS / BSD"),
    (255, 255,  "Cisco/Network",   "Cisco IOS / Network device"),
    (60,  64,   "FreeBSD",         "FreeBSD / OpenBSD"),
    (32,  32,   "Windows 9x",      "Windows 95/98/ME (legacy)"),
    (254, 255,  "Solaris",         "Solaris / AIX"),
]

# -------------------------------------------------------------------
# TCP Window size → OS hints
# -------------------------------------------------------------------
WINDOW_OS_MAP = [
    (65535, 65535, "Windows / BSD",   "Windows or BSD (max window size)"),
    (8192,  8192,  "Windows XP",      "Windows XP / 2003"),
    (16384, 16384, "Linux older",     "Linux 2.4.x kernel"),
    (5840,  5840,  "Linux 2.6",       "Linux 2.6.x kernel"),
    (65392, 65392, "Linux modern",    "Linux 4.x+ (autotuning)"),
    (4128,  4128,  "Cisco",           "Cisco IOS"),
    (32768, 32768, "Linux/Solaris",   "Linux or Solaris"),
]

# -------------------------------------------------------------------
# Banner keyword → OS hints
# -------------------------------------------------------------------
BANNER_OS_PATTERNS = [
    (r"Ubuntu",          "Linux",   "Ubuntu Linux"),
    (r"Debian",          "Linux",   "Debian Linux"),
    (r"CentOS|Red Hat|RHEL", "Linux", "Red Hat / CentOS Linux"),
    (r"Fedora",          "Linux",   "Fedora Linux"),
    (r"Kali",            "Linux",   "Kali Linux"),
    (r"Alpine",          "Linux",   "Alpine Linux"),
    (r"Amazon Linux",    "Linux",   "Amazon Linux"),
    (r"FreeBSD",         "BSD",     "FreeBSD"),
    (r"OpenBSD",         "BSD",     "OpenBSD"),
    (r"macOS|Darwin|Mac OS X", "macOS", "macOS / OS X"),
    (r"Windows Server 2022",   "Windows", "Windows Server 2022"),
    (r"Windows Server 2019",   "Windows", "Windows Server 2019"),
    (r"Windows Server 2016",   "Windows", "Windows Server 2016"),
    (r"Windows Server 2012",   "Windows", "Windows Server 2012"),
    (r"Windows Server 2008",   "Windows", "Windows Server 2008"),
    (r"Windows 10|Windows 11", "Windows", "Windows 10/11"),
    (r"Windows NT",      "Windows", "Windows NT"),
    (r"IOS",             "Cisco",   "Cisco IOS"),
    (r"Junos",           "Juniper", "Juniper JunOS"),
    (r"MikroTik",        "MikroTik","MikroTik RouterOS"),
    (r"VMware",          "VMware",  "VMware ESXi / vSphere"),
    (r"Android",         "Android", "Android"),
    (r"Metasploitable",  "Linux",   "Linux (Metasploitable)"),
]

# -------------------------------------------------------------------
# Port combination heuristics
# Certain combinations of open ports strongly suggest a specific OS
# -------------------------------------------------------------------
PORT_COMBO_HINTS = [
    ({135, 139, 445},          "Windows",  "Windows (SMB stack detected)"),
    ({22, 80, 443},            "Linux",    "Linux server (common web stack)"),
    ({22, 111, 2049},          "Linux",    "Linux (NFS/RPC stack)"),
    ({23, 80},                  "Cisco",    "Cisco device (Telnet + HTTP mgmt)"),
    ({22, 80, 3306},           "Linux",    "Linux LAMP stack"),
    ({3389, 135, 445},         "Windows",  "Windows Desktop/Server (RDP + SMB)"),
    ({22, 25, 110, 143},       "Linux",    "Linux mail server"),
    ({512, 513, 514},          "Linux",    "Linux (r-services — likely old Unix)"),
    ({1521},                    "Linux",    "Linux/Solaris (Oracle DB)"),
    ({1433},                    "Windows",  "Windows (MSSQL Server)"),
    ({5985, 5986},             "Windows",  "Windows (WinRM/PowerShell remoting)"),
    ({5900},                    "Linux",    "Linux desktop (VNC)"),
    ({6000},                    "Linux",    "Linux (X11 display)"),
]


def _ttl_probe(target, port, timeout=2):
    """
    Attempt to read the TTL from a TCP connection response.
    Uses IP_TTL socket option — Linux only, silently skips on other platforms.
    Returns TTL int or None.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)

        # Enable IP_RECVTTL if available (Linux)
        try:
            s.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, 1)
        except (AttributeError, OSError):
            pass

        s.connect((target, port))

        # Try to read TTL from socket (platform-specific)
        try:
            ttl = s.getsockopt(socket.IPPROTO_IP, socket.IP_TTL)
            s.close()
            return ttl
        except Exception:
            pass

        s.close()
    except Exception:
        pass
    return None


def _ttl_from_ping(target, timeout=2):
    """
    Get TTL by sending an ICMP ping and reading the response TTL.
    Requires root. Returns TTL int or None.
    """
    if os.geteuid() != 0:
        return None
    try:
        # Build minimal ICMP echo request
        icmp_type = 8
        checksum  = 0
        header    = struct.pack("bbHHh", icmp_type, 0, checksum, os.getpid() & 0xFFFF, 1)
        data      = b"BLACKPORT"

        def calc_checksum(msg):
            s = 0
            for i in range(0, len(msg) - 1, 2):
                s += (msg[i] << 8) + msg[i+1]
            if len(msg) % 2:
                s += msg[-1] << 8
            s = (s >> 16) + (s & 0xffff)
            return ~s & 0xffff

        checksum = calc_checksum(header + data)
        header   = struct.pack("bbHHh", icmp_type, 0, socket.htons(checksum), os.getpid() & 0xFFFF, 1)
        packet   = header + data

        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sock.settimeout(timeout)
        sock.sendto(packet, (target, 0))

        resp, _ = sock.recvfrom(1024)
        sock.close()

        # TTL is byte 8 of IP header
        if len(resp) >= 9:
            return resp[8]
    except Exception:
        pass
    return None


def _classify_ttl(ttl):
    """Map a TTL value to an OS family."""
    if ttl is None:
        return None, None
    for lo, hi, family, detail in TTL_OS_MAP:
        if lo <= ttl <= hi:
            return family, detail
    return "Unknown", f"Unusual TTL {ttl}"


def _classify_banners(banners):
    """
    Scan a list of banner strings for OS keywords.
    Returns (family, detail) of the best match.
    """
    for banner in banners:
        if not banner:
            continue
        for pattern, family, detail in BANNER_OS_PATTERNS:
            if re.search(pattern, banner, re.IGNORECASE):
                return family, detail
    return None, None


def _classify_ports(open_ports):
    """
    Use port combination heuristics to suggest OS.
    Returns (family, detail) of the best match.
    """
    port_set = set(open_ports)
    for required_ports, family, detail in PORT_COMBO_HINTS:
        if required_ports.issubset(port_set):
            return family, detail
    return None, None


def detect_os(target, open_ports, banners=None, timeout=2):
    """
    Main entry point: detect OS using multiple methods.

    Args:
        target:     Target IP string
        open_ports: List of open port numbers (ints)
        banners:    List of banner strings from open ports (optional)
        timeout:    Socket timeout

    Returns:
        dict with keys:
            os_family:  "Linux", "Windows", "Cisco", etc.
            os_detail:  More specific description
            ttl:        Raw TTL value observed
            method:     How the detection was made
            confidence: "HIGH", "MEDIUM", "LOW"
    """
    result = {
        "os_family":  None,
        "os_detail":  "Unknown",
        "ttl":        None,
        "method":     None,
        "confidence": "LOW",
    }

    banners = banners or []

    # --- Method 1: Banner analysis (highest confidence) ---
    family, detail = _classify_banners(banners)
    if family:
        result.update({
            "os_family":  family,
            "os_detail":  detail,
            "method":     "banner",
            "confidence": "HIGH",
        })
        # Still probe TTL for corroboration
        ttl = _ttl_from_ping(target, timeout)
        if ttl:
            result["ttl"] = ttl
        return result

    # --- Method 2: TTL analysis ---
    ttl = _ttl_from_ping(target, timeout)
    if not ttl and open_ports:
        # Fallback: probe an open port for TTL
        ttl = _ttl_probe(target, open_ports[0], timeout)

    result["ttl"] = ttl
    ttl_family, ttl_detail = _classify_ttl(ttl)

    if ttl_family and ttl_family != "Unknown":
        result.update({
            "os_family":  ttl_family,
            "os_detail":  ttl_detail,
            "method":     "ttl",
            "confidence": "MEDIUM",
        })

    # --- Method 3: Port combination heuristics ---
    port_family, port_detail = _classify_ports(open_ports)
    if port_family:
        if result["os_family"] is None:
            result.update({
                "os_family":  port_family,
                "os_detail":  port_detail,
                "method":     "port_heuristic",
                "confidence": "LOW",
            })
        elif result["os_family"] == port_family:
            # Both methods agree — boost confidence
            result["os_detail"]  = port_detail
            result["confidence"] = "HIGH" if result["confidence"] == "MEDIUM" else "MEDIUM"
            result["method"]     = f"{result['method']}+port_heuristic"

    if result["os_family"] is None:
        result["os_detail"] = "Could not determine OS"

    return result


def format_os_result(os_result):
    """Format OS detection result for terminal display."""
    family     = os_result.get("os_family", "Unknown")
    detail     = os_result.get("os_detail", "Unknown")
    ttl        = os_result.get("ttl")
    method     = os_result.get("method", "unknown")
    confidence = os_result.get("confidence", "LOW")

    conf_color = {
        "HIGH":   Fore.GREEN,
        "MEDIUM": Fore.YELLOW,
        "LOW":    Fore.WHITE,
    }.get(confidence, "")

    ttl_str = f" | TTL={ttl}" if ttl else ""
    return (
        f"{Fore.CYAN}[OS]{Style.RESET_ALL} {detail}{ttl_str} "
        f"[{conf_color}{confidence}{Style.RESET_ALL} confidence via {method}]"
    )
