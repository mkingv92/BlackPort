# =====================================================================
# File: blackport/host_discovery.py
# Notes:
# - This file is part of the BlackPort project.
# - Use only on hosts/networks you own or have explicit permission to test.
# - ICMP ping requires root on Linux. TCP ping is used as fallback.
# =====================================================================

import socket
import struct
import os
import ipaddress
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style, init
init(autoreset=True)

# Ports used for TCP-based host discovery when ICMP is unavailable
TCP_PROBE_PORTS = [80, 443, 22, 445, 8080]


def parse_targets(target_str):
    """
    Parse a target string into a list of IP address strings.
    Supports:
      - Single IP:   192.168.56.104
      - CIDR range:  192.168.56.0/24
      - IP range:    192.168.56.1-50
    """
    targets = []

    try:
        # CIDR notation
        if "/" in target_str:
            net = ipaddress.ip_network(target_str, strict=False)
            # Skip network and broadcast addresses
            targets = [str(ip) for ip in net.hosts()]

        # Range notation: 192.168.1.1-50
        elif "-" in target_str.split(".")[-1]:
            base = ".".join(target_str.split(".")[:-1])
            last_octet = target_str.split(".")[-1]
            start, end = last_octet.split("-")
            for i in range(int(start), int(end) + 1):
                targets.append(f"{base}.{i}")

        # Single IP
        else:
            ipaddress.ip_address(target_str)  # validate
            targets = [target_str]

    except ValueError as e:
        raise ValueError(f"Invalid target format '{target_str}': {e}")

    return targets


def _icmp_ping(ip, timeout=1):
    """
    Send a raw ICMP echo request and wait for reply.
    Requires root/admin privileges.
    Returns True if host responds.
    """
    try:
        # Build ICMP echo request
        icmp_type = 8   # Echo request
        icmp_code = 0
        icmp_checksum = 0
        icmp_id = os.getpid() & 0xFFFF
        icmp_seq = 1
        header = struct.pack("bbHHh", icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq)
        data = b"BLACKPORT" * 2
        checksum = _icmp_checksum(header + data)
        header = struct.pack("bbHHh", icmp_type, icmp_code, socket.htons(checksum), icmp_id, icmp_seq)
        packet = header + data

        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sock.settimeout(timeout)
        sock.sendto(packet, (ip, 0))

        while True:
            try:
                resp, addr = sock.recvfrom(1024)
                if addr[0] == ip:
                    # Check ICMP type = 0 (echo reply)
                    icmp_header = resp[20:28]
                    resp_type = struct.unpack("bbHHh", icmp_header)[0]
                    if resp_type == 0:
                        return True
            except socket.timeout:
                break

        sock.close()
    except (PermissionError, OSError):
        pass
    return False


def _icmp_checksum(data):
    """Calculate ICMP checksum."""
    s = 0
    n = len(data) % 2
    for i in range(0, len(data) - n, 2):
        s += (data[i]) + ((data[i + 1]) << 8)
    if n:
        s += data[-1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def _tcp_ping(ip, timeout=1):
    """
    Attempt TCP connection to common ports as a host-up check.
    No root required. Returns True if any port responds.
    """
    for port in TCP_PROBE_PORTS:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                result = s.connect_ex((ip, port))
                if result == 0:
                    return True
        except Exception:
            continue
    return False


def _probe_host(ip, use_icmp=True, timeout=1):
    """
    Probe a single host using ICMP (if available) then TCP fallback.
    Returns (ip, alive, method) tuple.
    """
    if use_icmp:
        if _icmp_ping(ip, timeout):
            return (ip, True, "ICMP")

    # TCP fallback
    if _tcp_ping(ip, timeout):
        return (ip, True, "TCP")

    return (ip, False, None)


def discover_hosts(targets, threads=100, timeout=1, verbose=False):
    """
    Run host discovery across a list of IPs.
    Returns list of live host IP strings.
    """
    if len(targets) == 1:
        # Single target — skip discovery, assume alive
        return targets

    use_icmp = (os.geteuid() == 0)  # root check

    if not use_icmp and verbose:
        print(f"{Fore.YELLOW}[!] Not running as root — using TCP ping (slower, may miss some hosts){Style.RESET_ALL}")

    total   = len(targets)
    found   = []
    scanned = 0

    print(f"\n{Fore.CYAN}[*] Host discovery: probing {total} addresses...{Style.RESET_ALL}")

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(_probe_host, ip, use_icmp, timeout): ip for ip in targets}

        for future in as_completed(futures):
            result = future.result()
            scanned += 1
            ip, alive, method = result

            print(f"    Discovery: {scanned}/{total}", end="\r")

            if alive:
                found.append(ip)
                if verbose:
                    print(f"\n    {Fore.GREEN}[+] {ip} is up ({method}){Style.RESET_ALL}")

    print()

    # Sort IPs numerically
    found.sort(key=lambda ip: [int(x) for x in ip.split(".")])

    print(f"{Fore.GREEN}[*] {len(found)} live host(s) found out of {total} addresses{Style.RESET_ALL}\n")

    return found
