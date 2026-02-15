# =====================================================================
# File: udp_scanner.py
# Notes:
# - This file is part of the BlackPort project.
# - The comments added here are for readability only (no behavior change).
# - Use only on hosts/networks you own or have explicit permission to test.
# =====================================================================

import socket

# NOTE: scan_udp_port() - helper/entry function. Read the body for the exact steps.
def scan_udp_port(target, port, timeout=1):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(b"", (target, port))
        sock.recvfrom(1024)
        return True
    except:
        return False
    finally:
        sock.close()
