# =====================================================================
# File: banner.py
# Notes:
# - This file is part of the BlackPort project.
# - The comments added here are for readability only (no behavior change).
# - Use only on hosts/networks you own or have explicit permission to test.
# =====================================================================

import socket

# NOTE: grab_banner() - helper/entry function. Read the body for the exact steps.
def grab_banner(target, port):
    try:
        sock = socket.socket()
        sock.settimeout(1)
        sock.connect((target, port))
        banner = sock.recv(1024).decode(errors="ignore").strip()
        sock.close()
        return banner if banner else "No banner"
    except:
        return "No banner"
