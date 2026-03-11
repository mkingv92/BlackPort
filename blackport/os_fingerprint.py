# =====================================================================
# File: os_fingerprint.py
# Notes:
# - This file is part of the BlackPort project.
# - The comments added here are for readability only (no behavior change).
# - Use only on hosts/networks you own or have explicit permission to test.
# =====================================================================

def detect_os(open_ports):
    if 445 in open_ports:
        return "Likely Windows (SMB detected)"
    if 22 in open_ports and 3306 not in open_ports:
        return "Likely Linux/Unix"
    if 548 in open_ports:
        return "Likely macOS"
    return "Unknown"
