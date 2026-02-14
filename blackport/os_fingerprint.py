def detect_os(open_ports):
    if 445 in open_ports:
        return "Likely Windows (SMB detected)"
    if 22 in open_ports and 3306 not in open_ports:
        return "Likely Linux/Unix"
    if 548 in open_ports:
        return "Likely macOS"
    return "Unknown"
