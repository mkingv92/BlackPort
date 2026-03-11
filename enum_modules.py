# =====================================================================
# File: enum_modules.py
# Notes:
# - This file is part of the BlackPort project.
# - The comments added here are for readability only (no behavior change).
# - Use only on hosts/networks you own or have explicit permission to test.
# =====================================================================

import socket
import re
import ftplib
import subprocess

# NOTE: get_http_title() - helper/entry function. Read the body for the exact steps.
def get_http_title(ip, port):
    try:
        s = socket.socket()
        s.settimeout(3)
        s.connect((ip, port))
        s.send(f"GET / HTTP/1.1\r\nHost: {ip}\r\n\r\n".encode())
        data = s.recv(4096).decode(errors="ignore")
        s.close()

        match = re.search(r"<title>(.*?)</title>", data, re.IGNORECASE)
        if match:
            return match.group(1)
    except:
        return None


# NOTE: check_ftp_anonymous() - helper/entry function. Read the body for the exact steps.
def check_ftp_anonymous(ip):
    try:
        ftp = ftplib.FTP(ip, timeout=3)
        ftp.login("anonymous", "anonymous")
        ftp.quit()
        return True
    except:
        return False


# NOTE: enum_smb_shares() - helper/entry function. Read the body for the exact steps.
def enum_smb_shares(ip):
    smb_data = {
        "version": None,
        "signing": None,
        "shares": []
    }

    try:
        # Get share list
        result = subprocess.run(
            ["smbclient", "-L", f"//{ip}", "-N"],
            capture_output=True,
            text=True,
            timeout=5
        )

        output = result.stdout

        if not output:
            return None

        # --- Extract shares ---
        for line in output.splitlines():
            line = line.strip()
            if line and not line.startswith(("Sharename", "----")):
                parts = line.split()
                if len(parts) >= 1:
                    share = parts[0]
                    if share not in ["IPC$", "Reconnecting"]:
                        smb_data["shares"].append(share)

        # --- Detect SMB version (basic heuristic) ---
        if "SMB1" in output:
            smb_data["version"] = "SMBv1"
        elif "SMB2" in output:
            smb_data["version"] = "SMBv2"
        else:
            smb_data["version"] = "Unknown"

        # --- Detect signing ---
        if "signing required" in output.lower():
            smb_data["signing"] = True
        elif "signing disabled" in output.lower():
            smb_data["signing"] = False
        else:
            smb_data["signing"] = None

        return smb_data

    except Exception:
        return None
