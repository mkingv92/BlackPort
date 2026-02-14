import socket
import re
import ftplib
import subprocess

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


def check_ftp_anonymous(ip):
    try:
        ftp = ftplib.FTP(ip, timeout=3)
        ftp.login("anonymous", "anonymous")
        ftp.quit()
        return True
    except:
        return False


def enum_smb_shares(ip):
    try:
        result = subprocess.run(
            ["smbclient", "-L", f"//{ip}", "-N"],
            capture_output=True,
            text=True,
            timeout=5
        )
        return result.stdout
    except:
        return None
