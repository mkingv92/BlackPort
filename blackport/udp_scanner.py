import socket

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
