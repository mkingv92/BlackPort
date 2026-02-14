import socket
import ssl

def show_banner(VERSION):
    print(f"""
==============================
        BLACKPORT v{VERSION}
  Offensive Port Intelligence
==============================
""")

def grab_banner(target, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(3)
            s.connect((target, port))

            # Try passive receive first
            try:
                data = s.recv(1024)
                if data:
                    print("RAW:", repr(data))
                    return data.decode(errors="ignore").strip()
            except:
                pass

            # HTTP trigger
            if port == 80:
                s.sendall(b"GET / HTTP/1.1\r\nHost: " + target.encode() + b"\r\n\r\n")
                data = s.recv(1024)
                if data:
                    print("RAW:", repr(data))
                    return data.decode(errors="ignore").strip()

            # HTTPS trigger
            if port == 443:
                context = ssl.create_default_context()
                with context.wrap_socket(s, server_hostname=target) as ssock:
                    ssock.sendall(b"GET / HTTP/1.1\r\nHost: " + target.encode() + b"\r\n\r\n")
                    data = ssock.recv(1024)
                    if data:
                        print("RAW:", repr(data))
                        return data.decode(errors="ignore").strip()

        return None

    except Exception as e:
        print("Banner error:", e)
        return None
