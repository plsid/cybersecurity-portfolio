# scanner/service_detect.py
import socket

def grab_banner(ip, port):
    """Attempt to grab service banner"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((ip, port))
        
        # Send probe for common protocols
        sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
        banner = sock.recv(1024).decode().strip()
        sock.close()
        return banner
    except:
        return None
