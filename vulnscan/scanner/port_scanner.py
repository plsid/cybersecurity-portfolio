# scanner/port_scanner.py
from scapy.all import IP, TCP, sr1

def syn_scan(target, ports):
    """TCP SYN stealth scan"""
    open_ports = []
    for port in ports:
        packet = IP(dst=target)/TCP(dport=port, flags="S")
        response = sr1(packet, timeout=1, verbose=0)
        
        if response and response.haslayer(TCP):
            if response[TCP].flags == "SA":  # SYN-ACK = open
                open_ports.append(port)
                # Send RST to close connection
                sr1(IP(dst=target)/TCP(dport=port, flags="R"), timeout=1, verbose=0)
    return open_ports

