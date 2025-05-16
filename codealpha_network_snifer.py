import socket
import struct
import sys
import os

def get_local_ip():
    """Get your local IP address."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return socket.gethostbyname(socket.gethostname())

def parse_ip_header(data):
    ip_header = struct.unpack('!BBHHHBBH4s4s', data[:20])
    version_ihl = ip_header[0]
    version = version_ihl >> 4
    ihl = version_ihl & 0xF
    protocol = ip_header[6]
    src = socket.inet_ntoa(ip_header[8])
    dst = socket.inet_ntoa(ip_header[9])
    return version, ihl, protocol, src, dst

def get_protocol_name(proto):
    return {
        1: "ICMP",
        6: "TCP",
        17: "UDP"
    }.get(proto, f"Unknown ({proto})")

def main():
    host = get_local_ip()
    print(f"[*] Starting sniffer on {host}...")

    try:
        # Create raw socket
        sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        sniffer.bind((host, 0))
        sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        # Windows needs promiscuous mode enabled
        if os.name == 'nt':
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    except PermissionError:
        print("[!] Run this script as Administrator or root.")
        sys.exit(1)

    try:
        while True:
            raw_data, addr = sniffer.recvfrom(65535)
            version, ihl, proto, src, dst = parse_ip_header(raw_data)
            proto_name = get_protocol_name(proto)

            print(f"\n[+] Packet:")
            print(f"    Version         : {version}")
            print(f"    Header Length   : {ihl * 4} bytes")
            print(f"    Protocol        : {proto_name}")
            print(f"    Source IP       : {src}")
            print(f"    Destination IP  : {dst}")

    except KeyboardInterrupt:
        print("\n[*] Stopping sniffer.")
        if os.name == 'nt':
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        sys.exit(0)

if __name__ == "__main__":
    main()
