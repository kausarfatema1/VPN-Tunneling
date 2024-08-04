#!/usr/bin/python3

import fcntl
import struct
import os
import socket
import select
from scapy.all import IP

# Constants
IP_A = "0.0.0.0"
PORT = 9090
TUNSETIFF = 0x400454ca
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000

def create_tun_interface():
    tun = os.open("/dev/net/tun", os.O_RDWR)
    ifr = struct.pack('16sH', b'tun%d', IFF_TUN | IFF_NO_PI)
    ifname_bytes = fcntl.ioctl(tun, TUNSETIFF, ifr)
    ifname = ifname_bytes.decode('UTF-8')[:16].strip("\x00")
    return tun, ifname

def setup_tun_interface(ifname):
    os.system(f"ip addr add 192.168.53.1/24 dev {ifname}")
    os.system(f"ip link set dev {ifname} up")
    os.system(f"ip route add 192.168.50.0/24 dev {ifname}")

def main():
    # Create and set up TUN interface
    tun, ifname = create_tun_interface()
    print(f"Interface Name: {ifname}")
    setup_tun_interface(ifname)

    # Create UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((IP_A, PORT))

    # Initialize IP and port (their values do not matter initially)
    ip = '10.9.0.5'
    port = 10000

    fds = [sock, tun]

    while True:
        # This will block until at least one socket is ready
        ready, _, _ = select.select(fds, [], [])

        for fd in ready:
            if fd is sock:
                data, (ip, port) = sock.recvfrom(2048)
                pkt = IP(data)
                print(f"From socket <==: {pkt.src} --> {pkt.dst}")
                os.write(tun, data)
            elif fd is tun:
                packet = os.read(tun, 2048)
                pkt = IP(packet)
                print(f"From tun    ==>: {pkt.src} --> {pkt.dst}")
                sock.sendto(packet, (ip, port))

if __name__ == "__main__":
    main()
