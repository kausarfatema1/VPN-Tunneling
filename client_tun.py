#!/usr/bin/python3

import fcntl
import struct
import os
import socket
import select
from scapy.all import IP

TUNSETIFF = 0x400454ca
IFF_TUN = 0x0001
IFF_TAP = 0x0002
IFF_NO_PI = 0x1000

def create_tun_interface():
    tun = os.open("/dev/net/tun", os.O_RDWR)
    ifr = struct.pack('16sH', b'fatema%d', IFF_TUN | IFF_NO_PI)
    ifname_bytes = fcntl.ioctl(tun, TUNSETIFF, ifr)
    ifname = ifname_bytes.decode('UTF-8')[:16].strip("\x00")
    return tun, ifname

def setup_tun_interface(ifname):
    os.system(f"ip addr add 192.168.53.99/24 dev {ifname}")
    os.system(f"ip link set dev {ifname} up")
    os.system(f"ip route add 192.168.60.0/24 dev {ifname}")

def main():
    # Create and set up TUN interface
    tun, ifname = create_tun_interface()
    print(f"Interface Name: {ifname}")
    setup_tun_interface(ifname)

    # Create UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
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
                sock.sendto(packet, ('10.9.0.11', 9090))

if __name__ == "__main__":
    main()
