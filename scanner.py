import socket
import os

# Get local IP address with Python stdlib
HOST = [l for l in ([ip for ip in socket.gethostbyname_ex(socket.gethostname())[2]
                     if not ip.startswith("127.")][:1], [[(s.connect(('8.8.8.8', 53)),
                                                           s.getsockname()[0], s.close()) for s in
                                                          [socket.socket(socket.AF_INET,
                                                                         socket.SOCK_DGRAM)]][0][1]]) if l][0][0]


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as sniffer:
        sniffer.bind((HOST, 0))
        sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        print(sniffer.recvfrom(65565))


main()
