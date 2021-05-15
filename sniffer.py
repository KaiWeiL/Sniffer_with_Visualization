import socket
import ctypes
import struct

# Get local IP address with Python stdlib
from typing import Dict

HOST = [l for l in ([ip for ip in socket.gethostbyname_ex(socket.gethostname())[2]
                     if not ip.startswith("127.")][:1], [[(s.connect(('8.8.8.8', 53)),
                                                           s.getsockname()[0], s.close()) for s in
                                                          [socket.socket(socket.AF_INET,
                                                                         socket.SOCK_DGRAM)]][0][1]]) if l][0][0]


class IP(ctypes.Structure):
    _fields_ = [('version', ctypes.c_ubyte, 4),
                ('IHL', ctypes.c_ubyte, 4),
                ('type_of_service', ctypes.c_ubyte, 8),
                ('total_length', ctypes.c_ushort, 16),
                ('id', ctypes.c_ushort, 16),
                ('offset', ctypes.c_ushort, 16),
                ('ttl', ctypes.c_ubyte, 8),
                ('protocol', ctypes.c_ubyte, 8),
                ('header_checksum', ctypes.c_ushort, 16),
                ('src_address', ctypes.c_uint32, 32),
                ('dest_address', ctypes.c_uint32, 32)]


    def __new__(cls, buffer=None):
        return cls.from_buffer_copy(buffer)

    def __init__(self, buffer=None):
        print("Socket created and initialized successfully!")

    def get_src_address(self):
        return socket.inet_ntoa(struct.pack('<L', self.src_address))

    def get_dest_address(self):
        return socket.inet_ntoa(struct.pack('<L', self.dest_address))

    def get_protocol_type(self):
        protocol_type_map = {1: "ICMP", 6: 'TCP', 17: 'UDP'}
        for protocol_num in protocol_type_map:
            if protocol_num == self.protocol:
                return protocol_type_map.get(protocol_num)


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as sniffer:
        sniffer.bind((HOST, 0))
        sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        data_buff = sniffer.recvfrom(66)
        captured_packet = IP(data_buff[0])
        print(captured_packet.get_src_address())
        print(captured_packet.get_dest_address())
        print(captured_packet.get_protocol_type())


main()
