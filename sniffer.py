import socket
import struct
import sys

__author__ = 'Evgin'


def parse_tcp_packet(data):
    """
        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |          Source Port          |       Destination Port        |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                        Sequence Number                        |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                    Acknowledgment Number                      |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |  Data |           |U|A|P|R|S|F|                               |
        | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
        |       |           |G|K|H|T|N|N|                               |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |           Checksum            |         Urgent Pointer        |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                    Options                    |    Padding    |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                             data                              |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

                                TCP Header Format

    """
    tcp_packet_data = {}
    tcp_header = data[20:32]
    header = struct.unpack('!HHLL', tcp_header)
    src_port = header[0]
    dest_port = header[1]
    seq_num = header[2]
    ack_num = header[3]

    tcp_packet_data['src_port'] = src_port
    tcp_packet_data['dest_port'] = dest_port
    tcp_packet_data['seq_num'] = seq_num
    tcp_packet_data['ack_num'] = ack_num

    tcp_packet_data['data'] = data[48:]

    return tcp_packet_data


def parse_ip_packet_header(data):
    """
        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |Version|  IHL  |Type of Service|          Total Length         |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |         Identification        |Flags|      Fragment Offset    |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |  Time to Live |    Protocol   |         Header Checksum       |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                       Source Address                          |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                    Destination Address                        |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                    Options                    |    Padding    |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

                        Example Internet Datagram Header
    """
    icmp_packet_data = dict()
    ip_header = data[0:20]
    iph = struct.unpack('!BBHHHBBH4s4s', ip_header)

    version_ihl = iph[0]
    version = version_ihl >> 4
    ihl = version_ihl & 0xF
    icmp_packet_data['version'] = version
    icmp_packet_data['ihl'] = ihl

    ttl = iph[5]
    protocol = iph[6]
    icmp_packet_data['ttl'] = ttl
    icmp_packet_data['protocol'] = protocol

    src_addr = socket.inet_ntoa(iph[8])
    dest_addr = socket.inet_ntoa(iph[9])
    icmp_packet_data['src_addr'] = src_addr
    icmp_packet_data['dest_addr'] = dest_addr

    return  icmp_packet_data


def create_socket():
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW)
    host = socket.gethostbyname(socket.gethostname())
    sock.bind((host, 0))
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    return sock


def recv_packet(sock):
    data, address_info = sock.recvfrom(65565)
    return data, address_info


def parse_icmp_packet(data):
    """
        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |     Type      |     Code      |          Checksum             |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                             unused                            |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |      Internet Header + 64 bits of Original Data Datagram      |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    """
    packet_data = {}
    icmp_header = data[20:24]
    icmph = struct.unpack('!BBH', icmp_header)

    type = icmph[0]
    code = icmph[1]
    checksum = icmph[2]

    packet_data['type'] = type
    packet_data['code'] = code
    packet_data['checksum'] = checksum

    icmpdata = data[28:]
    packet_data['data'] = icmpdata

    return  packet_data


def main():
    sock = create_socket()
    while True:
        data, address_info = recv_packet(sock)
        packet_data = parse_ip_packet_header(data)
        protocol = packet_data['protocol']
        if  protocol == 6:
            packet_data = dict(packet_data.items() + parse_tcp_packet(data).items())
            if packet_data['src_port'] == 80:
                print packet_data
        elif protocol == 1:
            packet_data = dict(packet_data.items() + parse_icmp_packet(data).items())
        #            print packet_data
        else:
            pass

    return 0


if __name__ == '__main__':
    sys.exit(main())
else:
    pass
