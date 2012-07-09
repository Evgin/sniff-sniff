import socket
import sys

__author__ = 'Evgin'

def create_socket():
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW)
    host = socket.gethostbyname(socket.gethostname())
    sock.bind((host, 0))
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    return sock


def main():
    sock = create_socket()
    data, address_info = sock.recvfrom(65565)
    print address_info, data


if __name__ == '__main__':
    sys.exit(main())
else:
    pass
