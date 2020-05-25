import socket

from .errors import UnableToResolveDNS


class Utilities():

    @staticmethod
    def dns_lookup(hostname: str, port: int):
        try:
            address_data = socket.getaddrinfo(
                hostname,
                port,
                socket.AF_UNSPEC,
                socket.IPPROTO_IP)
        except (socket.gaierror, IndexError, ConnectionError):
            raise UnableToResolveDNS("Unable to resolve IP for: {}".format(
                hostname))

        family, _, _, _, socket_addr = address_data[0]
        ip_address = socket_addr[0]  # Use first entry by default
        for family, _, _, _, socket_addr in address_data:
            if family == socket.AF_INET:
                ip_address = socket_addr[0]

        return ip_address
