import socket
import enum


class Errors(enum.Enum):
    UnableToResolveDNS = "Unable to resolve IP for the given host."


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
            raise ValueError(Errors.UnableToResolveDNS.value)

        family, _, _, _, socket_addr = address_data[0]
        ip_address = socket_addr[0]  # Use first entry by default
        for family, _, _, _, socket_addr in address_data:
            if family == socket.AF_INET:
                ip_address = socket_addr[0]

        return ip_address

    @staticmethod
    def get_length(message, bytes_size):
        """
        Generates the length (in bytes) of the given message padding the
        result with the amount of bytes provided as input.

        Returns:
            str

        Example: get_length('a011',3) returns '000002'
        """
        def get_hex(value, byte_size):
            padding = byte_size * 2 + 2
            zero_x = f"{value:#0{padding}x}"
            return zero_x[2:]

        def get_bytesize(hexstring):
            return int(len(hexstring) / 2)

        return get_hex(get_bytesize(message), bytes_size)
