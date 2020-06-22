import socket
import enum

from .tls_definitions import (
    Contents,
    Protocols,
    CiphersTLSv12,
    Handshakes,
    SignatureAlgorithms
)

class Errors(enum.Enum):
    InvalidInit = "The scanner class has not been correctly initialized"


class Scanner():

    def __init__(self, hostname: str, port: int, proxy: dict = None):
        self.hostname = hostname
        self.port = port
        if (not isinstance(hostname, str) or
                not isinstance(port, int) or
                not isinstance(proxy, dict)):
            return [], Errors.InvalidInit.value
        self.proxy = proxy

    def run(self):
        """Runs numerous TLS Handshake attempts to determine supported versions

        Returns:
            [dict], err: An array representing the tested TLS Handshakes
        """
        # Trial run
        content_type = Contents.HANDSHAKE.value
        size = "xxxx"  # calculate; 2 bytes

        handshake_type = Handshakes.CLIENT_HELLO.value
        handshake_size = "xxxxxx"  # calculate; 3 bytes
        handshake_version = Protocols.TLSv12.value

        client_random = "xx"  # 32 bytes: 4 UNIX epoch + 28 random

        ciphers_size = "0002"  # calculate; 2 bytes; 2 bytes per cipher;
        cipher = CiphersTLSv12.TLS_RSA_WITH_AES_256_GCM_SHA384.value

        compression_methods_length = "01"  # 1 byte
        compression_method = "00"  # 1 byte; 00 is Null (no compression)

        extensions_length = "0013"  # calculate: 2 bytes
        server_name = "0000"  # type 0000 is server name
        server_name_length = "000f"  # calculate; 2 bytes
        server_name_list_length = "000d"  # calculate; 2 bytes
        server_name_type = "00"  # 00 is hostname
        hostname_length = "000a"  # calculate; 2 bytes
        hostname = "google.com"  # for the above, google.com has 10 chars/bytes

        sig_algs_type = "000d"  # extension type signature algorithms
        sig_length = "0004"  # calculate: 2 bytes; 2 bytes length hashes + hashes (2 bytes per hash)
        sig_hash_length = "0002"  # calculate: 2 bytes per hash
        sig_alg = SignatureAlgorithms.SHA384_DSA.value  # 2 bytes

        def get_hex(value, byte_size):
            padding = byte_size * 2 + 2
            zero_x = f"{value:#0{padding}x}"
            return zero_x[2:]

        def get_bytesize(hexstring):
            return int(len(hexstring) / 2)

        sig_algs = SignatureAlgorithms.SHA384_DSA.value
        sig_hash_length = get_hex(get_bytesize(sig_algs), 2)
        sig_length = get_hex(get_bytesize(sig_hash_length+sig_algs), 2)
        sig_algs_type = "000d"  # extension type signature algorithms

        message = content_type
        message += Protocols.TLSv10.value  # not the actual protocol in use
        message += size
        message += handshake_type
        message += handshake_size
        message += handshake_version
        message += client_random
        message += '00'  # session id

        message += ciphers_size
        message += cipher

        message += compression_methods_length
        message += compression_method

        message += extensions_length

        message += server_name
        message += server_name_length
        message += server_name_list_length
        message += server_name_type
        message += hostname_length
        message += hostname

        message += sig_algs_type
        message += sig_length
        message += sig_hash_length
        message += sig_alg

        return [], None
