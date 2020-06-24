import socket
import enum
import os

from .tls_definitions import (
    Contents,
    Protocols,
    CiphersTLSv12,
    Handshakes,
    SignatureAlgorithms
)

TIMEOUT = 3  # socket connection timeout in seconds
BUFFER = 4096


class Errors(enum.Enum):
    InvalidInit = "The scanner class has not been correctly initialized"
    SocketTimeout = "Unable to reach remote server. Please check network "\
        "connectivity or if the service is actually being served at the "\
        "host:port given."


class Scanner():

    def __init__(self, hostname: str, port: int):
        self.hostname = hostname
        self.port = port
        if (not isinstance(hostname, str) or not isinstance(port, int)):
            raise ValueError(Errors.InvalidInit.value)

    def run(self):
        """Runs numerous TLS Handshake attempts to determine supported versions

        Returns:
            [dict], err: An array representing the tested TLS Handshakes
        """
        # Trial run
        hello_bytes = self._build_client_hello()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        address = (self.hostname, self.port)
        try:
            sock.connect(address)
            sock.send(hello_bytes)
            response = sock.recv(BUFFER)
            response = response.hex()

        except socket.timeout:
            return None, Errors.SocketTimeout.value

        except Exception as e:
            unknown_error = str(e)
            print(unknown_error)
            return None, unknown_error

        finally:
            sock.close()

        return [], None

    def _build_client_hello(self):

        def get_length(message, bytes_size):
            """
            Generates the length (in bytes) of the given message padding the
            result with the amount of bytes provided as input.

            Returns:
                str
            """
            def get_hex(value, byte_size):
                padding = byte_size * 2 + 2
                zero_x = f"{value:#0{padding}x}"
                return zero_x[2:]

            def get_bytesize(hexstring):
                return int(len(hexstring) / 2)

            return get_hex(get_bytesize(message), bytes_size)

        # Extension signature
        sig_algs = SignatureAlgorithms.SHA384_DSA.value
        ext_sig_algs = sig_algs
        sig_hash_length = get_length(ext_sig_algs, 2)
        ext_sig_algs = sig_hash_length + ext_sig_algs
        sig_length = get_length(ext_sig_algs, 2)
        ext_type = "000d"  # extension type signature algorithms
        ext_sig_algs = ext_type + sig_length + ext_sig_algs

        # Extension server name
        hostname = "google.com".encode("utf-8").hex()  # for the above, google.com has 10 chars/bytes
        hostname_length = get_length(hostname, 2)
        server_name_type = "00"  # 00 is hostname
        ext_server_name = server_name_type + hostname_length + hostname
        server_name_list_length = get_length(ext_server_name, 2)
        ext_server_name = server_name_list_length + ext_server_name
        server_name_length = get_length(ext_server_name, 2)
        ext_type = "0000"  # type 0x0000 is servername
        ext_server_name = ext_type + server_name_length + ext_server_name

        # Extensions combined
        extensions = ext_server_name + ext_sig_algs
        extensions_length = get_length(extensions, 2)
        message = extensions_length + extensions

        # Compression
        compression_method = "00"  # 1 byte; 00 is Null (no compression)
        compr_length = get_length(compression_method, 1)
        message = compr_length + compression_method + message

        # Cipher suites
        #ciphers = CiphersTLSv12.TLS_RSA_WITH_AES_256_GCM_SHA384.value
        ciphers = CiphersTLSv12.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384.value
        ciphers_length = get_length(ciphers, 2)
        message = ciphers_length + ciphers + message

        # Session
        session_length = "00"  # not using session
        message = session_length + message

        # Client random: 32 bytes. Unix Epoch usage deemed insecure.
        rnd = os.urandom(32).hex()

        # Handshake
        handshake_version = Protocols.TLSv12.value
        message = handshake_version + rnd + message
        handshake_length = get_length(message, 3)  # 3 bytes
        handshake_type = Handshakes.CLIENT_HELLO.value
        message = handshake_type + handshake_length + message

        # Final adjustment
        total_size = get_length(message, 2)  # calculate; 2 bytes
        hello_version = Protocols.TLSv10.value  # not sure it works for all cases; perhaps it needs to be SSLv30 for it and TLSv10 for other cases; compatibility issues
        content_type = Contents.HANDSHAKE.value

        message = content_type + hello_version + total_size + message
        return bytes.fromhex(message)
