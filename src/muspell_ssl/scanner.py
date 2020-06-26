import socket
import enum
import os
import logging

from .tls_definitions import (
    Contents,
    Protocols,
    ProtocolCiphers,
    Handshakes,
)

# CONSTANTS
TIMEOUT = 5  # socket connection timeout in seconds
BUFFER = 4096

# Logging Setup
logging.basicConfig(
    filename="scanner.log",
    level=logging.INFO,
    format='%(asctime)-15s - %(levelname)s - %(message)s'
)


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
        results = []
        try:
            # Try a number of secret handshakes
            logging.info("Muspell SSL")
            logging.info("Starting scan for {}:{}".format(self.hostname,
                                                          self.port))
            logging.info("---")
            for protocol in Protocols:
                logging.info("***\nProtocol: {}".format(protocol.name))
                result = {}
                result["protocol"] = protocol.name
                ciphers = ProtocolCiphers[protocol.name]
                result["ciphers_tested"] = len(ciphers)
                ciphers_supported = []
                for cipher in ciphers:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(TIMEOUT)
                    # sock.setblocking(False)
                    address = (self.hostname, self.port)
                    hello_bytes = self._build_client_hello(
                        self.hostname,
                        protocol.value,
                        cipher.value)
                    logging.info("Testing cipher: {}".format(cipher.name))
                    logging.info("Client Hello:")
                    logging.info(hello_bytes.hex())
                    sock.connect(address)
                    sock.send(hello_bytes)
                    response = sock.recv(BUFFER)
                    response = response.hex()
                    sock.shutdown(socket.SHUT_RDWR)
                    sock.close()

                    # Evaluate response
                    logging.info("Response from remote server:")
                    logging.info(response)
                    if len(response) > 2:
                        if response[:2] == Contents.HANDSHAKE.value:
                            logging.info("{} supported: YES.".format(
                                cipher.name))
                            ciphers_supported.append(cipher.name)
                        else:
                            logging.info("{} supported: NO.".format(
                                cipher.name))
                    logging.info("#################")
                result["ciphers_supported"] = ciphers_supported
                print("Test finished for protocol: {}".format(protocol.name))
                results.append(result)
            logging.info("Results:\n{}".format(results))
            logging.info("Scan finished.")

        except socket.timeout:
            logging.info(Errors.SocketTimeout.value)
            sock.shutdown(socket.SHUT_RDWR)
            sock.close()
            return None, Errors.SocketTimeout.value

        except Exception as e:
            unknown_error = str(e)
            logging.info(unknown_error)
            sock.shutdown(socket.SHUT_RDWR)
            sock.close()
            return None, unknown_error

        return [], None

    def _build_client_hello(self, host, protocol, cipher_suite):
        """Builds a TLS Client Hello byte sequence for the given arguments.

        Args:
            host (str): a DNS record or IP address.
            protocol (str): 4 hex chars (2 bytes) representing the TLS
                            Protocol to test according to RFC.
            cipher_suite (str): 4 hex chars (2 bytes) representing the cipher
                                suite to test.
        Returns:
            byte string: a hex representation of the hello message which can
                         be sent over a network to a remote host.
        """

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

        # Extension server name
        hostname = host.encode("utf-8").hex()
        hostname_length = get_length(hostname, 2)
        server_name_type = "00"  # 00 is hostname
        ext_server_name = server_name_type + hostname_length + hostname
        server_name_list_length = get_length(ext_server_name, 2)
        ext_server_name = server_name_list_length + ext_server_name
        server_name_length = get_length(ext_server_name, 2)
        ext_type = "0000"  # type 0x0000 is servername
        ext_server_name = ext_type + server_name_length + ext_server_name

        # Extensions combined
        extensions = ext_server_name
        extensions_length = get_length(extensions, 2)
        message = extensions_length + extensions

        # Compression
        compression_method = "00"  # 1 byte; 00 is Null (no compression)
        compr_length = get_length(compression_method, 1)
        message = compr_length + compression_method + message

        # Cipher suites
        ciphers = cipher_suite
        ciphers_length = get_length(ciphers, 2)
        message = ciphers_length + ciphers + message

        # Session
        session_length = "00"  # not using session
        message = session_length + message

        # Client random: 32 bytes. Unix Epoch usage deemed insecure.
        rnd = os.urandom(32).hex()

        # Handshake
        handshake_version = protocol
        message = handshake_version + rnd + message
        handshake_length = get_length(message, 3)  # 3 bytes
        handshake_type = Handshakes.CLIENT_HELLO.value
        message = handshake_type + handshake_length + message

        # Final adjustment
        total_size = get_length(message, 2)  # calculate; 2 bytes
        hello_version = protocol
        content_type = Contents.HANDSHAKE.value

        message = content_type + hello_version + total_size + message
        return bytes.fromhex(message)
