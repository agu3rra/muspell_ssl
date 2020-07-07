import enum
import os
import logging
import json
import errno
import asyncio
from collections import deque  # for using stacks

from .tls_definitions import (
    Contents,
    Handshakes,
    Protocols,
    ProtocolCiphers,
    EcPointFormats,
    SupportedGroups,
    TLS_EMPTY_RENEGOTIATION_INFO_SCSV,
    SignatureAlgorithms,
)
from .utilities import Utilities

# CONSTANTS
TIMEOUT = 3  # socket connection timeout in seconds
BUFFER = 4096
SIMULTANEOUS_CONNECTIONS = 3  # number of simultaneous async connections

# Logging Setup
logging.basicConfig(
    filename="scanner.log",
    level=logging.INFO,
    format='%(asctime)-15s - %(levelname)s - %(message)s'
)


class Errors(enum.Enum):
    InvalidInit = "The scanner class has not been correctly initialized"
    SocketTimeout = "Timeout when trying to reach remote server. Please "\
        "check network connectivity or if the service is actually being "\
        "served at the host:port given."


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
        # Try a number of handshakes
        logging.info("####################################")
        logging.info("Muspell SSL")
        logging.info("Starting scan for {}:{}".format(self.hostname,
                                                      self.port))
        logging.info("---")
        for protocol in Protocols:
            logging.info("***\nProtocol: {}".format(protocol.name))
            result = {}
            result["protocol"] = protocol.name
            ciphers = deque(ProtocolCiphers[protocol.name])
            result["ciphers_tested"] = len(ciphers)
            ciphers_supported = []
            errors = []

            # Create buffer of ciphers to test
            ciphers_buffer = []
            while len(ciphers) > 0:
                buffer_element = []
                for i in range(SIMULTANEOUS_CONNECTIONS):
                    buffer_element.append(ciphers.pop())
                    if len(ciphers) == 0:
                        break
                ciphers_buffer.append(buffer_element)

            # In here I should have a group of simultanous tasks to call
            address = (self.hostname, self.port)
            for ciphers_group in ciphers_buffer:
                loop = asyncio.get_event_loop()
                tasks = []
                # Schedule tasks
                for cipher in ciphers_group:
                    hello_bytes = self._build_client_hello(
                        self.hostname,
                        protocol,
                        cipher.value)

                    tasks.append(
                        loop.create_task(
                            self.async_send(hello_bytes, address, cipher.name)
                        )
                    )
                # Run tasks
                try:
                    for task in tasks:
                        loop.run_until_complete(task)
                finally:
                    loop.close()
                # Process results for this group
                for task in tasks:
                    response, err, cipher_name = task.result()
                    if err is None:  # Valid response obtained
                        # Evaluate response
                        logging.info("Cipher: {}".format(cipher_name))
                        logging.info("Response from remote server:")
                        logging.info(response)
                        if len(response) > 12:
                            content_type = response[:2]
                            version = response[2:6]
                            hand_type = response[10:12]
                            if (content_type == Contents.HANDSHAKE.value and
                                    version == protocol.value and
                                    hand_type == Handshakes.SERVER_HELLO.value):

                                logging.info("{} supported: YES.".format(
                                    cipher_name))
                                ciphers_supported.append(cipher_name)
                            else:
                                logging.info("{} supported: NO.".format(
                                    cipher_name))
                        logging.info("#################")
                    else:
                        errors.append(cipher_name)

            result["ciphers_supported"] = ciphers_supported
            result["errors"] = errors
            print("Test finished for protocol: {}".format(protocol.name))
            results.append(result)
        logging.info("Results:\n{}".format(json.dumps(results, indent=4)))
        logging.info("Scan finished.")

        return results, None

    def _build_client_hello(self, host, protocol, cipher_suite):
        """Builds a TLS Client Hello byte sequence for the given arguments.

        Args:
            host (str): a DNS record or IP address.
            protocol (enum): The enum representing the protocol and its hex
                            value.
            cipher_suite (str): 4 hex chars (2 bytes) representing the cipher
                                suite to test.
        Returns:
            byte string: a hex representation of the hello message which can
                         be sent over a network to a remote host.
        """

        if protocol.value == Protocols.SSLv20.value:
            return self._client_hello_sslv20(cipher_suite)

        # Placeholder for final byte sequence message
        message = ''
        if protocol.name.count("TLS") == 1:
            # Extensions are supported as of TLSv1.0 onwards

            # Extension Supported Versions
            sup_version = protocol.value
            sup_version_len = Utilities.get_length(sup_version, 1)
            ext_len = Utilities.get_length(sup_version_len+sup_version, 2)
            ext_type = '002b'
            ext_supported_versions = ext_type + \
                ext_len + \
                sup_version_len + \
                sup_version

            # Extension Signature Algorithms
            algorithms = ""
            for algorithm in SignatureAlgorithms:
                algorithms += algorithm.value
            alg_len = Utilities.get_length(algorithms, 2)
            ext_len = Utilities.get_length(alg_len+algorithms, 2)
            ext_type = '000d'
            ext_signature_algs = ext_type + ext_len + alg_len + algorithms

            # Extension Extended Master Secret
            ext_type = '0017'
            ext_len = '0000'
            ext_extended_master_key = ext_type + ext_len

            # Extension Encrypt then MAC
            ext_type = '0016'
            ext_len = '0000'
            ext_encrypt_then_mac = ext_type + ext_len

            # Extension Session Ticket
            ext_type = '0023'
            ext_len = '0000'
            ext_session_ticket = ext_type + ext_len

            # Extension Supported Groups
            supported_groups = ""
            for group in SupportedGroups:
                supported_groups += group.value
            groups_list_len = Utilities.get_length(supported_groups, 2)
            groups = groups_list_len + supported_groups
            groups_len = Utilities.get_length(groups, 2)
            ext_type = "000a"  # supported group type
            ext_supported_groups = ext_type + groups_len + groups

            # Extension EC Point Formats
            ec_points = ""
            for point in EcPointFormats:
                ec_points += point.value
            points_len = Utilities.get_length(ec_points, 1)
            ext_len = Utilities.get_length(points_len + ec_points, 2)
            ext_type = "000b"  # ec point formats type
            ext_ec_point_formats = ext_type + ext_len + points_len + ec_points

            # Extension server name
            hostname = host.encode("utf-8").hex()
            hostname_length = Utilities.get_length(hostname, 2)
            server_name_type = "00"  # 00 is hostname
            ext_server_name = server_name_type + hostname_length + hostname
            server_name_list_length = Utilities.get_length(ext_server_name, 2)
            ext_server_name = server_name_list_length + ext_server_name
            server_name_length = Utilities.get_length(ext_server_name, 2)
            ext_type = "0000"  # type 0x0000 is servername
            ext_server_name = ext_type + server_name_length + ext_server_name

            # Extensions combined
            extensions = ext_server_name + \
                ext_ec_point_formats + \
                ext_supported_groups + \
                ext_supported_versions
                # ext_signature_algs + \
                # ext_session_ticket + \
                # ext_encrypt_then_mac + \
                # ext_extended_master_key + \

            extensions_length = Utilities.get_length(extensions, 2)
            message = extensions_length + extensions

        # Compression
        compression_method = "00"  # 0x0100 (DEFLATE + NULL)
        compr_length = Utilities.get_length(compression_method, 1)
        message = compr_length + compression_method + message

        # Cipher suites
        ciphers = cipher_suite + TLS_EMPTY_RENEGOTIATION_INFO_SCSV
        ciphers_length = Utilities.get_length(ciphers, 2)
        message = ciphers_length + ciphers + message

        # Session
        session_length = "00"  # not using session
        message = session_length + message

        # Client random: 32 bytes. Unix Epoch usage deemed insecure.
        rnd = os.urandom(32).hex()

        # Handshake
        handshake_version = protocol.value
        message = handshake_version + rnd + message
        handshake_length = Utilities.get_length(message, 3)  # 3 bytes
        handshake_type = Handshakes.CLIENT_HELLO.value
        message = handshake_type + handshake_length + message

        # Final adjustment
        total_size = Utilities.get_length(message, 2)  # calculate; 2 bytes
        hello_version = protocol.value
        content_type = Contents.HANDSHAKE.value

        message = content_type + hello_version + total_size + message
        return bytes.fromhex(message)

    def _client_hello_sslv20(self, cipher_suite):
        """The Hello on SSLv2.0 looks different enough that I wanted to add it
        separately.
        """
        challenge = os.urandom(16).hex()
        challenge_length = Utilities.get_length(challenge, 2)

        ciphers = cipher_suite
        ciphers_length = Utilities.get_length(ciphers, 2)

        session_length = "0000"  # not using session

        version = Protocols.SSLv20.value

        handshake_type = Handshakes.CLIENT_HELLO.value

        message = handshake_type + \
            version + \
            ciphers_length + \
            session_length + \
            challenge_length + \
            ciphers + \
            challenge

        total_length = Utilities.get_length(message, 1)
        message = '80' + total_length + message  # Observed all SSLv20
        # messages start with 0x80.

        return bytes.fromhex(message)

    async def async_send(self, message, address, cipher):
        """Sends an asynchronous message to a remote server

        Args:
            message ([bytes]): byte array representing a message
            address (str, int): a tuple that represents the remote server
            cipher (str): the cipher I wish to test, since when this returns I
                          won't know. Parsing the message is an alternative.

        Returns:
            [type]: [description]
        """
        shutdown_required = True
        response = ""  # ensure response exists if there is exception
        error = None
        try:
            host = address[0]
            port = address[1]
            reader, writer = await asyncio.open_connection(host,
                                                           port)
            writer.write(message)
            await writer.drain()
            response = await reader.read(BUFFER)
            response = response.hex()
        except Exception as e:
            error = str(e)
            if (e.errno == errno.ECONNREFUSED or
                    e.errno == errno.ENOTCONN or
                    e.errno == errno.ECONNRESET or
                    e.errno == errno.ECONNABORTED):
                shutdown_required = False

        if shutdown_required:
            # sock.shutdown(socket.SHUT_RDWR)
            writer.close()
            await writer.wait_closed()

        return response, error, cipher
