import enum


class Contents(enum.Enum):
    HANDSHAKE = '16'
    ALERT = '15'


class Handshakes(enum.Enum):
    CLIENT_HELLO = '01'
    SERVER_HELLO = '02'


class Protocols(enum.Enum):
    # SSLv20 = '0002'
    # SSLv30 = '0300'
    TLSv10 = '0301'
    TLSv11 = '0302'
    TLSv12 = '0303'
    TLSv13 = '0304'


class CiphersTLSv10v11(enum.Enum):
    TLS_RSA_WITH_AES_256_CBC_SHA = '0035'
    TLS_RSA_WITH_AES_128_CBC_SHA = '002f'
    TLS_RSA_WITH_3DES_EDE_CBC_SHA = '000a'
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA = 'c014'
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA = 'c013'


class CiphersTLSv12(enum.Enum):
    TLS_RSA_WITH_AES_256_GCM_SHA384 = '009d'
    TLS_RSA_WITH_AES_256_CBC_SHA = '0035'
    TLS_RSA_WITH_AES_128_GCM_SHA256 = '009c'
    TLS_RSA_WITH_AES_128_CBC_SHA = '002f'
    TLS_RSA_WITH_3DES_EDE_CBC_SHA = '000a'
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = 'cca8'
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = 'c030'
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA = 'c014'
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = 'c02f'
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA = '0c13'
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 = 'cca9'
    TLS_PSK_WITH_AES_128_GCM_SHA256 = '00a8'  # not accepted by google.com


class CiphersTLSv13(enum.Enum):
    TLS_CHACHA20_POLY1305_SHA256 = '1303'
    TLS_AES_256_GCM_SHA384 = '1302'
    TLS_AES_128_GCM_SHA256 = '1301'


class CiphersSSLv20(enum.Enum):
    SSL2_DES_64_CBC_WITH_MD5 = '060040'


ProtocolCiphers = {
    # SSLv20 = '0002'
    # SSLv30 = '0300'
    "TLSv10": CiphersTLSv10v11,
    "TLSv11": CiphersTLSv10v11,
    "TLSv12": CiphersTLSv12,
    "TLSv13": CiphersTLSv13,
}
