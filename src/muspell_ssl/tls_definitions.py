import enum


class Protocols(enum.Enum):
    SSLv20 = '0002'
    SSLv30 = '0300'
    TLSv10 = '0301'
    TLSv11 = '0302'
    TLSv12 = '0303'
    TLSv13 = '0304'


class CiphersTLSv12(enum.Enum):
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 = 'c02c'
    TLS_RSA_WITH_AES_256_GCM_SHA384 = '009d'  # I know google accepts this one


class CiphersSSLv20(enum.Enum):
    SSL2_DES_64_CBC_WITH_MD5 = '060040'


class Contents(enum.Enum):
    HANDSHAKE = '16'


class Handshakes(enum.Enum):
    CLIENT_HELLO = '01'
    SERVER_HELLO = '02'


class SignatureAlgorithms(enum.Enum):
    SHA384_DSA = '0502'  # DSA: Digital Signature Algorithm
    SHA256_DSA = '0402'
