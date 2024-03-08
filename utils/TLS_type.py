# record layer
class ContentType:
    CHANGE_CIPHER_SPEC = 20
    ALERT = 21
    HANDSHAKE = 22
    APPLICATION_DATA = 23


# alert
class AlertLevel:
    WARNING = 1
    FATAL = 2


class AlertDescription:
    """
    enum {
       close_notify(0),
       unexpected_message(10),
       bad_record_mac(20),
       decryption_failed_RESERVED(21),
       record_overflow(22),
       decompression_failure(30),
       handshake_failure(40),
       no_certificate_RESERVED(41),
       bad_certificate(42),
       unsupported_certificate(43),
       certificate_revoked(44),
       certificate_expired(45),
       certificate_unknown(46),
       illegal_parameter(47),
       unknown_ca(48),
       access_denied(49),
       decode_error(50),
       decrypt_error(51),
       export_restriction_RESERVED(60),
       protocol_version(70),

       insufficient_security(71),
       internal_error(80),
       user_canceled(90),
       no_renegotiation(100),
       unsupported_extension(110),           /* new */
       (255)
   } AlertDescription;
    """
    CLOSE_NOTIFY = 0
    UNEXPECTED_MESSAGE = 10
    BAD_RECORD_MAC = 20
    DECRYPTION_FAILED_RESERVED = 21
    RECORD_OVERFLOW = 22
    DECOMPRESSION_FAILURE = 40
    HANDSHAKE_FAILURE = 40
    NO_CERTIFICATE_RESERVED = 41
    BAD_CERTIFICATE = 42
    UNSUPPORTED_CERTIFICATE = 43
    CERTIFICATE_REVOKED = 44
    CERTIFICATE_EXPIRED = 45
    CERTIFICATE_UNKNOWN = 46
    ILLEGAL_PARAMETER = 47
    UNKNOWN_CA = 48
    ACCESS_DENIED = 49
    DECODE_ERROR = 50
    DECRYPT_ERROR = 51
    EXPORT_RESTRICTION_RESERVED = 60
    PROTOCOL_VERSION = 70

    INSUFFICIENT_SECURITY = 71
    INTERNAL_ERROR = 80
    USER_CANCELED = 90
    NO_RENEGOTIATION = 100
    UNSUPPORTED_EXTENSION = 110


# handshake
class HandShakeType:
    """
    enum {
          hello_request(0), client_hello(1), server_hello(2),
          certificate(11), server_key_exchange (12),
          certificate_request(13), server_hello_done(14),
          certificate_verify(15), client_key_exchange(16),
          finished(20), (255)
      } HandshakeType;
    """
    HELLO_REQUEST = 0
    CLIENT_HELLO = 1
    SERVER_HELLO = 2
    CERTIFICATE = 3
    SERVER_KEY_EXCHANGE = 12
    CERTIFICATE_REQUEST = 13
    SERVER_HELLO_DONE = 14
    CERTIFICATE_VERIFY = 15
    CLIENT_KEY_EXCHANGE = 16
    FINISHED = 20


class CompressionMethod:
    # 1 byte
    NULL = 0


class ExtensionType:
    # 2 byte
    SIGNATURE_ALGORITHMS = 13


class HashAlgorithm:
    # 1 byte
    NONE = 0
    MD5 = 1
    SHA1 = 2
    SHA224 = 3
    SHA256 = 4
    SHA384 = 5
    SHA512 = 6


class SignatureAlgorithm:
    # 1 byte
    ANONYMOUS = 0
    RSA = 1
    DSA = 2
    ECDSA = 3


class KeyExchangeAlgorithm:
    DHE_DSS = "DHE_DSS"
    DHE_RSA = "DHE_RSA"
    # DH_ANON = "DH_ANON"
    RSA = "RSA"
    # DH_DSS = "DH_DSS"
    # DH_RSA = "DH_RSA"
    ECDHE_RSA = "ECDHE_RSA"
    ECDHE_DSS = "ECDHE_DSS"


class ClientCertificateType:
    # 2 byte
    RSA_SIGN = 1
    DSS_SIGN = 2
    RSA_FIXED_DH = 3
    DSS_FIXED_DH = 4
    RSA_EPHEMERAL_DH_RESERVED = 5
    DSS_EPHEMERAL_DH_RESERVED = 6
    FORTEZZA_DMS_RESERVED = 20


class SymmetricAlgorithm:
    NULL = "NULL"
    RC4_128 = "RC4_128"
    Triple_DES_EDE_CBC = "3DES_EDE_CBC"
    AES_128_CBC = "AES128_CBC"
    AES_256_CBC = "AES256_CBC"


class ECCurveType:
    # 1 byte
    deprecate = 1
    name_curve = 3
    reserver = 248


class NamedCurve:
    # 2 byte
    secp256r1 = 23
    secp384r1 = 24
    secp521r1 = 25
    x25519 = 29
    x448 = 30


# Cipher Suite
class CipherSuite:
    TLS_NULL_WITH_NULL_NULL = 0x0000

    TLS_RSA_WITH_NULL_MD5 = 0x0001
    TLS_RSA_WITH_NULL_SHA = 0x0002
    TLS_RSA_WITH_NULL_SHA256 = 0x003b
    TLS_RSA_WITH_RC4_128_MD5 = 0x0004
    TLS_RSA_WITH_RC4_128_SHA = 0x0005
    TLS_RSA_WITH_3DES_EDE_CBC_SHA = 0x000a
    TLS_RSA_WITH_AES_128_CBC_SHA = 0x002f
    TLS_RSA_WITH_AES_256_CBC_SHA = 0x0035
    TLS_RSA_WITH_AES_128_CBC_SHA256 = 0x003c
    TLS_RSA_WITH_AES_256_CBC_SHA256 = 0x003d

    TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA = 0x0013
    TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA = 0x0016
    TLS_DHE_DSS_WITH_AES_128_CBC_SHA = 0x0032
    TLS_DHE_RSA_WITH_AES_128_CBC_SHA = 0x0033
    TLS_DHE_DSS_WITH_AES_256_CBC_SHA = 0x0038
    TLS_DHE_RSA_WITH_AES_256_CBC_SHA = 0x0039
    TLS_DHE_DSS_WITH_AES_128_CBC_SHA256 = 0x0040
    TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 = 0x0067
    TLS_DHE_DSS_WITH_AES_256_CBC_SHA256 = 0x006A
    TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 = 0x006B
    TLS_ECDHE_RSA_WITH_NULL_SHA = 0xC010
    TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA = 0xC012
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA = 0xC013
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA = 0xC014

    # unsupported
    # TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA = 0x000d
    # TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA = 0x0010
    # TLS_DH_DSS_WITH_AES_128_CBC_SHA = 0x0030
    # TLS_DH_RSA_WITH_AES_128_CBC_SHA = 0x0031
    # TLS_DH_DSS_WITH_AES_256_CBC_SHA = 0x0036
    # TLS_DH_RSA_WITH_AES_256_CBC_SHA = 0x0037
    # TLS_DH_DSS_WITH_AES_128_CBC_SHA256 = 0x003E
    # TLS_DH_RSA_WITH_AES_128_CBC_SHA256 = 0x003F
    # TLS_DH_DSS_WITH_AES_256_CBC_SHA256 = 0x0068
    # TLS_DH_RSA_WITH_AES_256_CBC_SHA256 = 0x0069
    # TLS_DH_anon_WITH_RC4_128_MD5 = 0x0018
    # TLS_DH_anon_WITH_3DES_EDE_CBC_SHA = 0x001B
    # TLS_DH_anon_WITH_AES_128_CBC_SHA = 0x0034
    # TLS_DH_anon_WITH_AES_256_CBC_SHA = 0x003A
    # TLS_DH_anon_WITH_AES_128_CBC_SHA256 = 0x006C
    # TLS_DH_anon_WITH_AES_256_CBC_SHA256 = 0x006D
    # TLS_ECDHE_ECDSA_WITH_NULL_SHA = 0xC006
    # TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA = 0xC008
    # TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA = 0xC009
    # TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA = 0xC00A
    # TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = 0xC02B
    # TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 = 0xC02C
    # TLS_ECDH_anon_WITH_NULL_SHA = 0xC015
    # TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA = 0xC017
    # TLS_ECDH_anon_WITH_AES_128_CBC_SHA = 0xC018
    # TLS_ECDH_anon_WITH_AES_256_CBC_SHA = 0xC019
    # TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = 0xC02F
    # TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = 0xC030
