from utils.TLS_type import *


class HandShake:
    """
    struct {
          HandshakeType msg_type;    /* handshake type */
          uint24 length;             /* bytes in message */
          select (HandshakeType) {
              case hello_request:       HelloRequest;
              case client_hello:        ClientHello;
              case server_hello:        ServerHello;
              case certificate:         Certificate;
              case server_key_exchange: ServerKeyExchange;
              case certificate_request: CertificateRequest;
              case server_hello_done:   ServerHelloDone;
              case certificate_verify:  CertificateVerify;
              case client_key_exchange: ClientKeyExchange;
              case finished:            Finished;
          } body;
      } Handshake;
    """

    def __init__(self):
        pass


class ClientHello(HandShake):
    def __init__(self, msg):
        super().__init__()
        self.handshake_type = HandShakeType.CLIENT_HELLO
        self.client_version = 0x0303
        self.length = 0

        self.random = None

        self.session_id_length = 0
        self.session_id = None

        self.cipher_suites_length = 0
        self.cipher_suites = None

        self.compression_methods_length = 0
        self.compression_methods = None

        self.extensions_length = 0
        self.extensions = None

        self.set_message(msg)

    def set_message(self, msg):
        self.random = msg["Random"]
        self.session_id = msg["SessionID"]
        self.cipher_suites = msg["CipherSuites"]
        self.compression_methods = msg["CompressionMethods"]
        self.extensions = msg["Extensions"]

        self.length = 6 + 32  # type+length+version+random

        if self.session_id is not None:
            self.session_id_length = len(self.session_id)
        self.length += 1 + self.session_id_length

        self.cipher_suites_length = len(self.cipher_suites) * 2
        self.length += 2 + self.cipher_suites_length

        if self.compression_methods is not None:
            self.compression_methods_length = len(self.compression_methods)
        self.length += 1 + self.compression_methods_length

        if self.extensions is not None:
            self.extensions_length = len(self.extensions) * 2
        self.length += 2 + self.extensions_length

    def show(self):
        print("--------------Client Hello--------------")
        print(f"[show]HandShake Type: {self.handshake_type}")
        print(f"[show]Version: {hex(self.client_version)}")
        print(f"[show]Length: {self.length}")
        print(f"[show]Random: {self.random}")
        print(f"[show]Session ID Length: {self.session_id_length}")
        print(f"[show]Session ID: {self.session_id}")
        print(f"[show]Cipher Suites Length: {self.cipher_suites_length}")
        print(f"[show]Cipher Suites: {self.cipher_suites}")
        print(f"[show]Compress Method Length: {self.compression_methods_length}")
        print(f"[show]Compress Methods: {self.compression_methods}")
        print(f"[show]Extensions Length: {self.extensions_length}")
        print(f"[show]Extensions: {self.extensions}")
        print("--------------Client Hello--------------\n")


class ServerHello(HandShake):
    def __init__(self, msg):
        super().__init__()
        self.handshake_type = HandShakeType.SERVER_HELLO
        self.server_version = 0x0303
        self.length = 0

        self.random = None

        self.session_id = None
        self.session_id_length = 0

        self.extensions_length = 0
        self.extensions = None

        self.compression_methods = None

        self.cipher_suites = None

        self.set_message(msg)

    def set_message(self, msg):
        self.random = msg["Random"]
        self.session_id = msg["SessionID"]
        self.cipher_suites = msg["SelectedCipherSuite"]
        self.compression_methods = msg["SelectedCompressionMethod"]
        self.extensions = msg["Extensions"]

        self.length = 6 + 32  # type+length+version+random

        if self.session_id is not None:
            self.session_id_length = len(self.session_id)
        self.length += 1 + self.session_id_length

        self.length += 4  # cipher suite & compress method

        if self.extensions is not None:
            self.extensions_length = len(self.extensions) * 2
        self.length += 2 + self.extensions_length

    def show(self):
        print("--------------Server Hello--------------")
        print(f"[show]HandShake Type: {self.handshake_type}")
        print(f"[show]Version: {hex(self.server_version)}")
        print(f"[show]Length: {self.length}")
        print(f"[show]Random: {self.random}")
        print(f"[show]Session ID Length: {self.session_id_length}")
        print(f"[show]Session ID: {self.session_id}")
        print(f"[show]Select Cipher Suite Length: {self.cipher_suites}")
        print(f"[show]Select Compress Method: {self.compression_methods}")
        print(f"[show]Extensions Length: {self.extensions_length}")
        print(f"[show]Extensions: {self.extensions}")
        print("--------------Server Hello--------------\n")


class Certificate(HandShake):
    def __init__(self, msg):
        super().__init__()
        self.handshake_type = HandShakeType.CERTIFICATE
        self.length = 0
        self.certificate_length = []
        self.certificate_list = None

        self.set_message(msg)

    def set_message(self, msg):
        self.length += 4  # type+length
        self.certificate_list = msg["CertificateList"]
        for cert in self.certificate_list:
            l = len(cert)
            self.certificate_length.append(l)
            self.length += l + 3

    def show(self):
        print("--------------Certificate--------------")
        print(f"[show]HandShake Type: {self.handshake_type}")
        print(f"[show]Length: {self.length}")
        print(f"[show]Certificate Length: {self.certificate_length}")
        print(f"[show]Certificates: {self.certificate_list}")
        print("--------------Certificate--------------\n")


class ServerKeyExchange(HandShake):
    def __init__(self, msg):
        super().__init__()
        self.handshake_type = HandShakeType.SERVER_KEY_EXCHANGE
        self.length = 0

        self.key_exchange_algorithm = None
        self.pubkey_length = 0

        # dhe
        self.p_length = 0
        self.g_length = 0
        self.server_DH_p = None
        self.server_DH_g = None
        self.server_DH_pubkey = None

        # ecdhe
        self.ec_curve_type = None
        self.ec_name_curve = None
        self.ec_pubkey = None

        self.signature_hash_algorithm = None
        self.signature_length = 0
        self.signed_params = None

        self.set_message(msg)

    def set_message(self, msg):
        self.length += 4  # type+length
        self.key_exchange_algorithm = msg["KeyExchangeAlgorithm"]

        if self.key_exchange_algorithm in [KeyExchangeAlgorithm.DHE_DSS, KeyExchangeAlgorithm.DHE_RSA]:
            self.server_DH_p = msg["ServerP"]
            self.p_length = len(self.server_DH_p)
            self.length += 3 + self.p_length

            self.server_DH_g = msg["ServerG"]
            self.g_length = len(self.server_DH_g)
            self.length += 3 + self.g_length

            self.server_DH_pubkey = msg["ServerDHPublicKey"]
            self.pubkey_length = len(self.server_DH_pubkey)
            self.length += 3 + self.pubkey_length

        elif self.key_exchange_algorithm in [KeyExchangeAlgorithm.ECDHE_DSS, KeyExchangeAlgorithm.ECDHE_RSA]:
            self.ec_curve_type = msg["ECCurveType"]
            self.ec_name_curve = msg["NamedCurve"]
            self.length += 3
            self.ec_pubkey = msg["ServerECDHEPublicKey"]
            self.pubkey_length = len(self.ec_pubkey)
            self.length += 3 + self.pubkey_length
        else:
            raise ValueError("Unsupported key exchange algorithm")

        self.signature_hash_algorithm = msg["HashAlgorithm"]
        self.signed_params = msg["Signature"]
        self.signature_length = len(self.signed_params)
        self.length += 1 + 3 + self.signature_length

    def show(self):
        print("--------------Server Key Exchange--------------")
        print(f"[show]HandShake Type: {self.handshake_type}")
        print(f"[show]Length: {self.length}")
        print(f"[show]Key Exchange Algorithm: {self.key_exchange_algorithm}")
        print(f"[show]Server DH_p Length: {self.p_length}")
        print(f"[show]Server DH_p: {self.server_DH_p}")
        print(f"[show]Server DH_g Length: {self.g_length}")
        print(f"[show]Server DH_g: {self.server_DH_g}")
        print(f"[show]Server DH_PublicKey Length: {self.pubkey_length}")
        print(f"[show]Server DH_PublicKey: {self.server_DH_pubkey}")
        if self.key_exchange_algorithm in [KeyExchangeAlgorithm.DHE_DSS, KeyExchangeAlgorithm.DHE_RSA]:
            print(f"[show]Hash Algorithm: {self.signature_hash_algorithm}")
            print(f"[show]Signature Length: {self.signature_length}")
            print(f"[show]Signature: {self.signed_params}")
        print("--------------Server Key Exchange--------------\n")


class CertificateVerify(HandShake):
    def __init__(self, msg):
        super().__init__()
        self.handshake_type = HandShakeType.CERTIFICATE_VERIFY
        self.length = 0

        self.certificate_verify = None

        self.set_message(msg)

    def set_message(self, msg):
        self.certificate_verify = msg["CertificateVerify"]
        self.length += 4 + len(self.certificate_verify)

    def show(self):
        print("--------------Certificate Verify--------------")
        print(f"[show]HandShake Type: {self.handshake_type}")
        print(f"[show]Length: {self.length}")
        print(f"[show]Certificate Verify Data: {self.certificate_verify}")
        print("--------------Certificate Verify--------------\n")


class CertificateRequest(HandShake):
    def __init__(self, msg):
        super().__init__()
        self.handshake_type = HandShakeType.CERTIFICATE_REQUEST
        self.length = 0

        self.type_count = 0
        self.client_certificate_type = None
        self.signature_hash_algorithm_length = 0
        self.signature_hash_algorithm = []
        self.signature_algorithms = None
        self.hash_algorithms = None
        self.distinguished_name_length = 0
        self.distinguished_name = None

        self.set_message(msg)

    def set_message(self, msg):
        self.length = 4  # type+length

        self.signature_hash_algorithm = msg["SignatureAndHashAlgorithms"]
        self.client_certificate_type = msg["ClientCertificateType"]
        self.type_count = len(self.client_certificate_type)
        self.length += 1

        self.signature_algorithms = msg["SignatureAlgorithms"]
        self.hash_algorithms = msg["HashAlgorithms"]
        if not self.signature_hash_algorithm:
            for s in self.signature_algorithms:
                for h in self.hash_algorithms:
                    self.signature_hash_algorithm.append(s << 8 | h)
                    self.signature_hash_algorithm_length += 2
        else:
            list_s = []
            list_h = []
            for sh in self.signature_hash_algorithm:
                s = (sh & 0xff00) >> 8
                h = sh & 0x00ff
                # keep order
                if s not in list_s:
                    list_s.append(s)
                if h not in list_h:
                    list_h.append(h)
            self.signature_algorithms = list_s
            self.hash_algorithms = list_h
            self.signature_hash_algorithm_length = len(self.signature_hash_algorithm) * 2
        self.length += 1 + self.signature_hash_algorithm_length

        self.distinguished_name = msg["DistinguishedName"]
        self.distinguished_name_length = len(self.distinguished_name)
        self.length += 3 + self.distinguished_name_length

    def show(self):
        print("--------------Certificate Request--------------")
        print(f"[show]HandShake Type: {self.handshake_type}")
        print(f"[show]Length: {self.length}")
        print(f"[show]Signature and Hash Algorithms: {self.signature_hash_algorithm}")
        print(f"[show]Client Certificate Type: {self.client_certificate_type}")
        print(f"[show]Count: {self.type_count}")
        print(f"[show]Signature Algorithms: {self.signature_algorithms}")
        print(f"[show]Hash Algorithms: {self.hash_algorithms}")
        print(f"[show]Distinguished Name Length: {self.distinguished_name_length}")
        print(f"[show]Distinguished Name: {self.distinguished_name}")
        print("--------------Certificate Request--------------\n")


class ClientKeyExchange(HandShake):
    def __init__(self, msg):
        super().__init__()
        self.key_exchange_algorithm = None
        self.handshake_type = HandShakeType.CLIENT_KEY_EXCHANGE
        self.length = 0

        self.exchange_key_length = 0
        self.exchange_key = None

        self.set_message(msg)

    def set_message(self, msg):
        self.length += 4
        self.exchange_key = msg["ExchangeKey"]
        self.exchange_key_length += len(self.exchange_key)
        self.length += 3 + self.exchange_key_length

    def show(self):
        print("--------------Client Key Exchange--------------")
        print(f"[show]HandShake Type: {self.handshake_type}")
        print(f"[show]Length: {self.length}")
        print(f"[show]Exchange Key Length: {self.exchange_key_length}")
        print(f"[show]Exchange Key: {self.exchange_key}")
        print("--------------Certificate Request--------------\n")


class Finished(HandShake):
    def __init__(self, msg):
        super().__init__()
        self.handshake_type = HandShakeType.FINISHED
        self.length = 0
        self.finished = None

        self.set_message(msg)

    def set_message(self, msg):
        self.finished = msg["VerifyData"]
        self.length += 4 + len(self.finished)

    def show(self):
        print("--------------Finished--------------")
        print(f"[show]HandShake Type: {self.handshake_type}")
        print(f"[show]Length: {self.length}")
        print(f"[show]Verify Data: {self.finished}")
        print("--------------Finished--------------\n")


class ServerHelloDone(HandShake):
    def __init__(self):
        super().__init__()
        self.handshake_type = HandShakeType.SERVER_HELLO_DONE
        self.length = 4

    def show(self):
        print("--------------Server Hello Done--------------")
        print(f"[show]HandShake Type: {self.handshake_type}")
        print(f"[show]Length: {self.length}")
        print("--------------Server Hello Done--------------\n")


class HelloRequest(HandShake):
    def __init__(self):
        super().__init__()

        self.handshake_type = HandShakeType.HELLO_REQUEST
