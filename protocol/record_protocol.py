from protocol.handshake_protocol import *
from protocol.change_cipher_spec_protocol import *
from protocol.application_data_protocol import *
import struct


class RecodeLayer:
    def __init__(self, t):
        self.content_type = t
        self.version = 0x0303
        self.length = None  # 2byte
        self.raw_data = None

        self.key_exchange_algorithm = None

    def set_key_exchange_algorithm(self, algorithm):
        self.key_exchange_algorithm = algorithm

    def wrap(self, item):
        if self.content_type == ContentType.HANDSHAKE:
            self.wrap_handshake(item)
        elif self.content_type == ContentType.ALERT:
            self.wrap_alert(item)
        elif self.content_type == ContentType.CHANGE_CIPHER_SPEC:
            self.wrap_change_cipher_spec(item)
        elif self.content_type == ContentType.APPLICATION_DATA:
            self.wrap_application_data(item)

        record_header = struct.pack("!BHH", self.content_type, self.version, len(self.raw_data) + 5)
        self.raw_data = record_header + self.raw_data

        print(f"\n[wrap]Record Content Type: {self.content_type}")
        print(f"[wrap]Record length: {len(self.raw_data)}")
        print(f"[wrap]Record raw: {self.raw_data}\n")

        return self.raw_data

    def extract(self, raw):
        record_header = struct.unpack("!BHH", raw[:5])
        self.content_type = record_header[0]
        self.version = record_header[1]
        self.length = record_header[2]
        print(f"\n[extract]Record Content Type: {self.content_type}")
        print(f"[extract]Record length: {len(raw)}")
        print(f"[extract]Record raw: {raw}\n")
        if self.content_type == ContentType.HANDSHAKE:
            return self.extract_handshake(raw[5:])
        elif self.content_type == ContentType.ALERT:
            return self.extract_alert(raw[5:])
        elif self.content_type == ContentType.CHANGE_CIPHER_SPEC:
            return self.extract_change_cipher_spec(raw[5:])
        elif self.content_type == ContentType.APPLICATION_DATA:
            return self.extract_application_data(raw[5:])
        else:
            '''wrong content type'''
            print("[error]")

    def wrap_handshake(self, item):
        if isinstance(item, ClientHello):
            self.raw_data = HandShakeType.CLIENT_HELLO.to_bytes(1, byteorder='big')
            self.raw_data += item.length.to_bytes(3, byteorder='big')
            self.raw_data += item.client_version.to_bytes(2, byteorder='big')
            self.raw_data += item.random

            self.raw_data += item.session_id_length.to_bytes(1, byteorder='big')
            if item.session_id_length != 0:
                self.raw_data += item.session_id

            self.raw_data += item.cipher_suites_length.to_bytes(2, byteorder='big')
            if item.cipher_suites_length != 0:
                for c in item.cipher_suites:
                    self.raw_data += c.to_bytes(2, byteorder='big')

            self.raw_data += item.compression_methods_length.to_bytes(1, byteorder='big')
            if item.compression_methods_length != 0:
                for c in item.compression_methods:
                    self.raw_data += c.to_bytes(1, byteorder='big')

            self.raw_data += item.extensions_length.to_bytes(2, byteorder='big')
            if item.extensions_length != 0:
                for e in item.extensions:
                    self.raw_data += e.to_bytes(2, byteorder='big')

            return True

        elif isinstance(item, ServerHello):
            self.raw_data = HandShakeType.SERVER_HELLO.to_bytes(1, byteorder='big')
            self.raw_data += item.length.to_bytes(3, byteorder='big')
            self.raw_data += item.server_version.to_bytes(2, byteorder='big')
            self.raw_data += item.random

            self.raw_data += item.session_id_length.to_bytes(1, byteorder='big')
            if item.session_id_length != 0:
                self.raw_data += item.session_id

            self.raw_data += item.cipher_suites.to_bytes(2, byteorder='big')

            self.raw_data += item.compression_methods.to_bytes(2, byteorder='big')

            self.raw_data += item.extensions_length.to_bytes(2, byteorder='big')
            if item.extensions_length != 0:
                for e in item.extensions:
                    self.raw_data += e.to_bytes(2, byteorder='big')
            return True

        elif isinstance(item, Certificate):
            self.raw_data = HandShakeType.CERTIFICATE.to_bytes(1, byteorder='big')
            self.raw_data += item.length.to_bytes(3, byteorder='big')
            for l, cert in zip(item.certificate_length, item.certificate_list):
                self.raw_data += l.to_bytes(3, byteorder='big')
                self.raw_data += cert

            return True

        elif isinstance(item, ServerKeyExchange):
            self.raw_data = HandShakeType.SERVER_KEY_EXCHANGE.to_bytes(1, byteorder='big')
            self.raw_data += item.length.to_bytes(3, byteorder='big')

            if item.key_exchange_algorithm in [KeyExchangeAlgorithm.DHE_DSS, KeyExchangeAlgorithm.DHE_RSA]:
                self.raw_data += item.p_length.to_bytes(3, byteorder='big')
                self.raw_data += item.server_DH_p
                self.raw_data += item.g_length.to_bytes(3, byteorder='big')
                self.raw_data += item.server_DH_g
                self.raw_data += item.pubkey_length.to_bytes(3, byteorder='big')
                self.raw_data += item.server_DH_pubkey

            elif item.key_exchange_algorithm in [KeyExchangeAlgorithm.ECDHE_RSA, KeyExchangeAlgorithm.ECDHE_DSS]:
                self.raw_data += item.ec_curve_type.to_bytes(1, byteorder='big')
                self.raw_data += item.ec_name_curve.to_bytes(2, byteorder='big')
                self.raw_data += item.pubkey_length.to_bytes(3, byteorder='big')
                self.raw_data += item.ec_pubkey

            self.raw_data += item.signature_hash_algorithm.to_bytes(1, byteorder='big')
            self.raw_data += item.signature_length.to_bytes(3, byteorder='big')
            self.raw_data += item.signed_params
            return True

        elif isinstance(item, CertificateRequest):
            self.raw_data = HandShakeType.CERTIFICATE_REQUEST.to_bytes(1, byteorder='big')
            self.raw_data += item.length.to_bytes(3, byteorder='big')

            self.raw_data += item.type_count.to_bytes(1, byteorder='big')
            for t in item.client_certificate_type:
                self.raw_data += t.to_bytes(1, byteorder='big')

            self.raw_data += item.signature_hash_algorithm_length.to_bytes(1, byteorder='big')
            for alg in item.signature_hash_algorithm:
                self.raw_data += alg.to_bytes(2, byteorder='big')

            self.raw_data += item.distinguished_name_length.to_bytes(3, byteorder='big')
            self.raw_data += item.distinguished_name

            return True

        elif isinstance(item, ServerHelloDone):
            self.raw_data = HandShakeType.SERVER_HELLO_DONE.to_bytes(1, byteorder='big')
            self.raw_data += item.length.to_bytes(3, byteorder='big')

            return True

        elif isinstance(item, CertificateVerify):
            self.raw_data = HandShakeType.CERTIFICATE_VERIFY.to_bytes(1, byteorder='big')
            self.raw_data += item.length.to_bytes(3, byteorder='big')

            self.raw_data += item.certificate_verify

            return True

        elif isinstance(item, ClientKeyExchange):
            self.raw_data = HandShakeType.CLIENT_KEY_EXCHANGE.to_bytes(1, byteorder='big')
            self.raw_data += item.length.to_bytes(3, byteorder='big')

            self.raw_data += item.exchange_key_length.to_bytes(3, byteorder='big')
            self.raw_data += item.exchange_key

            return True

        elif isinstance(item, Finished):
            self.raw_data = HandShakeType.FINISHED.to_bytes(1, byteorder='big')
            self.raw_data += item.length.to_bytes(3, byteorder='big')

            self.raw_data += item.finished

            return True
        elif isinstance(item, HelloRequest):
            pass
        else:
            print("[error]Unknown HandShake Type")
            return False

    def wrap_alert(self, item):
        pass

    def wrap_change_cipher_spec(self, item):
        if isinstance(item, ChangeCipherSpec):
            self.raw_data = item.change_cipher_spec.to_bytes(1, byteorder='big')
            return True
        else:
            print("[error]Unknown Type")
            return False

    def wrap_application_data(self, item):
        if isinstance(item, ApplicationData):
            self.raw_data = item.encrypt_text
            return True
        else:
            print("[error]Unknown Type")
            return False

    def extract_handshake(self, raw):
        t = raw[0]
        length = int.from_bytes(raw[1:4], byteorder='big')
        if t == HandShakeType.CLIENT_HELLO:
            version = int.from_bytes(raw[4:6], byteorder='big')
            random = raw[6:38]
            session_id_length = int.from_bytes(raw[38:39], byteorder='big')

            if session_id_length != 0:
                session_id = raw[39:39 + session_id_length]
                index = 39 + session_id_length
            else:
                session_id = None
                index = 39

            cipher_suites_length = int.from_bytes(raw[index:index + 2], byteorder='big')
            index += 2
            if cipher_suites_length != 0:
                cipher_suites = []
                data = raw[index:index + cipher_suites_length]
                i = 0
                while i < cipher_suites_length:
                    cipher_suites.append(int.from_bytes(data[i:i + 2], byteorder='big'))
                    i += 2
                index += cipher_suites_length
            else:
                cipher_suites = []

            compress_method_length = int.from_bytes(raw[index:index + 1], byteorder='big')
            index += 1
            if compress_method_length != 0:
                compress_methods = []
                data = raw[index:index + compress_method_length]
                i = 0
                while i < compress_method_length:
                    compress_methods.append(data[i])
                    i += 1
                index += compress_method_length
            else:
                compress_methods = []

            extensions_length = int.from_bytes(raw[index:index + 2], byteorder='big')
            index += 2
            if extensions_length != 0:
                extensions = []
                data = raw[index:index + extensions_length]
                i = 0
                while i < extensions_length:
                    extensions.append(int.from_bytes(data[i:i + 2], byteorder='big'))
                    i += 2
                index += extensions_length
            else:
                extensions = []

            message = {"SessionID": session_id,
                       "CipherSuites": cipher_suites,
                       "CompressionMethods": compress_methods,
                       "Random": random,
                       "Extensions": extensions
                       }
            return ClientHello(message)

        elif t == HandShakeType.SERVER_HELLO:
            version = int.from_bytes(raw[4:6], byteorder='big')
            random = raw[6:38]
            session_id_length = int.from_bytes(raw[38:39], byteorder='big')

            if session_id_length != 0:
                session_id = raw[39:39 + session_id_length]
                index = 39 + session_id_length
            else:
                session_id = None
                index = 40

            cipher_suite = int.from_bytes(raw[index:index + 2], byteorder='big')
            compress_method = int.from_bytes(raw[index + 2:index + 4], byteorder='big')
            index += 4

            extensions_length = int.from_bytes(raw[index:index + 2], byteorder='big')
            index += 2
            if extensions_length != 0:
                extensions = []
                data = raw[index:index + extensions_length]
                i = 0
                while i < extensions_length:
                    extensions.append(int.from_bytes(data[i:i + 2], byteorder='big'))
                    i += 2
                index += extensions_length
            else:
                extensions = []

            message = {"SessionID": session_id,
                       "SelectedCipherSuite": cipher_suite,
                       "SelectedCompressionMethod": compress_method,
                       "Random": random,
                       "Extensions": extensions
                       }
            return ServerHello(message)

        elif t == HandShakeType.CERTIFICATE:
            index = 4
            certificates = []
            while index < length:
                certificate_length = int.from_bytes(raw[index:index + 3], byteorder='big')
                index += 3
                cert = raw[index:index + certificate_length]
                certificates.append(cert)
                index += certificate_length

            message = {"CertificateList": certificates}
            return Certificate(message)

        elif t == HandShakeType.SERVER_KEY_EXCHANGE:
            index = 4
            if self.key_exchange_algorithm in [KeyExchangeAlgorithm.DHE_DSS, KeyExchangeAlgorithm.DHE_RSA]:
                p_length = int.from_bytes(raw[index:index + 3], byteorder='big')
                index += 3
                server_dh_p = raw[index:index + p_length]
                index += p_length

                g_length = int.from_bytes(raw[index:index + 3], byteorder='big')
                index += 3
                server_dh_g = raw[index:index + g_length]
                index += g_length

                pubkey_length = int.from_bytes(raw[index:index + 3], byteorder='big')
                index += 3
                server_dh_pubkey = raw[index:index + pubkey_length]
                index += pubkey_length

                if index < length:
                    signature_hash_algorithm = int.from_bytes(raw[index:index + 1], byteorder='big')
                    index += 1
                    signature_length = int.from_bytes(raw[index:index + 3], byteorder='big')
                    index += 3
                    signed_params = raw[index:index + signature_length]
                else:
                    signature_hash_algorithm = None
                    signed_params = None
                message = {"KeyExchangeAlgorithm": self.key_exchange_algorithm,
                           "ServerP": server_dh_p,
                           "ServerG": server_dh_g,
                           "ServerDHPublicKey": server_dh_pubkey,
                           "HashAlgorithm": signature_hash_algorithm,
                           "Signature": signed_params}

            elif self.key_exchange_algorithm in [KeyExchangeAlgorithm.ECDHE_DSS, KeyExchangeAlgorithm.ECDHE_RSA]:
                ec_curve_type = int.from_bytes(raw[index:index + 1], byteorder='big')
                index += 1
                ec_name_curve = int.from_bytes(raw[index:index + 2], byteorder='big')
                index += 2

                pubkey_length = int.from_bytes(raw[index:index + 3], byteorder='big')
                index += 3
                ec_pubkey = raw[index:index + pubkey_length]
                index += pubkey_length

                if index < length:
                    signature_hash_algorithm = int.from_bytes(raw[index:index + 1], byteorder='big')
                    index += 1
                    signature_length = int.from_bytes(raw[index:index + 3], byteorder='big')
                    index += 3
                    signed_params = raw[index:index + signature_length]
                else:
                    signature_hash_algorithm = None
                    signed_params = None
                message = {"KeyExchangeAlgorithm": self.key_exchange_algorithm,
                           "ECCurveType": ec_curve_type,
                           "NamedCurve": ec_name_curve,
                           "ServerECDHEPublicKey": ec_pubkey,
                           "HashAlgorithm": signature_hash_algorithm,
                           "Signature": signed_params}
            else:
                message = None

            return ServerKeyExchange(message)

        elif t == HandShakeType.CERTIFICATE_REQUEST:
            index = 4
            type_count = int.from_bytes(raw[index:index + 1], byteorder='big')
            index += 1
            i = 0
            client_certificate_type = []
            while i < type_count:
                client_certificate_type.append(int.from_bytes(raw[index:index + 1], byteorder='big'))
                index += 1
                i += 1

            signature_hash_algorithm_length = int.from_bytes(raw[index:index + 1], byteorder='big')
            index += 1
            i = 0
            signature_hash_algorithm = []
            while i < signature_hash_algorithm_length:
                signature_hash_algorithm.append(int.from_bytes(raw[index:index + 2], byteorder='big'))
                index += 2
                i += 2

            distinguished_name_length = int.from_bytes(raw[index:index + 3], byteorder='big')
            index += 3
            distinguished_name = raw[index:index + distinguished_name_length]

            message = {"ClientCertificateType": client_certificate_type,
                       "SignatureAndHashAlgorithms": signature_hash_algorithm,
                       "DistinguishedName": distinguished_name,
                       "SignatureAlgorithms": [],
                       "HashAlgorithms": []}

            return CertificateRequest(message)

        elif t == HandShakeType.SERVER_HELLO_DONE:
            return ServerHelloDone()

        elif t == HandShakeType.CERTIFICATE_VERIFY:
            verify_data = raw[4:length]
            message = {"CertificateVerify": verify_data}

            CV = CertificateVerify(message)
            CV.show()
            return CV

        elif t == HandShakeType.CLIENT_KEY_EXCHANGE:
            index = 4
            exchange_key_length = int.from_bytes(raw[index:index + 3], byteorder='big')
            index += 3
            exchange_key = raw[index:index + exchange_key_length]
            message = {"ExchangeKey": exchange_key}

            return ClientKeyExchange(message)

        elif t == HandShakeType.FINISHED:
            verify_data = raw[4:length]
            message = {"VerifyData": verify_data}

            return Finished(message)

        else:
            print("[error]")
            return False

    def extract_alert(self, raw):
        pass

    def extract_change_cipher_spec(self, raw):
        return ChangeCipherSpec()

    def extract_application_data(self, raw):
        encrypt_text = raw
        AD = ApplicationData(None, encrypt_text)
        AD.show()
        return AD


class TLSPlaintext:
    def __init__(self):
        self.version = 0x0303
        self.type = None
        self.fragment_length = 0
        self.fragment = None

    def wrap(self, record_data, content_type):
        self.type = content_type
        raw = self.type.to_bytes(1, byteorder='big')
        raw += self.version.to_bytes(2, byteorder='big')
        self.fragment = record_data
        self.fragment_length = len(self.fragment)
        raw += self.fragment_length.to_bytes(2, byteorder='big')
        raw += self.fragment
        print(f"\n[wrap]TLSPlaintext Content Type: {self.type}")
        print(f"[wrap]TLSPlaintext fragment length: {self.fragment_length}\n")
        return raw

    def extract(self, raw):
        self.type = int.from_bytes(raw[0:1], byteorder="big")
        self.version = int.from_bytes(raw[1:3], byteorder="big")
        self.fragment_length = int.from_bytes(raw[3:5], byteorder="big")
        self.fragment = raw[5:]
        print(f"\n[extract]TLSPlaintext Content Type: {self.type}")
        print(f"[extract]TLSPlaintext fragment length: {self.fragment_length}\n")
        if self.type == ContentType.HANDSHAKE:
            return self.split_handshake(self.fragment, self.fragment_length)
        elif self.type == ContentType.CHANGE_CIPHER_SPEC:
            return self.fragment
        elif self.type == ContentType.ALERT:
            pass

    def extract_handshake_head(self, raw):
        content_type = int.from_bytes(raw[0:1], byteorder='big')
        version = int.from_bytes(raw[1:3], byteorder='big')
        length = int.from_bytes(raw[3:5], byteorder='big')
        handshake_type = int.from_bytes(raw[5:6], byteorder='big')
        return content_type, version, length, handshake_type

    def split_handshake(self, raw, fragment_length):
        raw_list = []
        index = 0
        while index < fragment_length:
            head = self.extract_handshake_head(raw[index:])
            if head[3] in [HandShakeType.FINISHED, HandShakeType.CERTIFICATE_VERIFY, HandShakeType.CERTIFICATE,
                           HandShakeType.CERTIFICATE_REQUEST, HandShakeType.HELLO_REQUEST, HandShakeType.SERVER_HELLO,
                           HandShakeType.CLIENT_KEY_EXCHANGE, HandShakeType.SERVER_HELLO_DONE,
                           HandShakeType.SERVER_KEY_EXCHANGE, HandShakeType.CLIENT_HELLO]:
                raw_list.append(raw[index:index + head[2]])
            index += head[2]
        return raw_list


class TLSCiphertext:
    def __init__(self, cipher_type):
        self.version = 0x0303
        self.type = cipher_type
        self.fragment_length = 0
        self.fragment = None
        self.MAX_LENGTH = 2 ** 14

    def wrap(self, record_data, content_type):
        self.type = content_type
        raw = self.type.to_bytes(1, byteorder='big')
        raw += self.version.to_bytes(2, byteorder='big')
        self.fragment = record_data
        self.fragment_length = len(self.fragment)

        if self.fragment_length > self.MAX_LENGTH:
            print("[error]Payload too long")
            return False

        raw += self.fragment_length.to_bytes(2, byteorder='big')
        raw += self.fragment
        print(f"\n[wrap]TLSCiphertext Content Type: {self.type}")
        print(f"[wrap]TLSCiphertext fragment length: {self.fragment_length}\n")
        return raw

    def extract(self, raw):
        self.type = int.from_bytes(raw[0:1], byteorder="big")
        self.version = int.from_bytes(raw[1:3], byteorder="big")
        self.fragment_length = int.from_bytes(raw[3:5], byteorder="big")
        self.fragment = raw[5:]
        print(f"\n[extract]TLSCiphertext Content Type: {self.type}")
        print(f"[extract]TLSCiphertext fragment length: {self.fragment_length}\n")

        return self.fragment
