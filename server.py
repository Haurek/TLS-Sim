from utils.util import *
from protocol.handshake_protocol import *
from protocol.record_protocol import *
from protocol.alert_protocol import *
from protocol.change_cipher_spec_protocol import *
from protocol.application_data_protocol import *
from utils.crypt import *
from utils.TLS_type import *


class TLSServer:
    def __init__(self, s, addr):
        # socket
        self.socket = s
        self.address = addr
        self.connect_socket = None

        # config
        self.server_version = 0x0303
        self.client_version = None

        # session ID
        self.session_id = None

        # default cipher suite
        self.supported_cipher_suites = [CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256]
        # compress methods
        self.supported_compression_methods = [CompressionMethod.NULL]

        # selected session configuration
        self.selected_cipher_suite = None
        self.selected_compression_method = None
        self.selected_key_exchange_algorithm = None
        self.selected_symmetric_algorithm = None
        self.selected_hash_algorithm = None
        self.certificate_request = True

        # command line chose configuration
        self.cmd_key_exchange_algorithm = None
        self.cmd_symmetric_algorithm = None
        self.cmd_hash_algorithm = None
        self.cmd_signature_algorithm = None

        # certificate
        # only support rsa sign and dss sign certificate
        self.supported_certificate_types = [ClientCertificateType.RSA_SIGN, ClientCertificateType.DSS_SIGN]
        self.supported_cert_signature_algorithms = [SignatureAlgorithm.RSA, SignatureAlgorithm.DSA]
        # default certificate hash algorithm is SHA256
        self.supported_cert_hash_algorithms = [HashAlgorithm.SHA256]

        # random
        self.client_random = None
        self.server_random = None

        # server certificate
        self.certificates = []

        # server key exchange
        # dh
        self.server_dh_p = 0
        self.server_dh_g = 0
        self.server_dh_public, self.server_dh_private = load_key("./src/key/server_dh_public_key.pem",
                                                                 "./src/key/server_dh_private_key.pem")
        self.client_dh_p = 0
        self.client_dh_g = 0
        self.client_dh_public = None
        # ecdhe
        self.server_ecdhe_public = None
        self.server_ecdhe_private = None
        self.client_ecdhe_public = None
        self.server_curve_name = None

        # rsa
        self.server_rsa_public, self.server_rsa_private = load_key("./src/key/server_rsa_public_key.pem",
                                                                   "./src/key/server_rsa_private_key.pem")
        self.client_rsa_public = None
        # dsa
        self.server_dsa_public, self.server_dsa_private = load_key("./src/key/server_dsa_public_key.pem",
                                                                   "./src/key/server_dsa_private_key.pem")
        self.client_dsa_public = None

        # client certificate
        self.client_certificates = None
        self.selected_signature_algorithm = None

        # client key exchange
        self.pre_master_secret = None

        # session key
        self.master_secret = None

        # handshake message had sent and received
        # used for signature and verify
        self.handshake_message = b''

        # server state
        self.is_encrypt = False
        self.is_connect = False

    # 设置Cipher suites
    def set_cipher_suite(self, key_exchange, symmetric, hash):
        self.cmd_key_exchange_algorithm = key_exchange
        self.cmd_symmetric_algorithm = symmetric
        self.cmd_hash_algorithm = hash
        if key_exchange in [KeyExchangeAlgorithm.RSA, KeyExchangeAlgorithm.DHE_RSA, KeyExchangeAlgorithm.ECDHE_RSA]:
            self.cmd_signature_algorithm = SignatureAlgorithm.RSA
        elif key_exchange in [KeyExchangeAlgorithm.DHE_DSS, KeyExchangeAlgorithm.ECDHE_DSS]:
            self.cmd_signature_algorithm = SignatureAlgorithm.DSA
        else:
            self.cmd_signature_algorithm = None

    # 从ClientHello中选择Cipher suite
    def select_cipher_suite(self, suites):
        for c in suites:
            if c in self.supported_cipher_suites:
                self.selected_cipher_suite = c
                break

        if self.selected_cipher_suite is None:
            print("[error]There is no suitable Cipher suite")
            raise ValueError("No suitable Cipher suite")

        self.selected_key_exchange_algorithm, \
        self.selected_signature_algorithm, \
        self.selected_symmetric_algorithm, \
        self.selected_hash_algorithm = extract_cipher_suite(self.selected_cipher_suite)

    # 选择Compress method
    def select_compression_method(self, compression_method):
        self.selected_compression_method = CompressionMethod.NULL

    def handshake(self, client_hello):
        # check version
        if client_hello.client_version != 0x0303:
            print("[error]Wrong protocol version")
            return False

        # get client random
        self.client_random = client_hello.random

        print("[shake]Generate Server random...")
        self.server_random = generate_random()

        print("[shake]Select Cipher Suite from Client Hello...")
        # select default
        self.select_cipher_suite(client_hello.cipher_suites)
        # set command line configuration
        if self.cmd_key_exchange_algorithm is not None:
            self.selected_key_exchange_algorithm = self.cmd_key_exchange_algorithm
        if self.cmd_symmetric_algorithm is not None:
            self.selected_symmetric_algorithm = self.cmd_symmetric_algorithm
        if self.cmd_hash_algorithm is not None:
            self.selected_hash_algorithm = self.cmd_hash_algorithm
        if self.cmd_signature_algorithm is not None:
            self.selected_signature_algorithm = self.cmd_signature_algorithm
        print(f"[shake]Selected key exchange algorithm: {self.selected_key_exchange_algorithm}")
        print(f"[shake]Selected symmetric algorithm: {self.selected_symmetric_algorithm}")
        print(f"[shake]Selected hash algorithm: {self.selected_hash_algorithm}")
        print(f"[shake]Selected signature algorithm: {self.selected_signature_algorithm}")

        print("[shake]Select Compression Method from Client Hello")
        self.select_compression_method(client_hello.compression_methods)
        print(f"[shake]Selected Compression Method: {self.selected_compression_method}")

        # check extensions in client hello
        if client_hello.extensions is not None:
            pass

        print("[shake]Generate Session ID...")
        self.session_id = generate_session_id()
        message = {"SessionID": self.session_id,
                   "SelectedCipherSuite": self.selected_cipher_suite,
                   "SelectedCompressionMethod": self.selected_compression_method,
                   "Random": self.server_random,
                   "Extensions": None
                   }

        print("[shake]Send Server Hello")
        SH = ServerHello(message)
        RL_SH = RecodeLayer(ContentType.HANDSHAKE)
        data = RL_SH.wrap(SH)
        SH.show()

        # send server certificate
        if self.selected_key_exchange_algorithm in [KeyExchangeAlgorithm.RSA,
                                                    KeyExchangeAlgorithm.DHE_RSA, KeyExchangeAlgorithm.DHE_DSS,
                                                    KeyExchangeAlgorithm.ECDHE_RSA, KeyExchangeAlgorithm.ECDHE_DSS]:
            print("[shake]Send Server Certificate")
            # load certificate
            if self.selected_signature_algorithm == SignatureAlgorithm.RSA:
                self.certificates.append(load_certificate("./src/certificate/server_rsa_cert.pem"))
            elif self.selected_signature_algorithm == SignatureAlgorithm.DSA:
                self.certificates.append(load_certificate("./src/certificate/server_dsa_cert.pem"))
            else:
                raise ValueError("Unsupported signature algorithm")
            message = {"CertificateList": self.certificates}
            CT = Certificate(message)
            RL_CT = RecodeLayer(ContentType.HANDSHAKE)
            data += RL_CT.wrap(CT)
            CT.show()

            # ask for client certificate
            self.certificate_request = True
        else:
            self.certificate_request = False

        # DHE and ECDHE key exchange algorithm should send server key exchange
        if self.selected_key_exchange_algorithm in [KeyExchangeAlgorithm.DHE_DSS, KeyExchangeAlgorithm.DHE_RSA,
                                                    KeyExchangeAlgorithm.ECDHE_DSS, KeyExchangeAlgorithm.ECDHE_RSA]:
            print("[shake]Send Server Key Exchange")
            # DHE mode
            if self.selected_key_exchange_algorithm in [KeyExchangeAlgorithm.DHE_RSA, KeyExchangeAlgorithm.DHE_DSS]:
                # generate DHE algorithm parameters
                print("[shake]Select DHE algorithm and generate parameters...")
                self.server_dh_p, \
                self.server_dh_g, \
                self.server_dh_public, \
                self.server_dh_private = generate_dhe_params_and_key()
                print("[shake]Generate DH parameters signature...")
                signature_data = self.client_random + self.client_random + self.server_dh_p + self.server_dh_g + self.server_dh_public

                if self.selected_key_exchange_algorithm == KeyExchangeAlgorithm.DHE_RSA:
                    # sign the parameters with rsa key
                    signature = generate_signature(signature_data, self.selected_signature_algorithm,
                                                   self.selected_hash_algorithm, self.server_rsa_private)
                elif self.selected_key_exchange_algorithm == KeyExchangeAlgorithm.DHE_DSS:
                    # sign the parameters with dss key
                    signature = generate_signature(signature_data, self.selected_signature_algorithm,
                                                   self.selected_hash_algorithm, self.server_dsa_private)
                else:
                    # something wrong
                    signature = None

                message = {"KeyExchangeAlgorithm": self.selected_key_exchange_algorithm,
                           "ServerP": self.server_dh_p,
                           "ServerG": self.server_dh_g,
                           "ServerDHPublicKey": self.server_dh_public,
                           "HashAlgorithm": self.selected_hash_algorithm,
                           "Signature": signature}
            # ECDHE mode
            elif self.selected_key_exchange_algorithm in [KeyExchangeAlgorithm.ECDHE_RSA,
                                                          KeyExchangeAlgorithm.ECDHE_DSS]:
                # generate ECDHE algorithm parameters
                print("[shake]Select ECDHE algorithm and generate parameters...")
                # bytes like
                self.server_ecdhe_public, \
                self.server_ecdhe_private, \
                self.server_curve_name = generate_ecdhe_key_and_param()

                print("[shake]Generate DH parameters signature...")
                signature_data = self.client_random + self.client_random + self.server_ecdhe_public

                if self.selected_key_exchange_algorithm == KeyExchangeAlgorithm.ECDHE_RSA:
                    # sign the parameters with rsa key
                    signature = generate_signature(signature_data, self.selected_signature_algorithm,
                                                   self.selected_hash_algorithm, self.server_rsa_private)
                elif self.selected_key_exchange_algorithm == KeyExchangeAlgorithm.ECDHE_DSS:
                    # sign the parameters with dss key
                    signature = generate_signature(signature_data, self.selected_signature_algorithm,
                                                   self.selected_hash_algorithm, self.server_dsa_private)
                else:
                    # something wrong
                    signature = None

                message = {"KeyExchangeAlgorithm": self.selected_key_exchange_algorithm,
                           "ECCurveType": ECCurveType.name_curve,
                           "NamedCurve": NamedCurve.secp384r1,
                           "ServerECDHEPublicKey": self.server_ecdhe_public,
                           "HashAlgorithm": self.selected_hash_algorithm,
                           "Signature": signature}
            else:
                # unsupported
                # # DH algorithm
                # # load local parameters
                # # weak key exchange algorithm
                # print("[shake]Load local DH parameters...")
                # params = load_dh_params("./src/key/server_dh_params.txt")
                # self.server_dh_p = params[0]
                # self.server_dh_g = params[1]
                # self.server_dh_public, self.server_dh_private = load_key("./src/key/server_dh_public_key.pem", "./src/key/server_dh_private_key.pem")
                # message = {"KeyExchangeAlgorithm": self.selected_key_exchange_algorithm,
                #            "ServerP": self.server_dh_p,
                #            "ServerG": self.server_dh_g,
                #            "ServerDHPublicKey": self.server_dh_public}
                print("[error]Unsupported DH key exchange algorithm")
                return False

            SKE = ServerKeyExchange(message)
            RL_SKE = RecodeLayer(ContentType.HANDSHAKE)
            RL_SKE.set_key_exchange_algorithm(self.selected_key_exchange_algorithm)
            data += RL_SKE.wrap(SKE)
            SKE.show()

        # send CertificateRequest
        if self.certificate_request:
            print("[shake]Send Certificate Request")
            # ask client certificate
            message = {"ClientCertificateType": self.supported_certificate_types,
                       "SignatureAlgorithms": self.supported_cert_signature_algorithms,
                       "HashAlgorithms": self.supported_cert_hash_algorithms,
                       "SignatureAndHashAlgorithms": [],
                       "DistinguishedName": "MyCertificate".encode()}
            CR = CertificateRequest(message)
            RL_CR = RecodeLayer(ContentType.HANDSHAKE)
            data += RL_CR.wrap(CR)
            CR.show()

        # send server hello done
        print("[shake]Send Server Hello Done")
        SD = ServerHelloDone()
        RL_SD = RecodeLayer(ContentType.HANDSHAKE)
        data += RL_SD.wrap(SD)
        SD.show()

        self.handshake_message += data
        print("[shake]Wrap packages...")
        plaintext = TLSPlaintext()
        packages = plaintext.wrap(data, ContentType.HANDSHAKE)
        self.send_tls_packages(packages)

        # receive client data
        recv = self.recv_tls_packages()
        print("[shake]Extract packages...")
        plaintext = TLSPlaintext()
        packages = plaintext.extract(recv)
        for raw in packages:
            RL = RecodeLayer(None)
            Type = RL.extract(raw)
            # receive Certificate
            if isinstance(Type, Certificate):
                print("[shake]Receive Client Certificate")
                Type.show()
                self.client_certificates = Type.certificate_list
                try:
                    key = None
                    for cert in self.client_certificates:
                        print("[shake]Verify Certificate..")
                        key = verify_x509_certificate(cert, self.selected_signature_algorithm)
                        print("[shake]Certificate Verify successfully")
                    # get rsa or dsa public key from certificate
                    if self.selected_signature_algorithm == SignatureAlgorithm.RSA:
                        self.client_rsa_public = key
                    elif self.selected_signature_algorithm == SignatureAlgorithm.DSA:
                        self.client_dsa_public = key
                except:
                    print("[error]Certificate verify fail")
                    return False
                self.handshake_message += raw

            # receive ClientKeyExchange
            elif isinstance(Type, ClientKeyExchange):
                print("[shake]Receive Client Key Exchange")
                Type.show()
                print("[shake]Generate Pre Master Key...")
                # generate pre master secret
                # RSA mode
                if self.selected_key_exchange_algorithm == KeyExchangeAlgorithm.RSA:
                    self.pre_master_secret = rsa_decrypt(self.server_rsa_private, Type.exchange_key)
                # DHE mode
                elif self.selected_key_exchange_algorithm in [KeyExchangeAlgorithm.DHE_DSS,
                                                              KeyExchangeAlgorithm.DHE_RSA]:
                    self.client_dh_public = serialization.load_pem_public_key(Type.exchange_key)
                    if isinstance(self.server_dh_private, bytes):
                        self.server_dh_private = serialization.load_pem_private_key(
                            self.server_dh_private,
                            password=None
                        )
                    self.pre_master_secret = self.server_dh_private.exchange(self.client_dh_public)
                # ECDHE mode
                elif self.selected_key_exchange_algorithm in [KeyExchangeAlgorithm.ECDHE_DSS,
                                                              KeyExchangeAlgorithm.ECDHE_RSA]:
                    self.client_ecdhe_public = serialization.load_pem_public_key(Type.exchange_key)
                    if isinstance(self.server_ecdhe_private, bytes):
                        self.server_ecdhe_private = serialization.load_pem_private_key(
                            self.server_ecdhe_private,
                            password=None
                        )
                    self.pre_master_secret = self.server_ecdhe_private.exchange(ec.ECDH(), self.client_ecdhe_public)
                print(f"[shake]Pre Master Key: {self.pre_master_secret}")
                self.handshake_message += raw

            # receive CertificateVerify
            elif isinstance(Type, CertificateVerify):
                # verify client has this certificate
                print("[shake]Receive Certificate Verify")
                Type.show()
                if Type.certificate_verify is not None:
                    # verify rsa sign data
                    if self.selected_signature_algorithm == SignatureAlgorithm.RSA:
                        try:
                            print(f"[shake]Verify signature...")
                            verify_signature(Type.certificate_verify, self.handshake_message,
                                             self.selected_signature_algorithm, self.selected_hash_algorithm,
                                             self.client_rsa_public)
                            print(f"[shake]Signature verify  successfully")
                        except ValueError:
                            print("[error]CertificateVerify signature verify fail")
                            return False
                    # verify dss sign data
                    elif self.selected_signature_algorithm == SignatureAlgorithm.DSA:
                        try:
                            print(f"[shake]Verify certificate signature...")
                            verify_signature(Type.certificate_verify, self.handshake_message,
                                             self.selected_signature_algorithm, self.selected_hash_algorithm,
                                             self.client_dsa_public)
                            print(f"[shake]Certificate signature verify successfully")
                        except ValueError:
                            print("[error]Certificate  signature verify fail")
                            return False
                self.handshake_message += raw

            # receive Client Finished
            elif isinstance(Type, Finished):
                print("[shake]Receive Client Finished")
                Type.show()
                print("[shake]Generate Master key...")
                self.master_secret = generate_master_secret(self.pre_master_secret, self.client_random,
                                                            self.server_random, self.selected_symmetric_algorithm)
                print(f"[shake]Master key：{self.master_secret}")
                # decrypt and verify with history message
                decrypt_sig = decrypt_with_master_secret(Type.finished, self.master_secret,
                                                         self.selected_symmetric_algorithm)
                if self.selected_signature_algorithm == SignatureAlgorithm.RSA:
                    try:
                        print(f"[shake]Verify Finished data...")
                        verify_signature(decrypt_sig, self.handshake_message, self.selected_signature_algorithm,
                                         self.selected_hash_algorithm, self.client_rsa_public)
                        print(f"[shake]Finished data verify successfully")
                    except ValueError:
                        print("[error]Finished data verify fail")
                        return False
                elif self.selected_signature_algorithm == SignatureAlgorithm.DSA:
                    try:
                        print(f"[shake]Verify Finished data...")
                        verify_signature(decrypt_sig, self.handshake_message, self.selected_signature_algorithm,
                                         self.selected_hash_algorithm, self.client_dsa_public)
                        print(f"[shake]Finished data verify successfully")
                    except ValueError:
                        print("[error]Finished data verify fail")
                        return False
                self.handshake_message += raw

        # send finish
        print("[shake]Send Server Finished")
        # sign history message
        if self.selected_signature_algorithm == SignatureAlgorithm.RSA:
            verify_data = generate_signature(self.handshake_message, self.selected_signature_algorithm,
                                             self.selected_hash_algorithm, self.server_rsa_private)
        elif self.selected_signature_algorithm == SignatureAlgorithm.DSA:
            verify_data = generate_signature(self.handshake_message, self.selected_signature_algorithm,
                                             self.selected_hash_algorithm, self.server_dsa_private)
        else:
            print("[error]Unsupported signing algorithm")
            return False
        # encrypt signature wit master key
        enc = encrypt_with_master_secret(verify_data, self.master_secret, self.selected_symmetric_algorithm)
        message = {"VerifyData": enc}
        F = Finished(message)
        RL_F = RecodeLayer(ContentType.HANDSHAKE)
        data = RL_F.wrap(F)
        F.show()

        print("[shake]Wrap packages...")
        plaintext = TLSPlaintext()
        packages = plaintext.wrap(data, ContentType.HANDSHAKE)
        self.send_tls_packages(packages)

        # send change cipher spec
        print("[change]Send Change Cipher Change Spec")
        CCS = ChangeCipherSpec()
        RL_CCS = RecodeLayer(ContentType.CHANGE_CIPHER_SPEC)
        data = RL_CCS.wrap(CCS)
        plaintext = TLSPlaintext()
        packages = plaintext.wrap(data, ContentType.CHANGE_CIPHER_SPEC)
        self.send_tls_packages(packages)
        self.is_encrypt = True

        # recv change cipher spec
        recv = self.recv_tls_packages()
        print("[shake]Extract packages..")
        plaintext = TLSPlaintext()
        packages = plaintext.extract(recv)
        RL = RecodeLayer(None)
        Type = RL.extract(packages)
        if isinstance(Type, ChangeCipherSpec):
            print("[change]Receive Change Cipher Spec")
            self.is_encrypt = True

        print("[shake]HandShake finished")
        return True

    # 发送加密数据包
    def send_encrypt_package(self, plaintext):
        print("[data]Generate HMAC...")
        # MAC(MAC_write_key，seq_num+fragment.length+fragment)
        sig_data = self.client_random + self.server_random + len(plaintext).to_bytes(2, byteorder="big") + plaintext
        hmac = generate_hmac(self.master_secret, sig_data)

        print("[data]Generate encrypt data...")
        encrypt_data = encrypt_with_master_secret(plaintext + hmac, self.master_secret,
                                                  self.selected_symmetric_algorithm)
        AD = ApplicationData(plaintext, encrypt_data)
        AD.set_hmac(hmac)
        RL_AD = RecodeLayer(ContentType.APPLICATION_DATA)
        data = RL_AD.wrap(AD)
        AD.show()

        print("[data]Wrap packages...")
        ciphertext = TLSCiphertext(ContentType.APPLICATION_DATA)
        packages = ciphertext.wrap(data, ContentType.APPLICATION_DATA)

        self.send_tls_packages(packages)

        return True

    # 接收加密数据包并解密验证
    def recv_encrypt_package(self):
        recv = self.recv_tls_packages()
        print("[data]Extract packages...")
        ciphertext = TLSCiphertext(ContentType.APPLICATION_DATA)
        packages = ciphertext.extract(recv)

        RL = RecodeLayer(None)
        Type = RL.extract(packages)
        if isinstance(Type, ApplicationData):
            print("[data]Receive Application Data")
            plain_text = decrypt_with_master_secret(Type.encrypt_text, self.master_secret,
                                                    self.selected_symmetric_algorithm)
            Type.set_plaintext(plain_text[:len(plain_text) - 32])
            Type.set_hmac(plain_text[-32:])
            Type.show()
            sig_data = self.client_random + self.server_random + len(Type.plain_text).to_bytes(2,
                                                                                               byteorder="big") + Type.plain_text
            try:
                print("[data]Verify HMAC...")
                verify_hmac(self.master_secret, sig_data, Type.hmac)
                print("[data]Verify HMAC successfully")
                return True
            except:
                print("[error]Verify HMAC fail")
                return False

        return False

    # socket发送数据包
    def send_tls_packages(self, package):
        print("[socket]Send packages\n")
        self.connect_socket.send(package)

    # socket接收数据包
    def recv_tls_packages(self):
        while True:
            recv = self.connect_socket.recv(8192)
            if recv:
                print("[socket]Receive packages")
                return recv
            else:
                print("[socket]Close connect")
                return

    def run(self):
        while True:
            # 等待客户端连接
            if not self.is_connect:
                self.connect_socket, self.address = self.socket.accept()
                recv = self.recv_tls_packages()
                print("[shake]Extract packages...")
                plaintext = TLSPlaintext()
                packages = plaintext.extract(recv)
                for raw in packages:
                    RL = RecodeLayer(None)
                    Type = RL.extract(raw)
                    # recv Client Hello
                    if isinstance(Type, ClientHello):
                        print("[shake]Receive Client Hello")
                        print("[shake]HandShake begin")
                        Type.show()
                        self.handshake_message = raw
                        if not self.handshake(Type):
                            print("[error]HandShake Fail")
                            return False
                        else:
                            self.is_connect = True
                            break
            # 接收加密数据
            else:
                if not self.is_encrypt:
                    print("[error]Connect is unsafe")
                    return False
                if self.recv_encrypt_package():
                    print("[socket]Close connect")
                    return True
                else:
                    print("[error]Receive encrypt data fail")
                    return False
