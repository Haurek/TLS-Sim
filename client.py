from protocol.handshake_protocol import *
from protocol.record_protocol import *
from protocol.change_cipher_spec_protocol import *
from protocol.alert_protocol import *
from utils.crypt import *
from utils.util import *


class TLSClient:
    """TLS Client Class"""

    def __init__(self, s, addr):
        # socket
        self.address = addr
        self.socket = s

        # config
        self.client_version = 0x0303
        self.server_version = None

        # session ID
        self.session_id = None

        # default cipher suites
        self.supported_cipher_suites = [CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256]
        # compress method
        # only support Null
        self.supported_compression_methods = [CompressionMethod.NULL]

        # selected cipher suite
        self.selected_cipher_suite = None
        self.selected_compression_method = None
        self.selected_key_exchange_algorithm = None
        self.selected_symmetric_algorithm = None
        self.selected_signature_algorithm = None
        self.selected_hash_algorithm = None

        # command line chose configuration
        self.cmd_key_exchange_algorithm = None
        self.cmd_symmetric_algorithm = None
        self.cmd_hash_algorithm = None
        self.cmd_signature_algorithm = None

        # server key exchange
        # dh
        self.server_dh_p = 0
        self.server_dh_g = 0
        self.server_dh_public = None
        self.client_dh_p = 0
        self.client_dh_g = 0
        # local DH parameters
        # self.client_fixed_dh_public, self.client_fixed_dh_private = load_key("./src/key/client_dh_public_key.pem", "./src/key/client_dh_private_key.pem")
        # DHE parameters
        self.client_dhe_public = None
        self.client_dhe_private = None
        # ECDHE parameters
        self.client_ecdhe_public = None
        self.client_ecdhe_private = None
        self.server_ecdhe_public = None
        self.server_ecdhe_name_curve = None

        # rsa
        self.client_rsa_public, self.client_rsa_private = load_key("./src/key/client_rsa_public_key.pem",
                                                                   "./src/key/client_rsa_private_key.pem")
        self.server_rsa_public = None
        # dsa
        self.client_dsa_public, self.client_dsa_private = load_key("./src/key/client_dsa_public_key.pem",
                                                                   "./src/key/client_dsa_private_key.pem")
        self.server_dsa_public = None

        # random
        self.client_random = None
        self.server_random = None

        # client certificate
        self.selected_certificate = []
        self.server_certificates = None
        self.certificate_request = False

        # certificate request
        self.certificate_authorities = b'MyCertificate'
        # only support rsa and dsa sign certificate
        self.supported_certificate_types = [ClientCertificateType.RSA_SIGN, ClientCertificateType.DSS_SIGN]
        self.supported_cert_signature_algorithms = [SignatureAlgorithm.RSA, SignatureAlgorithm.DSA]
        # only support sha256 hash algorithm
        self.supported_cert_hash_algorithms = [HashAlgorithm.SHA256]
        self.selected_certificate_type = None
        self.selected_cert_signature_algorithm = None
        self.selected_cert_hash_algorithm = None

        # client key exchange
        self.pre_master_secret = None

        # session key
        self.master_secret = None

        # history handshake message
        self.handshake_message = b''

        # client state
        self.is_encrypt = False

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

    # 选择证书类型和签名算法
    def select_certificate_type_and_signature_algorithms(self, certificate_types, signature_hash_algorithms):
        for t in self.supported_certificate_types:
            if t in certificate_types:
                self.selected_certificate_type = t
                break
        if self.selected_certificate_type is None:
            print("[error]No appropriate certificate type")
            return False

        for alg in signature_hash_algorithms:
            if alg & 0xff in self.supported_cert_hash_algorithms and alg >> 8 in self.supported_cert_signature_algorithms:
                self.selected_cert_hash_algorithm = alg & 0xff
                self.selected_cert_signature_algorithm = alg >> 8
                break

        if self.selected_cert_hash_algorithm is None or self.selected_cert_signature_algorithm is None:
            print("[error]No appropriate signature and hash type")
            return False

        return True

    # 根据证书类型选择证书
    def select_certificate(self):
        # only support rsa and dsa type certificate
        if self.selected_signature_algorithm == SignatureAlgorithm.RSA:
            self.selected_certificate.append(load_certificate("./src/certificate/client_rsa_cert.pem"))
        elif self.selected_signature_algorithm == SignatureAlgorithm.DSA:
            self.selected_certificate.append(load_certificate("./src/certificate/client_dsa_cert.pem"))
        else:
            raise ValueError("Unsupported Certificate Type")

    def handshake(self):
        print("[shake]HandShake begin")

        # Generate Client Hello
        print("[shake]Generate Client Random...")
        self.client_random = generate_random()
        message = {"SessionID": None,
                   "CipherSuites": self.supported_cipher_suites,
                   "CompressionMethods": self.supported_compression_methods,
                   "Random": self.client_random,
                   "Extensions": None
                   }
        print("[shake]Send Client Hello")
        CH = ClientHello(message)
        RL_CH = RecodeLayer(ContentType.HANDSHAKE)
        data = RL_CH.wrap(CH)
        CH.show()

        print("[shake]Wrap package...")
        plaintext = TLSPlaintext()
        packages = plaintext.wrap(data, ContentType.HANDSHAKE)
        self.send_tls_packages(packages)

        self.handshake_message += data

        # recv server handshake message
        recv = self.recv_tls_packages()
        print("[shake]Extract packages..")
        plaintext = TLSPlaintext()
        packages = plaintext.extract(recv)
        for raw in packages:
            RL = RecodeLayer(None)
            RL.set_key_exchange_algorithm(self.selected_key_exchange_algorithm)
            Type = RL.extract(raw)
            # receive ServerHello
            if isinstance(Type, ServerHello):
                print("[shake]Receive Server Hello")
                Type.show()

                # get server random
                self.server_version = Type.server_version
                self.server_random = Type.random
                # get session ID
                self.session_id = Type.session_id

                # get selected cipher suite
                self.selected_cipher_suite = Type.cipher_suites
                self.selected_key_exchange_algorithm, \
                self.selected_signature_algorithm, \
                self.selected_symmetric_algorithm, \
                self.selected_hash_algorithm = extract_cipher_suite(self.selected_cipher_suite)

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
                self.selected_compression_method = Type.compression_methods

                self.handshake_message += raw

            # receive server certificate
            elif isinstance(Type, Certificate):
                print("[shake]Receive Server Certificate")
                Type.show()

                self.server_certificates = Type.certificate_list
                # verify certificate
                try:
                    key = None
                    for cert in self.server_certificates:
                        print("[shake]Verify Certificate...")
                        key = verify_x509_certificate(cert, self.selected_signature_algorithm)
                        if not key:
                            print("[error]Certificate verify fail")
                            return False
                        print("[shake]Verify Certificate successfully")
                except:
                    print("[error]Certificate verify fail")
                    return False
                # get server rsa or dsa public key from certificate
                if self.selected_signature_algorithm == SignatureAlgorithm.RSA:
                    self.server_rsa_public = key
                elif self.selected_signature_algorithm == SignatureAlgorithm.DSA:
                    self.server_dsa_public = key

                self.handshake_message += raw
            # receive ServerKeyExchange
            elif isinstance(Type, ServerKeyExchange):
                print("[shake]Receive Server Key Exchange")
                Type.show()
                # DHE
                if self.selected_key_exchange_algorithm in [KeyExchangeAlgorithm.DHE_DSS, KeyExchangeAlgorithm.DHE_RSA]:
                    # get DHE parameters
                    self.server_dh_p = Type.server_DH_p
                    self.server_dh_g = Type.server_DH_g
                    self.server_dh_public = Type.server_DH_pubkey
                    signature = Type.signed_params
                    signature_data = self.client_random + self.client_random + self.server_dh_p + self.server_dh_g + self.server_dh_public
                    self.server_dh_public = serialization.load_pem_public_key(self.server_dh_public)
                # ECDHE
                elif self.selected_key_exchange_algorithm in [KeyExchangeAlgorithm.ECDHE_DSS,
                                                              KeyExchangeAlgorithm.ECDHE_RSA]:
                    # get ECDHE parameters
                    self.server_ecdhe_name_curve = Type.ec_name_curve
                    self.server_ecdhe_public = Type.ec_pubkey
                    signature = Type.signed_params
                    signature_data = self.client_random + self.client_random + self.server_ecdhe_public
                    self.server_ecdhe_public = serialization.load_pem_public_key(self.server_ecdhe_public)
                else:
                    return False

                # verify signature
                # RSA mode
                if self.selected_key_exchange_algorithm == KeyExchangeAlgorithm.DHE_RSA:
                    try:
                        print("[shake]Verify signature..")
                        verify_signature(signature, signature_data, self.selected_signature_algorithm,
                                         self.selected_hash_algorithm, self.server_rsa_public)
                        print(f"[shake]Signature verify successfully")
                    except ValueError:
                        print("[error]Signature verify fail")
                        return False
                # DSS mode
                elif self.selected_key_exchange_algorithm == KeyExchangeAlgorithm.DHE_DSS:
                    try:
                        print("[shake]Verify signature..")
                        verify_signature(signature, signature_data, self.selected_signature_algorithm,
                                         self.selected_hash_algorithm, self.server_dsa_public)
                        print(f"[shake]Signature verify successfully")
                    except ValueError:
                        print("[error]Signature verify fail")
                        return False

                self.handshake_message += raw

            # receive CertificateRequest
            elif isinstance(Type, CertificateRequest):
                print("[shake]Receive Certificate Request")
                Type.show()
                # select certificate type
                print("[shake]Select Certificate Type and Signature and Hash Algorithm")
                if not self.select_certificate_type_and_signature_algorithms(Type.client_certificate_type,
                                                                             Type.signature_hash_algorithm):
                    self.certificate_request = False
                else:
                    self.certificate_request = True
                print(f"[shake]Select Certificate Type: {self.selected_certificate_type}")
                print(f"[shake]Select Certificate Signature Algorithm: {self.selected_cert_signature_algorithm}")
                print(f"[shake]Select Certificate Hash Algorithm: {self.selected_cert_hash_algorithm}")
                # check distinguished name
                if self.certificate_authorities != Type.distinguished_name:
                    print("[error]Unknown authorities")
                    return False

                self.handshake_message += raw
            # receive ServerHelloDone
            elif isinstance(Type, ServerHelloDone):
                print("[shake]Receive Server Hello Done")
                Type.show()
                self.handshake_message += raw

            # unsupported
            elif isinstance(Type, HelloRequest):
                pass
            else:
                print("[error]Unknown HandShake Type")
                return False

        # send client certificate
        data = b''
        if self.certificate_request:
            print("[shake]Send Client Certificate")
            self.select_certificate()
            message = {"CertificateList": self.selected_certificate}
            CT = Certificate(message)
            RL_CT = RecodeLayer(ContentType.HANDSHAKE)
            data += RL_CT.wrap(CT)
            CT.show()

        # generate pre master secret and send ClientKeyExchange
        print("[shake]Send Client Key Exchange")
        print("[shake]Generate Pre Master Key...")
        # RSA mode
        if self.selected_key_exchange_algorithm == KeyExchangeAlgorithm.RSA:
            self.pre_master_secret = 0x0303.to_bytes(2, byteorder='big') + os.urandom(46)
            message = {"ExchangeKey": rsa_encrypt(self.server_rsa_public, self.pre_master_secret)}
        # unsupported DH mode
        # elif self.selected_key_exchange_algorithm in [KeyExchangeAlgorithm.DH_RSA, KeyExchangeAlgorithm.DH_DSS, KeyExchangeAlgorithm.DH_ANON]:
        #     public_key = self.client_fixed_dh_public.public_bytes(
        #         encoding=serialization.Encoding.PEM,
        #         format=serialization.PublicFormat.SubjectPublicKeyInfo
        #     )
        #     message = {"ExchangeKey": public_key}
        #     self.pre_master_secret = self.client_fixed_dh_private.exchange(self.server_dh_public)
        # DHE mode
        elif self.selected_key_exchange_algorithm in [KeyExchangeAlgorithm.DHE_DSS, KeyExchangeAlgorithm.DHE_RSA]:
            p = int.from_bytes(self.server_dh_p, byteorder='big')
            g = int.from_bytes(self.server_dh_g, byteorder='big')
            keys = generate_dhe_key(p, g)
            self.client_dhe_private = keys[1]
            self.client_dhe_public = keys[0]
            self.pre_master_secret = self.client_dhe_private.exchange(self.server_dh_public)
            public_key = self.client_dhe_public.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            message = {"ExchangeKey": public_key}
        # ECDHE mode
        elif self.selected_key_exchange_algorithm in [KeyExchangeAlgorithm.ECDHE_RSA, KeyExchangeAlgorithm.ECDHE_DSS]:
            keys = generate_ecdhe_key()
            self.client_ecdhe_private = keys[1]
            self.client_ecdhe_public = keys[0]
            self.pre_master_secret = self.client_ecdhe_private.exchange(ec.ECDH(), self.server_ecdhe_public)

            public_key = self.client_ecdhe_public.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            message = {"ExchangeKey": public_key}
        else:
            print("[error]Unknown key exchange algorithm")
            return False

        print(f"[shake]Pre Master Key: {self.pre_master_secret}")
        CKE = ClientKeyExchange(message)
        RL_CKE = RecodeLayer(ContentType.HANDSHAKE)
        data += RL_CKE.wrap(CKE)
        CKE.show()

        # send certificate verify
        if self.certificate_request:
            print("[shake]Send Certificate Verify")
            self.handshake_message += data
            if self.selected_signature_algorithm == SignatureAlgorithm.RSA:
                signature = generate_signature(self.handshake_message, self.selected_signature_algorithm,
                                               self.selected_hash_algorithm, self.client_rsa_private)
            elif self.selected_signature_algorithm == SignatureAlgorithm.DSA:
                signature = generate_signature(self.handshake_message, self.selected_signature_algorithm,
                                               self.selected_hash_algorithm, self.client_dsa_private)
            else:
                print("[error]Unsupported signing algorithm")
                return False

            message = {"CertificateVerify": signature}
            CV = CertificateVerify(message)
            RL_CV = RecodeLayer(ContentType.HANDSHAKE)
            CV_data = RL_CV.wrap(CV)
            CV.show()
            data += CV_data
            self.handshake_message += CV_data
        # generate master key
        print("[shake]Generate Master key...")
        self.master_secret = generate_master_secret(self.pre_master_secret, self.client_random, self.server_random,
                                                    self.selected_symmetric_algorithm)
        print(f"[shake]Master Key: {self.master_secret}")

        # send finish
        print("[shake]Send Client Finished")
        if self.selected_signature_algorithm == SignatureAlgorithm.RSA:
            verify_data = generate_signature(self.handshake_message, self.selected_signature_algorithm,
                                             self.selected_hash_algorithm, self.client_rsa_private)
        elif self.selected_signature_algorithm == SignatureAlgorithm.DSA:
            verify_data = generate_signature(self.handshake_message, self.selected_signature_algorithm,
                                             self.selected_hash_algorithm, self.client_dsa_private)
        else:
            print("[error]Unsupported signing algorithm")
            return False
        message = {"VerifyData": encrypt_with_master_secret(verify_data, self.master_secret,
                                                            self.selected_symmetric_algorithm)}
        F = Finished(message)
        RL_F = RecodeLayer(ContentType.HANDSHAKE)
        F_data = RL_F.wrap(F)
        F.show()
        data += F_data
        self.handshake_message += F_data

        print("[shake]Wrap package...")
        plaintext = TLSPlaintext()
        packages = plaintext.wrap(data, ContentType.HANDSHAKE)
        self.send_tls_packages(packages)

        # send change cipher spec
        print("[change]Change Cipher Spec")
        CCS = ChangeCipherSpec()
        RL_CCS = RecodeLayer(ContentType.CHANGE_CIPHER_SPEC)
        data = RL_CCS.wrap(CCS)

        print("[shake]Wrap package...")
        plaintext = TLSPlaintext()
        packages = plaintext.wrap(data, ContentType.CHANGE_CIPHER_SPEC)
        self.send_tls_packages(packages)
        self.is_encrypt = True

        # receive server finished and change cipher spec
        while True:
            recv = self.recv_tls_packages()
            print("[shake]Extract packages..")
            plaintext = TLSPlaintext()
            packages = plaintext.extract(recv)
            for raw in packages:
                RL = RecodeLayer(None)
                Type = RL.extract(raw)
                # receive ChangeCipherSpec
                if isinstance(Type, ChangeCipherSpec):
                    print("[change]Receive Change Cipher Spec")
                    self.is_encrypt = True
                # receive Finished
                if isinstance(Type, Finished):
                    print("[shake]Receive Server Finished")
                    Type.show()
                    decrypt_data = decrypt_with_master_secret(Type.finished, self.master_secret,
                                                              self.selected_symmetric_algorithm)
                    # verify signature
                    if self.selected_signature_algorithm == SignatureAlgorithm.RSA:
                        try:
                            print(f"[shake]Verify Finished signature...")
                            verify_signature(decrypt_data, self.handshake_message, self.selected_signature_algorithm,
                                             self.selected_hash_algorithm, self.server_rsa_public)
                            print(f"[shake]Finished signature verify successfully")
                        except ValueError:
                            print("[error]Finished signature verify fail")
                            return False
                    elif self.selected_signature_algorithm == SignatureAlgorithm.DSA:
                        try:
                            print(f"[shake]Verify data...")
                            verify_signature(decrypt_data, self.handshake_message, self.selected_signature_algorithm,
                                             self.selected_hash_algorithm, self.server_dsa_public)
                            print(f"[shake]Data Verify successfully")
                        except ValueError:
                            print("[error]CertificateVerify signature verify fail")
                            return False
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

    def resume(self):
        pass

    # socket发送数据包
    def send_tls_packages(self, package):
        print("[socket]Send packages\n")
        self.socket.send(package)

    # socket接收数据包
    def recv_tls_packages(self):
        while True:
            recv = self.socket.recv(8192)
            if recv:
                print("[socket]Receive packages")
                return recv

    def connect(self, data):
        # 握手过程
        if not self.handshake():
            print("[error]HandShake Fail")
        # 发送加密数据
        else:
            if self.is_encrypt and not self.send_encrypt_package(data):
                print("[error]Send encrypt data fail")
                return False
            else:
                print("[client]Finish")
                print("[socket]Close connect")
                self.socket.close()
                return True
