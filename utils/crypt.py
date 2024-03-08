from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.algorithms import *
from cryptography.hazmat.primitives.asymmetric import padding as cert_padding
from cryptography.hazmat.primitives import padding as algorithm_padding
from cryptography.hazmat.primitives import hashes, hmac
from utils.TLS_type import *
import datetime
import os

# certificate
def generate_x509_certificate(cert_path, private_key, public_key):
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"CN"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Shanghai"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"ShangHai"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"FDU"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"FDU"),
    ])
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        public_key
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now(datetime.timezone.utc)
    ).not_valid_after(
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=10)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
        critical=False,
    ).sign(private_key, hashes.SHA256())

    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    return cert


def load_certificate(path):
    with open(path, "rb") as cert_file:
        cert_data = cert_file.read()

    return cert_data


def verify_x509_certificate(certificate_data, sign_algorithm):
    current_time = datetime.datetime.now()
    certificate = x509.load_pem_x509_certificate(certificate_data, default_backend())
    if current_time < certificate.not_valid_before or current_time > certificate.not_valid_after:
        print("[error]Certificate is expired or not yet valid.")
        return False

    try:
        public_key = certificate.public_key()
        p = cert_padding.PKCS1v15()
        if sign_algorithm == SignatureAlgorithm.RSA:
            public_key.verify(certificate.signature,
                              certificate.tbs_certificate_bytes,
                              p,
                              certificate.signature_hash_algorithm
                              )
        elif sign_algorithm == SignatureAlgorithm.DSA:
            public_key.verify(
                certificate.signature,
                certificate.tbs_certificate_bytes,
                certificate.signature_hash_algorithm
            )
        else:
            raise ValueError("Unsupported signature algorithm")
        return certificate.public_key()
    except Exception as e:
        print("Certificate validation failed:", e)


def generate_dhe_params_and_key():
    parameters = dh.generate_parameters(generator=2, key_size=2048)
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()

    dh_public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    dh_private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    p = parameters.parameter_numbers().p
    g = parameters.parameter_numbers().g
    dh_p_bytes = p.to_bytes(((p.bit_length() + 7) // 8), byteorder="big")
    dh_g_bytes = g.to_bytes(((g.bit_length() + 7) // 8), byteorder="big")
    return dh_p_bytes, dh_g_bytes, dh_public_key_bytes, dh_private_key_bytes


def generate_ecdhe_key():
    private_key = ec.generate_private_key(
        ec.SECP384R1()
    )
    public_key = private_key.public_key()

    return public_key, private_key


def generate_ecdhe_key_and_param():
    private_key = ec.generate_private_key(
        ec.SECP384R1()
    )
    public_key = private_key.public_key()

    parameter = ec.SECP384R1.name

    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return public_key_pem, private_key_pem, parameter


def generate_dhe_key(p, g):
    pn = dh.DHParameterNumbers(p, g)
    parameters = pn.parameters()
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    return public_key, private_key


def generate_signature(data, signing_algorithm, hash_algorithm, private_key):
    if hash_algorithm == HashAlgorithm.SHA256:
        chosen_hash = hashes.SHA256()
    elif hash_algorithm == HashAlgorithm.SHA1:
        chosen_hash = hashes.SHA1()
    elif hash_algorithm == HashAlgorithm.SHA224:
        chosen_hash = hashes.SHA224()
    elif hash_algorithm == HashAlgorithm.SHA384:
        chosen_hash = hashes.SHA384()
    elif hash_algorithm == HashAlgorithm.SHA512:
        chosen_hash = hashes.SHA512()
    elif hash_algorithm == HashAlgorithm.MD5:
        chosen_hash = hashes.MD5()
    else:
        raise ValueError("Unsupported hash algorithm")
    hasher = hashes.Hash(chosen_hash, default_backend())
    hasher.update(data)
    digest = hasher.finalize()

    if signing_algorithm == SignatureAlgorithm.RSA:
        sig = private_key.sign(
            digest,
            cert_padding.PSS(
                mgf=cert_padding.MGF1(hashes.SHA256()),
                salt_length=cert_padding.PSS.MAX_LENGTH
            ),
            utils.Prehashed(chosen_hash)
        )
    elif signing_algorithm == SignatureAlgorithm.DSA:
        sig = private_key.sign(
            digest,
            utils.Prehashed(chosen_hash)
        )
    else:
        raise ValueError("Unsupported signing algorithm")

    return sig


def verify_signature(sig, data, signing_algorithm, hash_algorithm, public_key):
    if hash_algorithm == HashAlgorithm.SHA256:
        chosen_hash = hashes.SHA256()
    elif hash_algorithm == HashAlgorithm.SHA1:
        chosen_hash = hashes.SHA1()
    elif hash_algorithm == HashAlgorithm.SHA224:
        chosen_hash = hashes.SHA224()
    elif hash_algorithm == HashAlgorithm.SHA384:
        chosen_hash = hashes.SHA384()
    elif hash_algorithm == HashAlgorithm.SHA512:
        chosen_hash = hashes.SHA512()
    elif hash_algorithm == HashAlgorithm.MD5:
        chosen_hash = hashes.MD5()
    else:
        print("[error]Unsupported hash algorithm")
        return False
    hasher = hashes.Hash(chosen_hash, default_backend())
    hasher.update(data)
    digest = hasher.finalize()

    if signing_algorithm == SignatureAlgorithm.RSA:
        public_key.verify(
            sig,
            digest,
            cert_padding.PSS(
                mgf=cert_padding.MGF1(hashes.SHA256()),
                salt_length=cert_padding.PSS.MAX_LENGTH
            ),
            utils.Prehashed(chosen_hash)
        )
        return True
    elif signing_algorithm == SignatureAlgorithm.DSA:
        public_key.verify(
            sig,
            digest,
            utils.Prehashed(chosen_hash)
        )
        return True
    else:
        raise ValueError("Unsupported signing algorithm")


def load_key(public_file, private_file):
    with open(private_file, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None
        )

    with open(public_file, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read()
        )

    return public_key, private_key


def generate_master_secret(pre_master_secret, client_random, server_random, algorithm):
    if algorithm == SymmetricAlgorithm.RC4_128 or \
            algorithm == SymmetricAlgorithm.AES_128_CBC or \
            algorithm == SymmetricAlgorithm.Triple_DES_EDE_CBC:
        length = 16
    elif algorithm == SymmetricAlgorithm.AES_256_CBC:
        length = 32
    else:
        length = 0

    h1 = hmac.HMAC(client_random + server_random, hashes.SHA256())
    h1.update(pre_master_secret)
    pre_master_secret_hmac = h1.finalize()
    output = [b""]
    counter = 1

    while hashes.SHA256.digest_size * (len(output) - 1) < length:
        h2 = hmac.HMAC(pre_master_secret_hmac, hashes.SHA256())
        h2.update(output[-1])
        h2.update(bytes(counter))
        output.append(h2.finalize())
        counter += 1

    return b"".join(output)[: length]


def generate_rsa_key(public_path, private_path):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    with open(private_path, "wb") as private_key_file:
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        private_key_file.write(private_key_pem)

    with open(public_path, "wb") as public_key_file:
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        public_key_file.write(public_key_pem)

    return public_key, private_key


def rsa_encrypt(public_key, message):
    ciphertext = public_key.encrypt(
        message,
        cert_padding.OAEP(
            mgf=cert_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext


def rsa_decrypt(private_key, ciphertext):
    plaintext = private_key.decrypt(
        ciphertext,
        cert_padding.OAEP(
            mgf=cert_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext


def generate_dsa_key(public_path, private_path):
    private_key = dsa.generate_private_key(
        key_size=2048
    )
    public_key = private_key.public_key()
    with open(private_path, "wb") as private_key_file:
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        private_key_file.write(private_key_pem)

    with open(public_path, "wb") as public_key_file:
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        public_key_file.write(public_key_pem)

    return public_key, private_key


def encrypt_with_master_secret(data, master_secret, algorithm):
    if algorithm == SymmetricAlgorithm.RC4_128:
        return rc4_128_encrypt(master_secret, data)
    elif algorithm == SymmetricAlgorithm.AES_128_CBC:
        iv = os.urandom(16)
        return aes_128_cbc_encrypt(master_secret, iv, data)
    elif algorithm == SymmetricAlgorithm.AES_256_CBC:
        iv = os.urandom(16)
        return aes_256_cbc_encrypt(master_secret, iv, data)
    elif algorithm == SymmetricAlgorithm.Triple_DES_EDE_CBC:
        iv = os.urandom(8)
        return triple_des_ede_cbc_encrypt(master_secret, iv, data)
    else:
        raise ValueError("Unsupported Symmetric Algorithm")


def decrypt_with_master_secret(encrypted_data, master_secret, algorithm):
    if algorithm == SymmetricAlgorithm.RC4_128:
        return rc4_128_decrypt(master_secret, encrypted_data)
    elif algorithm == SymmetricAlgorithm.AES_128_CBC:
        iv = encrypted_data[:16]
        return aes_128_cbc_decrypt(master_secret, iv, encrypted_data[16:])
    elif algorithm == SymmetricAlgorithm.AES_256_CBC:
        iv = encrypted_data[:16]
        return aes_256_cbc_decrypt(master_secret, iv, encrypted_data[16:])
    elif algorithm == SymmetricAlgorithm.Triple_DES_EDE_CBC:
        iv = encrypted_data[:8]
        return triple_des_ede_cbc_decrypt(master_secret, iv, encrypted_data[8:])
    else:
        raise ValueError("Unsupported Symmetric Algorithm")


# weak
def rc4_128_encrypt(key, plaintext):
    cipher = Cipher(algorithms.ARC4(key), mode=None)
    encryptor = cipher.encryptor()

    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    return ciphertext


def rc4_128_decrypt(key, ciphertext):
    cipher = Cipher(algorithms.ARC4(key), mode=None)
    decryptor = cipher.decryptor()

    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    return plaintext


def aes_128_cbc_encrypt(key, iv, plaintext):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()

    padder = algorithm_padding.PKCS7(128).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()

    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    return iv + ciphertext


def aes_128_cbc_decrypt(key, iv, ciphertext):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()

    decrypted_padded_text = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = algorithm_padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(decrypted_padded_text) + unpadder.finalize()

    return plaintext


def aes_256_cbc_encrypt(key, iv, plaintext):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()

    padder = algorithm_padding.PKCS7(256).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()

    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    return iv + ciphertext


def aes_256_cbc_decrypt(key, iv, ciphertext):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()

    decrypted_padded_text = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = algorithm_padding.PKCS7(256).unpadder()
    plaintext = unpadder.update(decrypted_padded_text) + unpadder.finalize()

    return plaintext


def triple_des_ede_cbc_encrypt(key, iv, plaintext):
    cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()

    padder = algorithm_padding.PKCS7(64).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()

    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    return iv + ciphertext


def triple_des_ede_cbc_decrypt(key, iv, ciphertext):
    cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()

    decrypted_padded_text = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = algorithm_padding.PKCS7(64).unpadder()
    plaintext = unpadder.update(decrypted_padded_text) + unpadder.finalize()

    return plaintext


def generate_hmac(master_secret, data):
    h = hmac.HMAC(master_secret, hashes.SHA256())
    h.update(data)
    signature = h.finalize()
    return signature


def verify_hmac(master_secret, plaintext, signature):
    h = hmac.HMAC(master_secret, hashes.SHA256())
    h.update(plaintext)
    try:
        h.verify(signature)
        return True
    except:
        return False


if __name__ == '__main__':
    s_rsa_pub, s_rsa_pri = generate_rsa_key("../src/key/server_rsa_public_key.pem", "../src/key/server_rsa_private_key.pem")
    s_dsa_pub, s_dsa_pri = generate_dsa_key("../src/key/server_dsa_public_key.pem", "../src/key/server_dsa_private_key.pem")
    c_rsa_pub, c_rsa_pri = generate_rsa_key("../src/key/client_rsa_public_key.pem", "../src/key/client_rsa_private_key.pem")
    c_dsa_pub, c_dsa_pri = generate_dsa_key("../src/key/client_dsa_public_key.pem", "../src/key/client_dsa_private_key.pem")

    # generate_dh_params_and_key("../src/key/server_dh_public_key.pem", "../src/key/server_dh_private_key.pem", "../src/key/server_dh_params.txt")
    # generate_dh_params_and_key("../src/key/client_dh_public_key.pem", "../src/key/client_dh_private_key.pem", "../src/key/client_dh_params.txt")

    cert_name = "../src/certificate/server_rsa_cert.pem"
    cert = generate_x509_certificate(cert_name, s_rsa_pri, s_rsa_pub)

    cert_name = "../src/certificate/server_dsa_cert.pem"
    generate_x509_certificate(cert_name, s_dsa_pri, s_dsa_pub)

    cert_name = "../src/certificate/client_rsa_cert.pem"
    generate_x509_certificate(cert_name, c_rsa_pri, c_rsa_pub)

    cert_name = "../src/certificate/client_dsa_cert.pem"
    generate_x509_certificate(cert_name, c_dsa_pri, c_dsa_pub)
