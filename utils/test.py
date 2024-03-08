import datetime
import hmac

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import utils

from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from protocol.handshake_protocol import *
from protocol.record_protocol import *
from protocol.change_cipher_spec_protocol import *
from protocol.alert_protocol import *
from utils.crypt import *
from utils.util import *
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def MyPRF(master_key, client_random, server_random, algorithm):
    if algorithm == SymmetricAlgorithm.RC4_128 or \
            algorithm == SymmetricAlgorithm.AES_128_CBC or \
            algorithm == SymmetricAlgorithm.Triple_DES_EDE_CBC:
        length = 16
    elif algorithm == SymmetricAlgorithm.AES_256_CBC:
        length = 32
    else:
        length = 0

    salt1 = client_random + server_random
    h1 = hmac.HMAC(salt1, hashes.SHA256())
    h1.update(master_key)
    key_hash = h1.finalize()
    output = [b""]
    counter = 1

    while hashes.SHA256.digest_size * (len(output) - 1) < length:
        h = hmac.HMAC(key_hash, hashes.SHA256())
        h.update(output[-1])
        h.update(bytes([counter]))
        output.append(h.finalize())
        counter += 1

    return b"".join(output)[: length]

# 示例用法
if __name__ == "__main__":
    client_random = b'a' * 31
    server_random = b'b' * 32
    master_key = b'c' * 32
    key1 = MyPRF(master_key, client_random, server_random, SymmetricAlgorithm.AES_128_CBC)
    key2 = generate_master_secret(master_key, client_random, server_random, SymmetricAlgorithm.AES_128_CBC)
    print(key2)
    print(key1)
