import hashlib
import os
import struct
import time
from socket import *
from utils.TLS_type import *


# 生成client_random和server_random
def generate_random():
    random_bytes = os.urandom(28)
    timestamp = int(time.time())
    timestamp_bytes = struct.pack(">I", timestamp)
    return timestamp_bytes + random_bytes


# 生成session ID,默认32bytes
def generate_session_id():
    random_bytes = os.urandom(32)
    session_id = hashlib.sha256(random_bytes).digest()
    return session_id


def select_hash(cmd):
    if cmd == "MD5":
        hash = HashAlgorithm.MD5
    elif cmd == "SHA1":
        hash = HashAlgorithm.SHA1
    elif cmd == "SHA224":
        hash = HashAlgorithm.SHA224
    elif cmd == "SHA256":
        hash = HashAlgorithm.SHA256
    elif cmd == "SHA384":
        hash = HashAlgorithm.SHA384
    elif cmd == "SHA512":
        hash = HashAlgorithm.SHA512
    else:
        print("[error]Unsupport hash algorithm")
        hash = None

    return hash


def extract_cipher_suite(t):
    key_exchange, signature, cipher, hash = None, None, None, None
    if t in [0x0001, 0x0002, 0x003b, 0x0004, 0x0005, 0x000a, 0x002f,
             0x0035, 0x003c, 0x003d]:
        key_exchange = KeyExchangeAlgorithm.RSA
    if t in [0x0013, 0x0032, 0x0038, 0x0040, 0x006A]:
        key_exchange = KeyExchangeAlgorithm.DHE_DSS
    if t in [0x16, 0x33, 0x39, 0x67, 0x6B]:
        key_exchange = KeyExchangeAlgorithm.DHE_RSA
    if t in [0xc010, 0xc012, 0xc013, 0xc014, 0xc02f, 0xc030]:
        key_exchange = KeyExchangeAlgorithm.ECDHE_RSA
    if t in [0x0001, 0x0002, 0x003b]:
        cipher = SymmetricAlgorithm.NULL
    if t in [0x0004, 0x0005, 0x0018]:
        cipher = SymmetricAlgorithm.RC4_128
    if t in [0x002f, 0x003c, 0x0030, 0x0031, 0x0032, 0x0033, 0x003E,
             0x003F, 0x0040, 0x0067, 0x0034, 0x006C, 0xC009, 0xC013, 0xC018]:
        cipher = SymmetricAlgorithm.AES_128_CBC
    if t in [0x0035, 0x003d, 0x0036, 0x0037, 0x0038, 0x0039, 0x0068, 0x0069,
             0x006a, 0x006b, 0x003A, 0x006D, 0xC00A, 0xC014, 0xC019]:
        cipher = SymmetricAlgorithm.AES_256_CBC
    if t in [0x000a, 0x000d, 0x0010, 0x0013, 0x0016, 0x001b, 0xC008, 0xC012,
             0xC017]:
        cipher = SymmetricAlgorithm.Triple_DES_EDE_CBC
    if t in [0x0001, 0x0004, 0x0018]:
        hash = HashAlgorithm.MD5
    elif t in [0x003b, 0x003c, 0x003d, 0x003E, 0x003F, 0x0040, 0x0067, 0x0068,
               0x0069, 0x006A, 0x006B, 0x006C, 0x006D, 0xC02B, 0xC02F]:
        hash = HashAlgorithm.SHA256
    else:
        # 其他SHA算法默认为SHA1
        hash = HashAlgorithm.SHA1

    return key_exchange, signature, cipher, hash
