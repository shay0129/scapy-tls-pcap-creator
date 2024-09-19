# crypto.py
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes
import os
from typing import Tuple
import time
import secrets
import hashlib
import hmac


def generate_random() -> Tuple[int, bytes]:
    gmt_unix_time = int(time.time())
    random_bytes = os.urandom(28)
    return gmt_unix_time, random_bytes


def generate_pre_master_secret() -> bytes:
    return b'\x03\x03' + secrets.token_bytes(46)

def P_hash(secret, seed, length):
    """TLS 1.2 P_hash function"""

    result = b""
    A = seed
    while len(result) < length:
        A = hmac.new(secret, A, hashlib.sha256).digest()
        result += hmac.new(secret, A + seed, hashlib.sha256).digest()
    return result[:length]

from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding

def encrypt_pre_master_secret(pre_master_secret: bytes, server_public_key: rsa.RSAPublicKey) -> bytes:
    return server_public_key.encrypt(
        pre_master_secret,
        asymmetric_padding.PKCS1v15()
    )

def decrypt_pre_master_secret(encrypted_pre_master_secret: bytes, server_private_key: rsa.RSAPrivateKey) -> bytes:
    return server_private_key.decrypt(
        encrypted_pre_master_secret,
        asymmetric_padding.PKCS1v15()
    )
