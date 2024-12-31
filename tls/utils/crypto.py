"""
Cryptographic utilities module.
Provides encryption, MAC generation and other cryptographic functions for TLS 1.2.
"""

from cryptography.hazmat.primitives import constant_time, hashes
from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding
from cryptography.hazmat.primitives.asymmetric import rsa
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Util.Padding import pad
import struct
import logging
from typing import Tuple, Optional
import logging
import struct
import hmac
import time
import secrets
import hashlib

from tls.constants import (
    TLSRecord, CryptoConstants,
    GeneralConfig, TLSVersion
)


class CryptoError(Exception):
    """Base exception for cryptographic operations"""
    pass

class EncryptionError(CryptoError):
    """Raised when encryption fails"""
    pass

class ValidationError(CryptoError):
    """Raised when validation fails"""
    pass

def validate_key_size(key: bytes, expected_size: int, name: str) -> None:
    """Validate cryptographic key size"""
    if len(key) != expected_size:
        raise ValidationError(f"{name} must be {expected_size} bytes, got {len(key)}")

def validate_min_key_size(key: bytes, min_size: int, name: str) -> None:
    """Validate minimum cryptographic key size"""
    if len(key) < min_size:
        raise ValidationError(f"{name} must be at least {min_size} bytes, got {len(key)}")

def generate_session_id() -> bytes:
    """
    Generate a cryptographically secure random session ID.
    
    Returns:
        bytes: Random 32-byte session ID
    """
    try:
        return secrets.token_bytes(TLSRecord.SESSION_ID_SIZE)
    except Exception as e:
        raise CryptoError(f"Failed to generate session ID: {e}")

def compare_to_original(post_value: bytes, original_value: bytes) -> bool:
    """
    Compare two values in constant time to prevent timing attacks.
    
    Args:
        post_value: First value to compare
        original_value: Second value to compare
        
    Returns:
        bool: True if values match, False otherwise
    """
    if not post_value or not original_value:
        return False
    try:
        return constant_time.bytes_eq(post_value, original_value)
    except Exception:
        return False

def compute_mac(key: bytes, message: bytes, algorithm: Optional[hashes.HashAlgorithm] = None) -> bytes:
    """
    Compute HMAC for message authentication.
    
    Args:
        key: MAC key
        message: Message to authenticate
        algorithm: Hash algorithm (default: SHA-256)
        
    Returns:
        bytes: MAC value
        
    Raises:
        CryptoError: If MAC computation fails
    """
    try:
        if algorithm is None:
            algorithm = hashes.SHA256()
            
        validate_min_key_size(key, CryptoConstants.MIN_MAC_KEY_SIZE, "MAC key")
        h = hmac.HMAC(key, algorithm)
        h.update(message)
        return h.finalize()
        
    except Exception as e:
        raise CryptoError(f"MAC computation failed: {e}")



def encrypt_tls12_record_cbc(data: bytes, key: bytes, iv: bytes, mac_key: bytes, seq_num: bytes = b'\x00' * 8) -> bytes:
    """
    Encrypt TLS 1.2 record using AES-128-CBC and HMAC-SHA256 for integrity.
    """
    try:
        logging.debug(f"Input lengths: data={len(data)}, key={len(key)}, iv={len(iv)}, mac_key={len(mac_key)}, seq_num={len(seq_num)}")
        logging.debug(f"First 16 bytes of key: {key[:16].hex()}")
        logging.debug(f"IV: {iv.hex()}")
        # Validate input lengths
        assert len(key) == 16, "Key must be 16 bytes for AES-128"
        assert len(iv) == 16, "IV must be 16 bytes"
        assert len(mac_key) >= 32, "MAC key must be at least 32 bytes"
        assert len(seq_num) == 8, "Sequence number must be 8 bytes"

        # Record Header Components
        record_type = b'\x17'  # Application Data
        version = b'\x03\x03'  # TLS 1.2
        length = struct.pack('!H', len(data))  # Length of plaintext

        # Create HMAC for Integrity
        mac_input = seq_num + record_type + version + length + data
        mac = HMAC.new(mac_key, mac_input, SHA256).digest()

        # Verify size before padding/encryption
        max_tls_record_size = 2**14  # 16 KB
        if len(data) + len(mac) > max_tls_record_size:
            raise ValueError("TLS record exceeds maximum allowed size")

        # Pad plaintext + MAC
        plaintext = data + mac
        padded_plaintext = pad(plaintext, AES.block_size)  # PKCS#7 padding

        # Encrypt with AES-CBC
        cipher = AES.new(key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(padded_plaintext)

        # Combine header and ciphertext
        record = record_type + version + struct.pack('!H', len(ciphertext)) + ciphertext

        return record

    except Exception as e:
        logging.error(f"Error in encrypt_tls12_record_cbc: {str(e)}")
        raise

def generate_random() -> Tuple[int, bytes]:
    """
    Generate random data for TLS ClientHello/ServerHello.
    
    Returns:
        Tuple[int, bytes]: (GMT Unix time, 28 random bytes)
    """
    try:
        gmt_unix_time = int(time.time())
        random_bytes = secrets.token_bytes(28)
        return gmt_unix_time, random_bytes
    except Exception as e:
        raise CryptoError(f"Failed to generate random data: {e}")

def generate_pre_master_secret() -> bytes:
    """
    Generate TLS 1.2 pre-master secret.
    
    Returns:
        bytes: 48-byte pre-master secret with TLS version
    """
    try:
        # Convert TLS version to bytes first
        tls_version_bytes = TLSVersion.TLS_1_2.to_bytes(2, byteorder='big')
        
        # Generate 46 random bytes
        random_bytes = secrets.token_bytes(46)
        
        # Combine TLS version bytes with random bytes
        pre_master_secret = tls_version_bytes + random_bytes
        
        return pre_master_secret
    
    except Exception as e:
        raise CryptoError(f"Failed to generate pre-master secret: {e}")

def P_hash(secret: bytes, seed: bytes, length: int) -> bytes:
    """
    TLS 1.2 P_hash function for PRF.
    
    Args:
        secret: Secret key
        seed: Seed value
        length: Desired output length
        
    Returns:
        bytes: Pseudo-random output of specified length
    """
    try:
        result = bytearray()
        A = seed
        
        while len(result) < length:
            A = hmac.new(secret, A, hashlib.sha256).digest()
            result.extend(hmac.new(secret, A + seed, hashlib.sha256).digest())
            
        return bytes(result[:length])
        
    except Exception as e:
        raise CryptoError(f"P_hash computation failed: {e}")

def encrypt_pre_master_secret(
    pre_master_secret: bytes,
    server_public_key: rsa.RSAPublicKey
) -> bytes:
    """
    Encrypt pre-master secret using server's public key.
    
    Args:
        pre_master_secret: Pre-master secret to encrypt
        server_public_key: Server's RSA public key
        
    Returns:
        bytes: Encrypted pre-master secret
    """
    try:
        if len(pre_master_secret) != 48:
            raise ValidationError("Pre-master secret must be 48 bytes")
            
        return server_public_key.encrypt(
            pre_master_secret,
            asymmetric_padding.PKCS1v15()
        )
        
    except Exception as e:
        raise CryptoError(f"Failed to encrypt pre-master secret: {e}")

def decrypt_pre_master_secret(
    encrypted_pre_master_secret: bytes,
    server_private_key: rsa.RSAPrivateKey
) -> bytes:
    """
    Decrypt pre-master secret using server's private key.
    
    Args:
        encrypted_pre_master_secret: Encrypted pre-master secret
        server_private_key: Server's RSA private key
        
    Returns:
        bytes: Decrypted pre-master secret
    """
    try:
        # Decrypt using server's private key
        decrypted = server_private_key.decrypt(
            encrypted_pre_master_secret,
            asymmetric_padding.PKCS1v15()
        )
        
        if len(decrypted) != 48:
            raise ValidationError("Decrypted pre-master secret has invalid length")
        
        # Extract TLS version (first 2 bytes)
        tls_version = int.from_bytes(decrypted[:2], byteorder='big')
        
        # Validate TLS version
        if tls_version != TLSVersion.TLS_1_2:
            raise ValidationError(
                f"Invalid TLS version: expected {hex(TLSVersion.TLS_1_2)}, "
                f"got {hex(tls_version)}"
            )
        
        return decrypted
        
    except Exception as e:
        raise CryptoError(f"Failed to decrypt pre-master secret: {e}")