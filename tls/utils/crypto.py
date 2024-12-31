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



import logging
import struct
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Util.Padding import pad, unpad

def encrypt_tls12_record_cbc(
    data: bytes, 
    key: bytes, 
    iv: bytes, 
    mac_key: bytes, 
    seq_num: bytes = None
) -> bytes:
    """
    Encrypt TLS 1.2 record using AES-128-CBC and HMAC-SHA256 for integrity.
    
    Args:
        data (bytes): Plaintext data to encrypt
        key (bytes): 16-byte encryption key
        iv (bytes): 16-byte initialization vector
        mac_key (bytes): MAC key (at least 32 bytes)
        seq_num (bytes, optional): 8-byte sequence number. Defaults to b'\x00' * 8.
    
    Returns:
        bytes: Fully formatted TLS record
    
    Raises:
        ValueError: If input validation fails
    """
    # Use explicit sequence number or default to zeros
    if seq_num is None:
        seq_num = b'\x00' * 8
    
    try:
        # Extensive input validation
        if not isinstance(data, bytes):
            raise ValueError("Data must be bytes")
        
        if len(key) != 16:
            raise ValueError(f"Key must be 16 bytes, got {len(key)}")
        
        if len(iv) != 16:
            raise ValueError(f"IV must be 16 bytes, got {len(iv)}")
        
        if len(mac_key) < 32:
            raise ValueError(f"MAC key must be at least 32 bytes, got {len(mac_key)}")
        
        if len(seq_num) != 8:
            raise ValueError(f"Sequence number must be 8 bytes, got {len(seq_num)}")
        
        # Logging for debugging
        logging.debug(f"Encrypting record:")
        logging.debug(f"Data length: {len(data)} bytes")
        logging.debug(f"Key: {key.hex()}")
        logging.debug(f"IV: {iv.hex()}")
        logging.debug(f"Seq Num: {seq_num.hex()}")
        
        # Record Header Components
        record_type = b'\x17'  # Application Data
        version = b'\x03\x03'  # TLS 1.2
        
        # Prepare MAC input
        length = struct.pack('!H', len(data))
        mac_input = seq_num + record_type + version + length + data
        
        # Create MAC
        mac = HMAC.new(mac_key, mac_input, SHA256).digest()
        
        # Combine plaintext and MAC
        plaintext = data + mac
        
        # Maximum TLS record size (16 KB)
        max_tls_record_size = 2**14
        if len(plaintext) > max_tls_record_size:
            raise ValueError(f"Record size {len(plaintext)} exceeds max {max_tls_record_size}")
        
        # Pad plaintext
        padded_plaintext = pad(plaintext, AES.block_size)
        
        # Encrypt
        cipher = AES.new(key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(padded_plaintext)
        
        # Construct full record
        record = record_type + version + struct.pack('!H', len(ciphertext)) + ciphertext
        
        logging.debug(f"Encrypted record length: {len(record)} bytes")
        logging.debug(f"Ciphertext length: {len(ciphertext)} bytes")
        
        return record
    
    except Exception as e:
        logging.error(f"Encryption error: {str(e)}")
        raise

def decrypt_tls12_record_cbc(
    record: bytes, 
    key: bytes, 
    iv: bytes, 
    mac_key: bytes, 
    seq_num: bytes = None
) -> bytes:
    """
    Decrypt TLS 1.2 record using AES-128-CBC and HMAC-SHA256 for integrity.
    
    Args:
        record (bytes): Full TLS record to decrypt
        key (bytes): 16-byte decryption key
        iv (bytes): 16-byte initialization vector
        mac_key (bytes): MAC key (at least 32 bytes)
        seq_num (bytes, optional): 8-byte sequence number. Defaults to b'\x00' * 8.
    
    Returns:
        bytes: Decrypted and verified plaintext
    
    Raises:
        ValueError: If decryption or MAC verification fails
    """
    # Use explicit sequence number or default to zeros
    if seq_num is None:
        seq_num = b'\x00' * 8
    
    try:
        # Validate record structure
        if len(record) < 5:
            raise ValueError("Record too short")
        
        # Extract record components
        record_type = record[0:1]
        version = record[1:3]
        length = struct.unpack('!H', record[3:5])[0]
        ciphertext = record[5:]
        
        # Input validations
        if len(key) != 16:
            raise ValueError(f"Key must be 16 bytes, got {len(key)}")
        
        if len(iv) != 16:
            raise ValueError(f"IV must be 16 bytes, got {len(iv)}")
        
        if len(mac_key) < 32:
            raise ValueError(f"MAC key must be at least 32 bytes, got {len(mac_key)}")
        
        if len(seq_num) != 8:
            raise ValueError(f"Sequence number must be 8 bytes, got {len(seq_num)}")
        
        # Decrypt
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_plaintext = cipher.decrypt(ciphertext)
        
        # Unpad
        plaintext = unpad(padded_plaintext, AES.block_size)
        
        # Split plaintext and MAC
        mac_size = 32  # SHA256 MAC size
        data = plaintext[:-mac_size]
        received_mac = plaintext[-mac_size:]
        
        # Verify MAC
        mac_input = seq_num + record_type + version + struct.pack('!H', len(data)) + data
        expected_mac = HMAC.new(mac_key, mac_input, SHA256).digest()
        
        if not hmac_compare(received_mac, expected_mac):
            raise ValueError("MAC verification failed")
        
        return data
    
    except Exception as e:
        logging.error(f"Decryption error: {str(e)}")
        raise

def hmac_compare(a: bytes, b: bytes) -> bool:
    """
    Constant-time comparison of MACs to prevent timing attacks.
    
    Args:
        a (bytes): First MAC
        b (bytes): Second MAC
    
    Returns:
        bool: True if MACs are equal, False otherwise
    """
    if len(a) != len(b):
        return False
    
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    
    return result == 0

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

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