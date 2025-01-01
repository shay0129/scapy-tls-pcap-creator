"""
Cryptographic operations module for TLS.
Handles encryption of application data and key logging.
"""

from dataclasses import dataclass
from typing import Tuple
from pathlib import Path
import logging
import os
from cryptography.hazmat.primitives.asymmetric import padding
from scapy.layers.tls.record import TLSApplicationData
from scapy.all import raw

from tls.utils.crypto import encrypt_tls12_record_cbc
from tls.session_state import SessionState
from tls.constants import (
    keys as keys_constants, LoggingPaths
)


class CryptoError(Exception):
    """Base exception for cryptographic operations"""
    pass

class KeyDerivationError(CryptoError):
    """Raised when key derivation fails"""
    pass

class EncryptionError(CryptoError):
    """Raised when encryption fails"""
    pass

class KeyLoggingError(CryptoError):
    """Raised when key logging fails"""
    pass

@dataclass
class KeyBlock:
    """Container for derived keys"""
    client_mac_key: bytes
    server_mac_key: bytes
    client_key: bytes
    server_key: bytes
    client_iv: bytes
    server_iv: bytes

    @classmethod
    def derive(cls, session: SessionState) -> 'KeyBlock':
        """Derive key block from session parameters"""
        try:
            key_length = 2 * (
                keys_constants.SHA256_MAC_LENGTH +  # MAC keys
                keys_constants.AES_128_KEY_LENGTH +  # encryption keys
                16  # IV length for CBC mode
            )
            # Let scapy handle the label and seed combination
            key_block = session.prf.derive_key_block(
                session.master_secret,
                # Let scapy handle the label and seed combination
                session.server_random,
                session.client_random,
                key_length
            )

            return cls(
                client_mac_key=key_block[0:32],
                server_mac_key=key_block[32:64],
                client_key=key_block[64:80],
                server_key=key_block[80:96],
                client_iv=key_block[96:112],
                server_iv=key_block[112:128]
            )

        except Exception as e:
            raise KeyDerivationError(f"Failed to derive key block: {e}")

def get_connection_params(
    session,
    is_request: bool
) -> Tuple[str, str, int, int]:
    """Get connection parameters based on direction"""
    if is_request:
        return (
            session.client_ip,
            session.server_ip,
            session.client_port,
            session.server_port
        )
    return (
        session.server_ip,
        session.client_ip,
        session.server_port,
        session.client_port
    )

def create_tls_record(
    data: bytes,
    key: bytes,
    mac_key: bytes,
    seq_num: int
) -> TLSApplicationData:
    """Create encrypted TLS record"""
    try:
        # Convert sequence number to 8-byte representation
        seq_num_bytes = seq_num.to_bytes(8, byteorder='big')
        
        explicit_iv = os.urandom(keys_constants.IV_LENGTH)
        
        encrypted_data = encrypt_tls12_record_cbc(
            data,
            key,
            explicit_iv,
            mac_key,
            seq_num_bytes  # Pass as bytes
        )
        
        return TLSApplicationData(data=explicit_iv + encrypted_data)
        
    except Exception as e:
        raise EncryptionError(f"Failed to create TLS record: {e}")

def encrypt_and_send_application_data(
    session,
    data: bytes,
    is_request: bool,
    prf,
    master_secret,
    server_random,
    client_random,
    client_ip,
    server_ip,
    client_port,
    server_port,
    tls_context,
    state
) -> bytes:
    """
    Encrypts and sends TLS application data as per RFC 5246.
    """
    try:
        # Determine client/server context
        is_client = is_request
        key_block = KeyBlock.derive(session)
        verify_key_lengths(key_block)
        key = key_block.client_key if is_client else key_block.server_key
        mac_key = key_block.client_mac_key if is_client else key_block.server_mac_key

        # Generate sequence number
        seq_num = state.client_seq_num if is_client else state.server_seq_num
        seq_num_bytes = seq_num.to_bytes(8, byteorder='big')

        # יצירת IV רנדומלי חדש לכל רשומה
        explicit_iv = os.urandom(16)  # תמיד IV חדש!

        # Debug logging
        logging.debug(f"Data type: {type(data)}")
        logging.debug(f"Key type: {type(key)}")
        logging.debug(f"IV type: {type(explicit_iv)}")
        logging.debug(f"MAC key type: {type(mac_key)}")
        logging.debug(f"Sequence number type: {type(seq_num_bytes)}")

        # Encrypt data with the random IV
        encrypted_data = encrypt_tls12_record_cbc(
            data, key, explicit_iv, mac_key, seq_num_bytes
        )

        # Create TLS record with IV
        tls_record = explicit_iv + encrypted_data
        tls_data = TLSApplicationData(data=tls_record)
        tls_context.msg = [tls_data]

        # Update sequence number
        if is_client:
            state.client_seq_num += 1
        else:
            state.server_seq_num += 1

        # Determine source and destination
        src_ip, dst_ip, sport, dport = get_connection_params(session, is_request)

        # Send packet
        raw_packet = session.send_tls_packet(src_ip, dst_ip, sport, dport)

        logging.info(f"TLS Application Data sent from {src_ip}:{sport} to {dst_ip}:{dport}")
        return raw(tls_data)

    except Exception as e:
        logging.error(f"Error in encrypt_and_send_application_data: {e}")
        raise EncryptionError(f"Failed to encrypt and send data: {e}")
    
def handle_ssl_key_log(session) -> bool:
    """Write SSL/TLS session keys to Wireshark keylog file"""
    try:
        # Validate parameters
        if not hasattr(session, 'client_random') or not hasattr(session, 'master_secret'):
            logging.warning("Missing required session parameters for key logging")
            return True
            
        LoggingPaths.SSL_KEYLOG.parent.mkdir(parents=True, exist_ok=True)
        
        client_random_hex = session.client_random.hex()
        master_secret_hex = session.master_secret.hex() if isinstance(session.master_secret, bytes) else session.master_secret
        
        with open(LoggingPaths.SSL_KEYLOG, "w") as f:
            key_line = f"{'client_random'.upper()} {client_random_hex} {master_secret_hex}\n"
            f.write(key_line)
            
        logging.info(f"SSL keys logged to {LoggingPaths.SSL_KEYLOG}")
        return True
        
    except Exception as e:
        logging.error(f"Failed to write SSL keylog: {e}")
        return True  # Non-critical failure

def verify_key_lengths(
    key_block: KeyBlock,
    expected_mac_length: int = keys_constants.SHA256_MAC_LENGTH,
    expected_key_length: int = keys_constants.AES_128_KEY_LENGTH
    ) -> None:
    """Verify key lengths match expectations"""
    
    if len(key_block.server_key) != expected_key_length:
        raise KeyDerivationError(
            f"Invalid server key length: "
            f"got {len(key_block.server_key)}, "
            f"expected {expected_key_length}"
        )

    if len(key_block.server_mac_key) != expected_mac_length:
        raise KeyDerivationError(
            f"Invalid server MAC key length: "
            f"got {len(key_block.server_mac_key)}, "
            f"expected {expected_mac_length}"
        )
    
    if len(key_block.client_mac_key) != expected_mac_length:
        raise KeyDerivationError(
            f"Invalid client MAC key length: "
            f"got {len(key_block.client_mac_key)}, "
            f"expected {expected_mac_length}"
        )
        
    if len(key_block.client_key) != expected_key_length:
        raise KeyDerivationError(
            f"Invalid client key length: "
            f"got {len(key_block.client_key)}, "
            f"expected {expected_key_length}"
        )
    
def verify_key_pair(public_key, private_key):
    # Create test message
    test_data = os.urandom(32)
    # Encrypt with public key
    encrypted = public_key.encrypt(test_data, padding.PKCS1v15())
    # Decrypt with private key
    decrypted = private_key.decrypt(encrypted, padding.PKCS1v15())
    return test_data == decrypted