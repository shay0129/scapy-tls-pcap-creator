# tls_utils.py
import logging
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import datetime
from cryptography.hazmat.primitives import hashes
from cryptography import x509
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from typing import Tuple
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding
from cryptography.hazmat.primitives.padding import PKCS7
import struct
from utils import *
from datetime import datetime, timezone
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
from Crypto.Hash import HMAC, SHA256
from Crypto.Util.Padding import pad

import struct
import logging


def verify_master_secret(client_random, master_secret, log_file) -> bool:
    """Verify the master secret against the log file."""
    
    try:
        with open(log_file, "r") as f:
            log_lines = f.readlines()
    except FileNotFoundError:
        logging.error(f"{log_file} file not found.")
        return False

    if not log_lines:
        logging.error(f"{log_file} file is empty.")
        return False

    for line in log_lines:
        parts = line.strip().split()
        
        if len(parts) != 3 or parts[0] != "CLIENT_RANDOM":
            logging.error(f"Invalid log format: {line.strip()}")
            continue
        
        try:
            logged_client_random = bytes.fromhex(parts[1])
            logged_master_secret = bytes.fromhex(parts[2])
        except ValueError:
            logging.error(f"Error converting hex data in line: {line.strip()}")
            continue

        if compare_to_original(logged_client_random, client_random) and \
           compare_to_original(logged_master_secret, master_secret):
            return True  # Found a match
    
    logging.warning("No matching CLIENT_RANDOM found.")
    return False


def verify_key_pair(private_key, public_key) -> bool:
    """Verify that the public key matches the private key"""
    # Create some data to sign
    message = b"Test message for key verification"
    
    # Sign the data with the private key
    signature = private_key.sign(
        message,
        asymmetric_padding.PSS(
            mgf=asymmetric_padding.MGF1(hashes.SHA256()),
            salt_length=asymmetric_padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    if private_key.key_size != 2048:
        raise ValueError("Server's RSA private key should be 2048 bits for TLS 1.2")
    
    # Verify the signature with the public key
    try:
        public_key.verify(
            signature,
            message,
            asymmetric_padding.PSS(
                mgf=asymmetric_padding.MGF1(hashes.SHA256()),
                salt_length=asymmetric_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        if public_key.key_size != 2048:
            raise ValueError("Server's RSA public key should be 2048 bits for TLS 1.2")
    
        # Verify that the public key in the cert matches the private key
        if compare_to_original(public_key.public_numbers(), private_key.public_key().public_numbers()):
            return True
    except:
        return False


def load_server_cert_keys(cert_path: str, key_path: str) -> Tuple[x509.Certificate, rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    """Load the certificate and private key from files."""
    try:
        # Load private key
        with open(key_path, "rb") as f:
            key_data = f.read()
            try:
                private_key = serialization.load_pem_private_key(
                    key_data,
                    password=None,
                    backend=default_backend()
                )
            except ValueError:
                # If PEM fails, try DER format
                private_key = serialization.load_der_private_key(
                    key_data,
                    password=None,
                    backend=default_backend()
                )

        # Load certificate
        certificate = load_cert(cert_path)

        # Extract public key from the certificate
        public_key = certificate.public_key()

        # Verify that the public key in the cert matches the private key
        if not isinstance(private_key, rsa.RSAPrivateKey) or not isinstance(public_key, rsa.RSAPublicKey):
            raise ValueError("Both private and public keys must be RSA keys")

        if private_key.public_key().public_numbers() != public_key.public_numbers():
            raise ValueError("Public key in certificate does not match the private key")

        # Check key sizes
        if private_key.key_size != 2048 or public_key.key_size != 2048:
            raise ValueError("Both private and public keys should be 2048 bits for TLS 1.2")

        # Check certificate validity
        now = datetime.now(timezone.utc)
        cert_not_before = certificate.not_valid_before.replace(tzinfo=timezone.utc)
        cert_not_after = certificate.not_valid_after.replace(tzinfo=timezone.utc)
        
        if now < cert_not_before or now > cert_not_after:
            raise ValueError(f"Certificate for {cert_path} is not currently valid")

        # Log successful loading
        logging.info(f"Keys and certificate successfully loaded for server: {cert_path}")
        logging.info(f"Certificate subject: {certificate.subject}")
        logging.info(f"Certificate validity: {cert_not_before} to {cert_not_after}")

        return certificate, private_key, public_key

    except FileNotFoundError as e:
        logging.error(f"Key or certificate file not found: {str(e)}")
        raise
    except ValueError as e:
        logging.error(f"Invalid key or certificate: {str(e)}")
        raise
    except Exception as e:
        logging.error(f"Unexpected error loading keys and certificate: {str(e)}")
        raise



def encrypt_tls12_record_cbc(data, key, iv, mac_key, seq_num=b'\x00' * 8):
    """
    Encrypt TLS 1.2 record using AES-128-CBC and HMAC-SHA256 for integrity.

    Args:
        data (bytes): Plaintext data to encrypt.
        key (bytes): AES-128 encryption key (16 bytes).
        iv (bytes): Initialization vector (16 bytes).
        mac_key (bytes): HMAC key (32+ bytes for SHA-256).
        seq_num (bytes): 8-byte sequence number.

    Returns:
        bytes: The complete encrypted TLS 1.2 record (header + ciphertext).
    """
    try:
        # Step 1: Validate input lengths
        assert len(key) == 16, "Key must be 16 bytes for AES-128"
        assert len(iv) == 16, "IV must be 16 bytes"
        assert len(mac_key) >= 32, "MAC key must be at least 32 bytes"
        assert len(seq_num) == 8, "Sequence number must be 8 bytes"

        # Step 2: Record Header Components
        record_type = b'\x17'  # Application Data
        version = b'\x03\x03'  # TLS 1.2
        length = struct.pack('!H', len(data))  # Length of plaintext

        # Step 3: Create HMAC, for Integrity (not needed in aes-gcm)
        mac_input = seq_num + record_type + version + length + data
        logging.debug(f"MAC Input (Header + Data): {mac_input.hex()}")
        mac = HMAC.new(mac_key, mac_input, SHA256).digest()
        logging.debug(f"Generated MAC: {mac.hex()}")

        # Verify size before padding/encryption
        max_tls_record_size = 2**14  # 16 KB
        if len(data) + len(mac) > max_tls_record_size:
            raise ValueError("TLS record exceeds maximum allowed size")

        # Pad plaintext + MAC
        plaintext = data + mac
        padded_plaintext = pad(plaintext, AES.block_size)  # PKCS#7 padding
        logging.debug(f"Padded Plaintext: {padded_plaintext.hex()}")

        # Encrypt with AES-CBC
        cipher = AES.new(key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(padded_plaintext)
        logging.debug(f"Ciphertext: {ciphertext.hex()}")

        # Combine header and ciphertext
        record = record_type + version + length + ciphertext
        logging.debug(f"Final TLS Record: {record.hex()}")

        return record

    except Exception as e:
        logging.error(f"Error in encrypt_tls12_record_cbc: {str(e)}")
        raise



def load_private_key(key_path):
    """Load a private key from a PEM or DER file"""
    try:
        with open(key_path, 'rb') as key_file:
            key_data = key_file.read()
            
            try:
                # First try to load as PEM
                private_key = serialization.load_pem_private_key(
                    key_data,
                    password=None,  # If the key is password protected, provide it here
                    backend=default_backend()
                )
            except ValueError:
                # If PEM fails, try DER format
                private_key = serialization.load_der_private_key(
                    key_data,
                    password=None,
                    backend=default_backend()
                )

            # Verify key type and size
            if not hasattr(private_key, 'key_size'):
                raise ValueError("Loaded key does not appear to be an RSA key")
            
            if private_key.key_size != 2048:
                raise ValueError(f"Expected 2048-bit key, got {private_key.key_size}-bit key")

            logging.info(f"Successfully loaded private key from {key_path}")
            logging.info(f"Key type: {type(private_key).__name__}")
            logging.info(f"Key size: {private_key.key_size} bits")

            return private_key

    except FileNotFoundError:
        logging.error(f"Private key file not found: {key_path}")
        raise
    except (ValueError, TypeError) as e:
        logging.error(f"Invalid private key format: {str(e)}")
        raise
    except Exception as e:
        logging.error(f"Unexpected error loading private key: {str(e)}")
        raise

def load_cert(cert_path):
    """Load a certificate from a PEM or DER file"""
    try:
        with open(cert_path, 'rb') as cert_file:
            cert_data = cert_file.read()
            
            try:
                # First try to load as PEM
                certificate = x509.load_pem_x509_certificate(
                    cert_data,
                    backend=default_backend()
                )
            except ValueError:
                # If PEM fails, try DER format
                certificate = x509.load_der_x509_certificate(
                    cert_data,
                    backend=default_backend()
                )

            logging.info(f"Successfully loaded certificate from {cert_path}")
            logging.info(f"Subject: {certificate.subject}")
            logging.info(f"Issuer: {certificate.issuer}")
            logging.info(f"Valid from: {certificate.not_valid_before}")
            logging.info(f"Valid until: {certificate.not_valid_after}")

            return certificate

    except FileNotFoundError:
        logging.error(f"Certificate file not found: {cert_path}")
        raise
    except ValueError as e:
        logging.error(f"Invalid certificate format: {str(e)}")
        raise
    except Exception as e:
        logging.error(f"Unexpected error loading certificate: {str(e)}")
        raise

def load_certificate_chain(cert_path, intermediate_path=None, root_path=None):
    """Load a complete certificate chain"""
    chain = []
    
    # Load end-entity certificate
    chain.append(load_cert(cert_path))
    
    # Load intermediate certificate if provided
    if intermediate_path:
        chain.append(load_cert(intermediate_path))
    
    # Load root certificate if provided
    if root_path:
        chain.append(load_cert(root_path))
    
    # Verify chain
    for i in range(len(chain)-1):
        if chain[i].issuer != chain[i+1].subject:
            logging.warning(f"Certificate chain broken between {i} and {i+1}")
    
    return chain