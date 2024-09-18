# tls_utils.py
import logging
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from scapy.layers.tls.record import TLS, TLSApplicationData
from cryptography.hazmat.primitives import padding
from utils import compute_mac
from cryptography.hazmat.primitives import constant_time
from cryptography.hazmat.primitives import serialization
import datetime
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes
from cryptography import x509
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from typing import Tuple
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding
import os

from utils import *
from datetime import datetime, timezone


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
        if now < certificate.not_valid_before_utc or now > certificate.not_valid_after_utc:
            raise ValueError(f"Certificate for {cert_path} is not currently valid")

        # Log successful loading
        logging.info(f"Keys and certificate successfully loaded for server: {cert_path}")
        logging.info(f"Certificate subject: {certificate.subject}")
        logging.info(f"Certificate validity: {certificate.not_valid_before_utc} to {certificate.not_valid_after_utc}")

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

def generate_session_id():
    """Generate a random session ID"""
    # in this case, we generate a 32-byte random session ID
    # Session Resumption, which is not implemented here, would use a different session ID
    return os.urandom(32)

def encrypt_tls12_record_cbc(data, key, iv, mac_key):
    """Encrypt data using AES-128-CBC and HMAC-SHA256 for integrity."""
    mac = compute_mac(mac_key, data)
    ciphertext = encrypt_data(data + mac, key, iv)
    return iv + ciphertext

def encrypt_data(data: bytes, key: bytes, iv: bytes) -> bytes:
    """Encrypts data using AES-128-CBC and HMAC-SHA256 for integrity."""
    # Padding the data to be block-size aligned (16 bytes for AES)
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()
    
    # AES-128-CBC encryption
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    
    return ciphertext

def decrypt_tls12_record_cbc(encrypted_data, key, mac_key):
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]

    decrypted_with_mac = decrypt_data(ciphertext, key, iv)

    # fork the decrypted data from the MAC
    decrypted = decrypted_with_mac[:-32]
    received_mac = decrypted_with_mac[-32:]

    # MAC verification
    calculated_mac = compute_mac(mac_key, decrypted)
    if not constant_time.bytes_eq(calculated_mac, received_mac):
        raise ValueError("MAC verification failed")

    return decrypted

def decrypt_data(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """Decrypts data using AES-128-CBC."""
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Remove padding
    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    
    return data


