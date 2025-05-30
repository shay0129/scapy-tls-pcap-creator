"""
Certificate utilities module.
Handles loading and validation of certificates and keys.
"""

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from datetime import datetime, timezone
from typing import Tuple, List, Optional, Union
from pathlib import Path
import logging
from enum import Enum

class CertificateError(Exception):
    """Base exception for certificate operations"""
    pass

class CertificateLoadError(CertificateError):
    """Raised when certificate loading fails"""
    pass

class KeyLoadError(CertificateError):
    """Raised when key loading fails"""
    pass

class ChainValidationError(CertificateError):
    """Raised when certificate chain validation fails"""
    pass

class KeyType(Enum):
    """Supported key types"""
    RSA = "RSA"
    EC = "EC"
    ED25519 = "ED25519"

def validate_cert_path(cert_path: Union[str, Path]) -> Path:
    """Validate and convert certificate path"""
    path = Path(cert_path)
    if not path.exists():
        raise FileNotFoundError(f"Certificate file not found: {path}")
    if not path.is_file():
        raise ValueError(f"Certificate path is not a file: {path}")
    return path

def validate_private_key(private_key: rsa.RSAPrivateKey) -> None:
    """Validate private key type and properties"""
    key_size = private_key.key_size
    if key_size < 2048:
        raise KeyLoadError(f"Key size {key_size} bits is too small - minimum 2048 bits required")

def log_certificate_info(cert: x509.Certificate, path: Path) -> None:
    """Log certificate details"""
    logging.info(f"Successfully loaded certificate from {path}")
    logging.info(f"Subject: {cert.subject}")
    logging.info(f"Issuer: {cert.issuer}")
    logging.info(f"Valid from: {cert.not_valid_before}")
    logging.info(f"Valid until: {cert.not_valid_after}")
    logging.info(f"Serial number: {cert.serial_number}")
    logging.info(f"Key type: {type(cert.public_key()).__name__}")

def log_key_info(private_key: rsa.RSAPrivateKey, path: Path) -> None:
    """Log private key details"""
    logging.info(f"Successfully loaded private key from {path}")
    logging.info(f"Key type: {type(private_key).__name__}")
    logging.info(f"Key size: {private_key.key_size} bits")
    public_key = private_key.public_key()
    logging.info(f"Public exponent: {public_key.public_numbers().e}")

def load_cert(cert_path: Union[str, Path]) -> x509.Certificate:
    """Load a certificate from a PEM or DER file."""
    try:
        path = validate_cert_path(cert_path)
        logging.info(f"Loading certificate from: {path}")
        logging.info(f"File exists: {path.exists()}")
        logging.info(f"File size: {path.stat().st_size} bytes")
        cert_data = path.read_bytes()
        logging.info(f"Read {len(cert_data)} bytes")
        if len(cert_data) > 0:
            logging.info(f"First 100 bytes: {cert_data[:100]}")
            try:
                logging.info(f"File content as text: {cert_data.decode('utf-8')[:200]}")
            except UnicodeDecodeError:
                logging.info("File content is not UTF-8 text (probably DER format)")
        else:
            logging.error("Certificate file is empty!")
        try:
            if b'-----BEGIN CERTIFICATE-----' in cert_data:
                certificate = x509.load_pem_x509_certificate(cert_data)
                logging.info("Successfully loaded as PEM")
            else:
                certificate = x509.load_der_x509_certificate(cert_data)
                logging.info("Successfully loaded as DER")
            return certificate
        except ValueError as e:
            logging.error(f"Failed to load as either PEM or DER: {e}")
            raise CertificateLoadError(f"Invalid certificate format: {e}")
    except Exception as e:
        logging.error(f"Error loading certificate: {str(e)}")
        raise CertificateLoadError(f"Failed to load certificate from {cert_path}: {e}")

def load_private_key(key_path: Union[str, Path], password: Optional[bytes] = None) -> rsa.RSAPrivateKey:
    """
    Load a private key from a PEM or DER file.
    
    Args:
        key_path: Path to private key file
        password: Optional password for encrypted keys
        
    Returns:
        rsa.RSAPrivateKey: Loaded private key
        
    Raises:
        KeyLoadError: If loading fails
    """
    try:
        path = Path(key_path)
        if not path.exists():
            raise FileNotFoundError(f"Key file not found: {path}")
        key_data = path.read_bytes()
        private_key = None
        try:
            private_key = serialization.load_pem_private_key(
                key_data,
                password=password,
                backend=default_backend()
            )
        except ValueError:
            try:
                private_key = serialization.load_der_private_key(
                    key_data,
                    password=password,
                    backend=default_backend()
                )
            except ValueError as e:
                raise KeyLoadError(f"Invalid key format: {e}")
        if not isinstance(private_key, rsa.RSAPrivateKey):
            raise KeyLoadError("Key must be an RSA private key")
        validate_private_key(private_key)
        log_key_info(private_key, path)
        return private_key
    except Exception as e:
        raise KeyLoadError(f"Failed to load private key: {e}")

def load_server_cert_keys(
    cert_path: Union[str, Path],
    key_path: Union[str, Path],
    key_password: Optional[bytes] = None
) -> Tuple[x509.Certificate, rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    """
    Load and validate server certificate and keys.
    
    Args:
        cert_path: Path to certificate file
        key_path: Path to private key file
        key_password: Optional password for encrypted keys
        
    Returns:
        Tuple containing certificate, private key and public key
        
    Raises:
        CertificateError: If validation fails
    """
    try:
        certificate = load_cert(cert_path)
        private_key = load_private_key(key_path, key_password)
        public_key = certificate.public_key()
        if not isinstance(public_key, rsa.RSAPublicKey):
            raise CertificateError("Certificate must contain an RSA public key")
        verify_key_pair(private_key, public_key)
        verify_cert_validity(certificate, cert_path)
        logging.info("Certificate and keys loaded and validated successfully")
        return certificate, private_key, public_key
    except Exception as e:
        raise CertificateError(f"Error loading server certificate and keys: {e}")

def verify_key_pair(private_key: rsa.RSAPrivateKey, public_key: rsa.RSAPublicKey) -> None:
    """Verify public key matches private key"""
    if private_key.public_key().public_numbers() != public_key.public_numbers():
        raise CertificateError("Public key in certificate does not match private key")

def verify_cert_validity(cert: x509.Certificate, cert_path: Union[str, Path]) -> None:
    """Verify certificate is currently valid"""
    now = datetime.now(timezone.utc)
    if now < cert.not_valid_before.replace(tzinfo=timezone.utc) or \
       now > cert.not_valid_after.replace(tzinfo=timezone.utc):
        raise CertificateError(f"Certificate {cert_path} is not currently valid")

def load_certificate_chain(
    cert_path: Union[str, Path],
    intermediate_path: Optional[Union[str, Path]] = None,
    root_path: Optional[Union[str, Path]] = None
) -> List[x509.Certificate]:
    """
    Load and verify a certificate chain.
    
    Args:
        cert_path: Path to end-entity certificate
        intermediate_path: Optional path to intermediate certificate
        root_path: Optional path to root certificate
        
    Returns:
        List[x509.Certificate]: Certificate chain
        
    Raises:
        ChainValidationError: If chain validation fails
    """
    try:
        chain: List[x509.Certificate] = []
        chain.append(load_cert(cert_path))
        if intermediate_path:
            chain.append(load_cert(intermediate_path))
        if root_path:
            chain.append(load_cert(root_path))
        verify_certificate_chain(chain)
        return chain
    except Exception as e:
        raise ChainValidationError(f"Error loading certificate chain: {e}")

def verify_certificate_chain(chain: List[x509.Certificate]) -> None:
    """Verify certificate chain is valid"""
    if not chain:
        raise ChainValidationError("Empty certificate chain")
    for i in range(len(chain)-1):
        if chain[i].issuer != chain[i+1].subject:
            raise ChainValidationError(
                f"Certificate chain broken between certificates {i} and {i+1}: "
                f"Issuer {chain[i].issuer} does not match subject {chain[i+1].subject}"
            )
        try:
            chain[i].verify_directly_issued_by(chain[i+1])
        except Exception as e:
            raise ChainValidationError(
                f"Certificate {i} not properly signed by certificate {i+1}: {e}"
            )