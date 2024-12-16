"""
Certificate verification module.
Handles verification of server certificates, public keys, and server names.
"""

from dataclasses import dataclass
from typing import List, Set
from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography import x509
import logging

class VerificationError(Exception):
    """Base exception for verification failures"""
    pass

class PublicKeyError(VerificationError):
    """Raised when public key verification fails"""
    pass

class ChainVerificationError(VerificationError):
    """Raised when certificate chain verification fails"""
    pass

class ServerNameError(VerificationError):
    """Raised when server name verification fails"""
    pass

@dataclass
class PublicKeyInfo:
    """Container for public key information"""
    modulus: int
    exponent: int

    @classmethod
    def from_key(cls, key: rsa.RSAPublicKey) -> 'PublicKeyInfo':
        """Create from RSA public key"""
        numbers = key.public_numbers()
        return cls(modulus=numbers.n, exponent=numbers.e)

    def __eq__(self, other: 'PublicKeyInfo') -> bool:
        return (self.modulus == other.modulus and
                self.exponent == other.exponent)

def get_public_key_info(key: rsa.RSAPublicKey) -> PublicKeyInfo:
    """Extract public key information"""
    try:
        return PublicKeyInfo.from_key(key)
    except Exception as e:
        raise PublicKeyError(f"Failed to extract public key info: {e}")

def log_key_comparison(cert_info: PublicKeyInfo, loaded_info: PublicKeyInfo) -> None:
    """Log public key comparison details"""
    match = cert_info == loaded_info
    level = logging.INFO if match else logging.ERROR
    
    logging.log(level, "Public key comparison results:")
    logging.log(level, f"Certificate modulus (n): {hex(cert_info.modulus)}")
    logging.log(level, f"Loaded key modulus (n): {hex(loaded_info.modulus)}")
    logging.log(level, f"Certificate exponent (e): {hex(cert_info.exponent)}")
    logging.log(level, f"Loaded key exponent (e): {hex(loaded_info.exponent)}")

def verify_server_public_key(
    server_cert: x509.Certificate,
    server_public_key: rsa.RSAPublicKey
) -> bool:
    """
    Verify that the server's public key matches the one in the certificate.
    
    Args:
        server_cert: Server's X.509 certificate
        server_public_key: Server's RSA public key
        
    Returns:
        bool: True if the keys match
        
    Raises:
        PublicKeyError: If verification fails
    """
    try:
        # Validate inputs
        if not server_cert:
            raise PublicKeyError("Server certificate is missing")
        if not server_public_key:
            raise PublicKeyError("Server public key is missing")

        # Extract and compare public keys
        cert_info = get_public_key_info(server_cert.public_key())
        loaded_info = get_public_key_info(server_public_key)
        
        log_key_comparison(cert_info, loaded_info)
        return cert_info == loaded_info

    except Exception as e:
        raise PublicKeyError(f"Public key verification failed: {e}")

def verify_certificate_chain(chain: List[x509.Certificate]) -> bool:
    """
    Verify a certificate chain.
    
    Args:
        chain: List containing server certificate and root CA certificate
        
    Returns:
        bool: True if chain verification succeeds
        
    Raises:
        ChainVerificationError: If verification fails
    """
    try:
        if not chain or len(chain) != 2:
            raise ChainVerificationError(
                f"Invalid chain length: expected 2, got {len(chain) if chain else 0}"
            )

        server_cert, root_ca = chain
        
        # Verify issuer/subject relationship
        if server_cert.issuer != root_ca.subject:
            raise ChainVerificationError(
                f"Server certificate not issued by provided CA\n"
                f"Server cert issuer: {server_cert.issuer}\n"
                f"Root CA subject: {root_ca.subject}"
            )

        # Verify signature
        try:
            root_public_key = root_ca.public_key()
            root_public_key.verify(
                server_cert.signature,
                server_cert.tbs_certificate_bytes,
                asymmetric_padding.PKCS1v15(),
                server_cert.signature_hash_algorithm
            )
            logging.info("Certificate chain verification successful")
            return True
            
        except Exception as e:
            raise ChainVerificationError(f"Signature verification failed: {e}")

    except Exception as e:
        raise ChainVerificationError(f"Chain verification failed: {e}")

def get_certificate_names(cert: x509.Certificate) -> Set[str]:
    """Extract all valid names from certificate"""
    names = set()
    
    # Get Common Name
    for attr in cert.subject:
        if attr.oid == NameOID.COMMON_NAME:
            names.add(attr.value)
            
    # Get Subject Alternative Names
    try:
        san = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
        names.update(san.value.get_values_for_type(x509.DNSName))
    except x509.ExtensionNotFound:
        pass
        
    return names

def verify_server_name(
    server_cert: x509.Certificate,
    server_name: str
) -> bool:
    """
    Verify that the server name matches the certificate names.

    Args:
        server_cert: Server's X.509 certificate
        server_name: Expected server name (e.g., domain name)

    Returns:
        bool: True if the server name matches the certificate

    Raises:
        ServerNameError: If server name verification fails
    """
    try:
        # Extract all valid names (CN and SAN)
        valid_names = get_certificate_names(server_cert)
        
        # Check if the server name is in valid names
        if server_name in valid_names:
            logging.info(f"Server name '{server_name}' verified successfully.")
            return True
        else:
            raise ServerNameError(
                f"Server name '{server_name}' does not match certificate names: {valid_names}"
            )

    except Exception as e:
        raise ServerNameError(f"Server name verification failed: {e}")

