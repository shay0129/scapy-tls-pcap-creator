"""
Certificate chain management module.
Handles loading and setup of certificates and master secret generation.
"""

from dataclasses import dataclass
from typing import List
import logging

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa

from tls.utils.crypto import decrypt_pre_master_secret
from tls.utils.cert import load_cert, load_server_cert_keys
from tls.constants import CERTS_DIR
from scapy.layers.tls.crypto.prf import PRF

from tls.certificates.verify import (
    verify_server_public_key,
    verify_server_name,
    verify_certificate_chain
)

class CertificateError(Exception):
    """Base exception for certificate operations"""
    pass

class ChainSetupError(CertificateError):
    """Raised when certificate chain setup fails"""
    pass

class MasterSecretError(CertificateError):
    """Raised when master secret operations fail"""
    pass

@dataclass
class CertificateChain:
    """Container for certificate chain components"""
    ca_cert: x509.Certificate
    server_cert: x509.Certificate
    server_private_key: rsa.RSAPrivateKey
    server_public_key: rsa.RSAPublicKey
    chain: List[x509.Certificate]

from tls.constants import CertificatePaths  # במקום CERTS_DIR

def load_certificate_chain() -> CertificateChain:
    try:
        # Load CA certificate using full path
        ca_cert = load_cert(CertificatePaths.CA_CERT)
        
        # Load server credentials using full paths
        server_cert, server_private_key, server_public_key = load_server_cert_keys(
            cert_path=str(CertificatePaths.SERVER_CERT),
            key_path=str(CertificatePaths.SERVER_KEY)
        )
        
        # Create chain
        chain = [server_cert, ca_cert]
        
        return CertificateChain(
            ca_cert=ca_cert,
            server_cert=server_cert,
            server_private_key=server_private_key,
            server_public_key=server_public_key,
            chain=chain
        )
        
    except Exception as e:
        logging.error(f"Failed to load certificate chain: {e}")
        logging.error(f"CA cert path: {CertificatePaths.CA_CERT}")
        logging.error(f"Server cert path: {CertificatePaths.SERVER_CERT}")
        logging.error(f"Server key path: {CertificatePaths.SERVER_KEY}")
        raise ChainSetupError(f"Failed to load certificate chain: {e}")
    

def verify_chain_validity(
    chain: CertificateChain,
    server_name: str
) -> None:
    """
    Verify the complete certificate chain.
    
    Args:
        chain: Certificate chain to verify
        server_name: Expected server name
        
    Raises:
        ChainSetupError: If verification fails
    """
    try:
        # Verify public key matches certificate
        if not verify_server_public_key(chain.server_cert, chain.server_public_key):
            raise ChainSetupError(
                "Public key mismatch between loaded key and certificate"
            )

        # Verify certificate chain
        if not verify_certificate_chain(chain.chain):
            raise ChainSetupError(
                f"Certificate chain verification failed - "
                f"Server cert issuer: {chain.server_cert.issuer}, "
                f"CA cert subject: {chain.ca_cert.subject}"
            )

        # Verify server name
        if not verify_server_name(chain.server_cert, server_name):
            raise ChainSetupError("Server name verification failed")
            
        logging.info("Certificate chain verification passed")
        
    except Exception as e:
        raise ChainSetupError(f"Chain verification failed: {e}")

def log_chain_info(chain: CertificateChain) -> None:
    """Log certificate chain details"""
    logging.info("Certificate chain loaded successfully")
    logging.info(f"Server cert subject: {chain.server_cert.subject}")
    logging.info(
        f"Server public key modulus (n): "
        f"{chain.server_public_key.public_numbers().n}"
    )
    logging.info(f"CA cert subject: {chain.ca_cert.subject}")

def setup_certificates(session) -> None:
    """
    Setup and verify certificate chain.
    
    Args:
        session: TLS session instance
        
    Raises:
        ChainSetupError: If setup fails
    """
    try:
        # Load certificates
        chain = load_certificate_chain()
        
        # Verify chain
        verify_chain_validity(chain, session.SNI)
        
        # Update session
        session.ca_cert = chain.ca_cert
        session.server_cert = chain.server_cert
        session.server_private_key = chain.server_private_key
        session.server_public_key = chain.server_public_key
        session.cert_chain = chain.chain
        
        # Log success
        log_chain_info(chain)
        
    except Exception as e:
        raise ChainSetupError(f"Certificate setup failed: {e}")

def generate_master_secret(
        session,
        encrypted_pre_master_secret: bytes, 
        client_random: bytes,
        server_random: bytes
    ) -> bytes:
    """
    Generate master secret from pre-master secret as per RFC 5246 (TLS 1.2).
    
    master_secret = PRF(pre_master_secret, "master secret",
                       ClientHello.random + ServerHello.random)[0..47];
    
    Args:
        session: TLS session instance
        encrypted_pre_master_secret: Encrypted pre-master secret
        client_random: Client random bytes
        server_random: Server random bytes
        
    Returns:
        bytes: Generated 48-byte master secret
        
    Raises:
        MasterSecretError: If generation fails
    """
    try:
        # Decrypt pre-master secret
        pre_master_secret = decrypt_pre_master_secret(
            encrypted_pre_master_secret,
            session.server_private_key
        )
        logging.info(f"Decrypted pre_master_secret: {pre_master_secret.hex()}")
        
        # Use scapy's PRF to compute master secret
        # PRF internally uses the correct label "master secret" and handles the seed combination
        master_secret = session.prf.compute_master_secret(
            pre_master_secret, 
            client_random,
            server_random
        )
        
        logging.info(f"Generated master secret: {master_secret.hex()}")
        logging.info(f"Master secret length: {len(master_secret)} bytes")
        
        if len(master_secret) != 48:
            raise MasterSecretError(f"Invalid master secret length: {len(master_secret)}, expected 48")
            
        return master_secret
        
    except Exception as e:
        raise MasterSecretError(f"Master secret generation failed: {e}")
    
    
def handle_master_secret(session) -> None:
    """
    Handle master secret generation and validation.
    
    Args:
        session: TLS session instance
        
    Raises:
        MasterSecretError: If handling fails
    """
    try:
        session.master_secret = generate_master_secret(
            session,
            session.encrypted_pre_master_secret,
            session.client_random,
            session.server_random
        )
        
    except Exception as e:
        raise MasterSecretError(f"Master secret handling failed: {e}")