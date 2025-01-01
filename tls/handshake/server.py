"""
Server-side TLS handshake functions.
Handles Server Hello, Key Exchange and ChangeCipherSpec messages.
"""

from dataclasses import dataclass
from typing import List, Optional, Final
import logging
import os

from scapy.layers.tls.handshake import (
    TLSServerHello, TLSCertificate, TLSCertificateRequest,
    TLSServerHelloDone, TLSFinished
)
from scapy.layers.tls.extensions import (
    TLS_Ext_ExtendedMasterSecret, TLS_Ext_EncryptThenMAC,
    TLS_Ext_SignatureAlgorithms
)
from scapy.layers.tls.crypto.suites import TLS_RSA_WITH_AES_128_CBC_SHA256
from scapy.layers.tls.record import TLSChangeCipherSpec
from scapy.all import raw

from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509

from tls.utils.crypto import (
    compare_to_original, generate_random,
    decrypt_pre_master_secret,
    encrypt_finished_message
)
from tls.constants import TLSVersion
from tls.crypto.keys import KeyBlock

class HandshakeError(Exception):
    """Base exception for handshake operations"""
    pass

class ServerHelloError(HandshakeError):
    """Raised when Server Hello fails"""
    pass

class CertificateError(HandshakeError):
    """Raised when certificate operations fail"""
    pass

class ChangeCipherSpecError(HandshakeError):
    """Raised when ChangeCipherSpec fails"""
    pass

@dataclass
class ServerExtensions:
    """Server TLS extensions configuration"""
    signature_algorithms: List[str]
    extended_master_secret: bool = True
    encrypt_then_mac: bool = True

    def get_extension_list(self) -> List:
        """Generate list of TLS extensions"""
        extensions = []
        #TLS_Ext_ServerName(servernames=[ServerName(servername="Pasdaran.local")]), # need fix this extantion
        #TLS_Ext_SupportedGroups(groups=['secp256r1', 'x25519']), # relevant for ECDHE key exchange
        if self.signature_algorithms:
            extensions.append(
                TLS_Ext_SignatureAlgorithms(
                    sig_algs=self.signature_algorithms
                )
            )
        
        if self.extended_master_secret:
            extensions.append(TLS_Ext_ExtendedMasterSecret())
            
        if self.encrypt_then_mac:
            extensions.append(TLS_Ext_EncryptThenMAC())
        
        return extensions

def create_server_hello(
        session,
        extensions: Optional[ServerExtensions] = None
        ) -> TLSServerHello:
    """
    Create Server Hello message.
    
    Args:
        session: TLS session instance
        extensions: Optional server extensions configuration
        
    Returns:
        TLSServerHello: Configured hello message
    """
    # Generate server random
    session.server_GMT_unix_time, session.server_random_bytes = generate_random()
    session.server_random = session.server_GMT_unix_time.to_bytes(4, 'big') + session.server_random_bytes
    logging.info(f"Generated server_random: {session.server_random.hex()}")

    # Use default extensions if none provided
    if not extensions:
        extensions = ServerExtensions(
            signature_algorithms=['sha256+rsaepss']
        )

    # ECDH key exchange
    """ Used public server key, for play with it ECDH key exchange
    
    server_key_exchange = TLSServerKeyExchange(
        params=ServerDHParams(
            dh_p=self.server_public_key.public_numbers().n.to_bytes((self.server_public_key.public_numbers().n.bit_length() + 7) // 8, byteorder='big'),
            dh_g=self.server_public_key.public_numbers().e.to_bytes((self.server_public_key.public_numbers().e.bit_length() + 7) // 8, byteorder='big'),
            dh_Ys=self.server_public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo),
        ),
    )""" 

    return TLSServerHello(
        version=TLSVersion.TLS_1_2,
        gmt_unix_time=session.server_GMT_unix_time,
        random_bytes=session.server_random_bytes,
        sid=os.urandom(32),
        cipher=TLS_RSA_WITH_AES_128_CBC_SHA256.val,
        ext=extensions.get_extension_list()
    )

def prepare_certificate_chain(session) -> TLSCertificate:
    """
    Prepare server certificate chain.
    
    Args:
        session: TLS session instance
        
    Returns:
        TLSCertificate: Certificate message
        
    Raises:
        CertificateError: If certificate preparation fails
    """
    try:
        cert_entries = []
        for cert in session.cert_chain:
            cert_der = cert.public_bytes(serialization.Encoding.DER)
            cert_entries.append((len(cert_der), cert_der))
        
        return TLSCertificate(certs=cert_entries)
        
    except Exception as e:
        raise CertificateError(f"Failed to prepare certificate chain: {e}")

def validate_server_key(session, certificate: TLSCertificate) -> None:
    """
    Validate server public key matches certificate.
    
    Args:
        session: TLS session instance
        certificate: Server certificate message
        
    Raises:
        CertificateError: If validation fails
    """
    try:
        server_cert = x509.load_der_x509_certificate(certificate.certs[0][1])
        cert_public_key = server_cert.public_key()
        
        if cert_public_key.public_numbers() != session.server_public_key.public_numbers():
            raise CertificateError("Server public key does not match certificate")
            
    except Exception as e:
        raise CertificateError(f"Server key validation failed: {e}")

def create_certificate_request(session) -> TLSCertificateRequest:
    """Create certificate request message"""
    ca_dn = session.ca_cert.subject.public_bytes()
    return TLSCertificateRequest(
        ctypes=[1],  # RSA certificate type
        sig_algs=[0x0401],  # SHA256 + RSA
        certauth=[(len(ca_dn), ca_dn)]
    )

def send_server_hello(session) -> bytes:
    """
    Send Server Hello message and associated certificates.
    
    Args:
        session: TLS session instance
        
    Returns:
        bytes: Raw packet data
        
    Raises:
        ServerHelloError: If hello sequence fails
    """
    try:
        # Create messages
        server_hello = create_server_hello(session)
        certificate = prepare_certificate_chain(session)
        validate_server_key(session, certificate)
        cert_request = create_certificate_request(session)
        server_hello_done = TLSServerHelloDone()

        # Send messages
        session.send_to_client(server_hello)
        session.send_to_client(certificate)
        session.send_to_client(cert_request)
        session.send_to_client(server_hello_done)

        # Track handshake messages
        session.handshake_messages.extend([
            raw(server_hello),
            raw(certificate),
            raw(cert_request)
        ])

        # Update TLS context
        session.tls_context.msg = [
            server_hello,
            certificate,
            cert_request,
            server_hello_done
        ]

        return session.send_tls_packet(
            session.server_ip,
            session.client_ip,
            session.server_port,
            session.client_port,
            is_handshake=True
        )

    except Exception as e:
        raise ServerHelloError(f"Server Hello sequence failed: {e}")


def create_server_finished(session) -> tuple[TLSFinished, TLSChangeCipherSpec]:
    """
    Creates Server Finished and ChangeCipherSpec messages.
    
    Args:
        session: TLS session instance
        
    Returns:
        tuple[TLSFinished, TLSChangeCipherSpec]: The finished and change cipher spec messages
        
    Raises:
        ChangeCipherSpecError: If message creation fails
    """
    try:
        # Verify pre-master secret
        decrypted_pre_master_secret = decrypt_pre_master_secret(
            session.encrypted_pre_master_secret,
            session.server_private_key
        )
        
        if not compare_to_original(
            decrypted_pre_master_secret,
            session.pre_master_secret
        ):
            raise ChangeCipherSpecError("Pre-master secret validation failed")
            
        logging.info("Pre-master secret validated successfully")
        logging.debug(f"Decrypted pre-master secret: {decrypted_pre_master_secret.hex()}")

        # Compute verify data
        server_verify_data = session.prf.compute_verify_data(
            'server',
            'write',
            b''.join(session.handshake_messages),
            session.master_secret
        )

        # Generate signature
        signature_data = server_verify_data + b''.join(session.handshake_messages)
        signature = session.server_private_key.sign(
            signature_data,
            asymmetric_padding.PKCS1v15(),
            hashes.SHA256()
        )
        logging.info(f"Generated digital signature: {signature.hex()}")

        # Create messages
        change_cipher_spec = TLSChangeCipherSpec()
        server_finished = TLSFinished(vdata=server_verify_data)

        # Encrypt server finished message using server key
        key_block = KeyBlock.derive(session)
        server_finished_encrypted = encrypt_finished_message(
            server_finished, 
            key_block.server_key, 
            key_block.server_iv
        )
        return change_cipher_spec, server_finished_encrypted

    except Exception as e:
        raise ChangeCipherSpecError(f"Failed to create finished messages: {e}")

def send_server_change_cipher_spec(session) -> bytes:
    """
    Sends Server Finished and ChangeCipherSpec messages.
    
    Args:
        session: TLS session instance
        
    Returns:
        bytes: Raw packet data
        
    Raises:
        ChangeCipherSpecError: If sending messages fails
    """
    try:
        # Create messages
        change_cipher_spec, server_finished = create_server_finished(session)

        # Send messages
        session.send_to_client(change_cipher_spec)
        session.send_to_client(server_finished)
        
        # Update handshake state
        session.handshake_messages.append(raw(server_finished))
        session.handshake_messages.append(raw(change_cipher_spec))
        
        # Update TLS context
        session.tls_context.msg = [change_cipher_spec, server_finished]

        logging.info("Server ChangeCipherSpec and Finished messages sent")
        return session.send_tls_packet(
            session.server_ip,
            session.client_ip,
            session.server_port,
            session.client_port,
            is_handshake=True
        )

    except Exception as e:
        raise ChangeCipherSpecError(f"Failed to send finished messages: {e}")