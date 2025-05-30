# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownParameterType=false, reportUnknownArgumentType=false, reportAttributeAccessIssue=false, reportReturnType=false, reportUnusedVariable=false
"""
Server-side TLS handshake functions.
Handles Server Hello, Key Exchange and ChangeCipherSpec messages.
"""
from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
from scapy.layers.tls.crypto.suites import TLS_RSA_WITH_AES_128_CBC_SHA256
from scapy.layers.tls.record import TLSChangeCipherSpec
from scapy.compat import raw
from scapy.layers.tls.handshake import (
    TLSServerHello, TLSCertificate, TLSCertificateRequest,
    TLSServerHelloDone, TLSFinished
)
from scapy.layers.tls.extensions import (
    TLS_Ext_ExtendedMasterSecret, TLS_Ext_EncryptThenMAC,
    TLS_Ext_SignatureAlgorithms
)
from dataclasses import dataclass
from typing import List, Optional, cast
from ..session_state import SessionState
import logging
import os
from scapy.packet import Packet



from ..utils.crypto import (
    compare_to_original,
    decrypt_pre_master_secret,
    encrypt_finished_message
)
from ..constants import TLSVersion
from ..crypto.keys import KeyBlock

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

    def get_extension_list(self) -> List[object]:  # Add type argument
        """Generate list of TLS extensions"""
        extensions: List[object] = []
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
        session: SessionState,
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
    # Generate server random as one piece
    session.server_random = os.urandom(32)
    logging.info(f"Generated server_random: {session.server_random.hex()}")
    gmt_time = int.from_bytes(session.server_random[:4], 'big')
    random_bytes = session.server_random[4:]

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

    # Create and return the ServerHello message
    return cast(TLSServerHello, TLSServerHello(
        version=TLSVersion.TLS_1_2,
        gmt_unix_time=gmt_time,
        random_bytes=random_bytes,
        cipher=TLS_RSA_WITH_AES_128_CBC_SHA256.val, # CipherSuite.id = 60 in decimal
        ext=extensions.get_extension_list() if extensions else None
    ))

def prepare_certificate_chain(session: SessionState) -> TLSCertificate:
    """ Prepare certificate chain for sending. """
    try:
        cert_entries = []
        for cert in session.cert_chain:
            cert_der = cert.public_bytes(serialization.Encoding.DER)
            cert_entries.append((len(cert_der), cert_der))
        
        return cast(TLSCertificate, TLSCertificate(certs=cert_entries))
        
    except Exception as e:
        raise CertificateError(f"Failed to prepare certificate chain: {e}")

def validate_server_key(session: SessionState, certificate: TLSCertificate) -> None:
    """ Validate server public key against certificate """
    if not session.server_public_key or not certificate.certs:
        raise CertificateError("Server public key or certificate chain is missing")
    try:
        server_cert = x509.load_der_x509_certificate(certificate.certs[0][1])
        cert_public_key = server_cert.public_key()
        if cert_public_key.public_numbers() != session.server_public_key.public_numbers():
            raise CertificateError("Server public key does not match certificate")
            
    except Exception as e:
        raise CertificateError(f"Server key validation failed: {e}")

def create_certificate_request(session: SessionState) -> TLSCertificateRequest:
    """Create certificate request message"""
    ca_dn = session.ca_cert.subject.public_bytes()
    return cast(TLSCertificateRequest, TLSCertificateRequest(
        ctypes=[1],  # RSA certificate type
        sig_algs=[0x0401],  # SHA256 + RSA
        certauth=[(len(ca_dn), ca_dn)]
    ))

def send_server_hello(session: SessionState) -> bytes:
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
        session.handshake_messages.extend([
            raw(server_hello),
            raw(certificate),
            raw(cert_request)
        ])
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


def create_server_finished(session: SessionState) -> tuple[Packet, Packet]:
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
        server_verify_data = session.prf.compute_verify_data(
            'server',
            'write',
            b''.join(session.handshake_messages),
            session.master_secret
        )
        signature_data = server_verify_data + b''.join(session.handshake_messages)
        signature = session.server_private_key.sign(
            signature_data,
            asymmetric_padding.PKCS1v15(),
            hashes.SHA256()
        )
        logging.info(f"Generated digital signature: {signature.hex()}")
        change_cipher_spec = TLSChangeCipherSpec()
        server_finished = TLSFinished(vdata=server_verify_data)
        key_block = KeyBlock.derive(session)
        server_finished_encrypted = encrypt_finished_message(
            cast(TLSFinished, server_finished),
            key_block.server_key, 
            key_block.server_iv
        )
        return change_cipher_spec, server_finished_encrypted

    except Exception as e:
        raise ChangeCipherSpecError(f"Failed to create finished messages: {e}")

def send_server_change_cipher_spec(session: SessionState) -> bytes:
    """Send ChangeCipherSpec and Finished messages to client."""
    try:
        # Create messages
        change_cipher_spec, server_finished = create_server_finished(session)

        # Send messages
        session.send_to_client(change_cipher_spec)
        session.send_to_client(server_finished)
        session.handshake_messages.append(raw(server_finished))
        session.handshake_messages.append(raw(change_cipher_spec))
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