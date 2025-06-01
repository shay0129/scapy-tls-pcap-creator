# pyright: reportUnknownVariableType=false, reportUnknownMemberType=false, reportUnknownParameterType=false, reportUnknownArgumentType=false, reportMissingParameterType=false, reportMissingTypeArgument=false, reportReturnType=false, reportAttributeAccessIssue=false
"""
TLS Session module.
Handles unified TLS session management for both client and server sides.
"""
from scapy.layers.tls.crypto.prf import PRF
from scapy.layers.tls.record import TLS
from scapy.layers.inet import IP
from scapy.compat import raw
from scapy.packet import Raw, Packet
from typing import Optional, Any, List, Tuple, Protocol
import logging
from pathlib import Path

from .exceptions import TLSSessionError, HandshakeError, CertificateError
from .crypto.keys import verify_key_pair, handle_master_secret
from .constants import TLSVersion, GeneralConfig, NetworkPorts
from .crypto import (
    encrypt_and_send_application_data,
    handle_ssl_key_log
)
from .session_state import SessionState
from .handshake.client import (
    send_client_hello,
    send_client_handshake_messages,
    send_client_change_cipher_spec
)
from .handshake.server import (
    send_server_hello,
    send_server_change_cipher_spec
)
from .certificates.chain import (
    setup_certificates
)

class PcapWriterProtocol(Protocol):
    packets: List[Any]

class UnifiedTLSSession:
    """Unified TLS session handler for client and server sides."""

    pcap_writer: PcapWriterProtocol
    client_ip: str
    server_ip: str
    client_port: int
    server_port: int
    use_tls: bool
    use_client_cert: bool
    tls_context: TLS
    sni: str  # Use lowercase to avoid constant redefinition
    prf: PRF
    state: SessionState
    handshake_messages: List[Any]
    server_public_key: Optional[Any]
    server_private_key: Optional[Any]
    master_secret: Optional[bytes]
    server_random: Optional[bytes]
    client_random: Optional[bytes]
    cert_chain: list
    ca_cert: Optional[Any]  # Add ca_cert attribute

    def __init__(
        self,
        pcap_writer: PcapWriterProtocol,
        client_ip: str,
        server_ip: str,
        client_port: int,
        server_port: int,
        use_tls: bool = True,
        use_client_cert: bool = False
    ) -> None:
        """Initialize TLS session."""
        self._initialize_network(pcap_writer, client_ip, server_ip, client_port, server_port)
        self._initialize_tls(use_tls, use_client_cert)
        self.state = SessionState()
        self.handshake_messages = self.state.handshake_messages
        self.server_public_key = None
        self.server_private_key = None
        self.master_secret = None
        self.server_random = None
        self.client_random = None
        self.cert_chain = self.state.cert_chain
        self.ca_cert = None  # Initialize ca_cert
        self.state.prf = self.prf  # Ensure SessionState has a prf attribute
        self.state.server_random = self.server_random  # Ensure SessionState has server_random
        self.state.client_random = self.client_random  # Ensure SessionState has client_random
        self.state.client_ip = self.client_ip  # Ensure SessionState has client_ip
        self.state.server_ip = self.server_ip  # Ensure SessionState has server_ip
        self.state.client_port = self.client_port  # Ensure SessionState has client_port
        self.state.server_port = self.server_port  # Ensure SessionState has server_port
        self.state.send_tls_packet = self.send_tls_packet  # Allow state to send TLS packets
        # Ensure server public key is loaded for server handshake
        if not self.server_public_key:
            try:
                from .utils.cert import load_cert
                from .constants import CERTS_DIR
                server_cert_path = CERTS_DIR / "server.crt"
                cert = load_cert(server_cert_path)
                self.server_public_key = cert.public_key()
                # Optionally, add the cert to the cert_chain if not present
                if not self.cert_chain:
                    self.cert_chain.append(cert)
            except Exception as e:
                logging.error(f"Failed to load server public key: {e}")
        # Load CA certificate
        try:
            from .utils.cert import load_cert
            from .constants import CertificatePaths
            self.ca_cert = load_cert(CertificatePaths.CA_CERT)
        except Exception as e:
            logging.error(f"Failed to load CA certificate: {e}")
        # Load server private key
        self.server_private_key = None
        try:
            from .utils.cert import load_private_key
            from .constants import CertificatePaths
            self.server_private_key = load_private_key(CertificatePaths.SERVER_KEY)
            if self.server_private_key is None:
                raise ValueError("Server private key could not be loaded from SERVER_KEY path.")
        except Exception as e:
            logging.error(f"Failed to load server private key: {e}")
            raise CertificateError(f"Server private key is required for handshake but could not be loaded: {e}")
        # Ensure state.sni is always set to match session.sni for handshake and verification
        self.state.sni = self.sni
        self._setup_certificates()

    def _initialize_network(
        self,
        pcap_writer: PcapWriterProtocol,
        client_ip: str,
        server_ip: str,
        client_port: int,
        server_port: int
    ) -> None:
        """Initialize network parameters"""
        self.pcap_writer = pcap_writer
        self.client_ip = client_ip
        self.server_ip = server_ip
        self.client_port = client_port
        self.server_port = server_port

    def _initialize_tls(self, use_tls: bool, use_client_cert: bool) -> None:
        """Initialize TLS parameters"""
        self.use_tls = use_tls
        self.use_client_cert = use_client_cert
        self.tls_context = TLS(version=TLSVersion.TLS_1_2)
        self.sni = GeneralConfig.DEFAULT_SNI  # Use lowercase to avoid constant redefinition
        # Initialize PRF for TLS 1.2
        self.prf = PRF(hash_name='SHA256', tls_version=TLSVersion.TLS_1_2)

    def _setup_certificates(self) -> None:
        """Setup certificate chain"""
        try:
            setup_certificates(self.state)
        except Exception as e:
            raise CertificateError(f"Certificate setup failed: {e}")

    def perform_handshake(self) -> bool:
        """Perform TLS handshake sequence."""
        handshake_steps: List[Tuple[Any, Tuple[Any, ...], str, str]] = [
            (send_client_hello, (self,),
             "Failed to send Client Hello", "Client Hello sent successfully"),
            (send_server_hello, (self,),
             "Failed to receive Server Hello", "Server Hello received successfully"),
            (send_client_handshake_messages, (self,),
             "Failed to send Client Handshake Messages", "Client handshake messages sent successfully"),
            (verify_key_pair, (self.server_public_key, self.server_private_key),
             "Server key pair verification failed", "Server key pair verified successfully"),
            (handle_master_secret, (self,),
             "Failed to handle Master Secret", "Master Secret handled successfully"),
            (send_client_change_cipher_spec, (self,),
             "Failed to send Client Change Cipher Spec", "Client Change Cipher Spec sent successfully"),
            (send_server_change_cipher_spec, (self,),
             "Failed to receive Server Change Cipher Spec", "Server Change Cipher Spec received successfully"),
            (handle_ssl_key_log, (self,),
             "Failed to handle SSL Key Log", "SSL Key Log handled successfully"),
        ]
        try:
            logging.info("Starting TLS Handshake...")
            for func, args, error_msg, success_msg in handshake_steps:
                if not func(*args):
                    raise HandshakeError(error_msg)
                logging.info(success_msg)
            self.state.handshake_completed = True
            logging.info("TLS Handshake completed successfully")
            return True
        except HandshakeError as e:
            logging.error(f"TLS Handshake failed: {e}")
            self.state.handshake_completed = False
            return False
        except AttributeError as e:
            logging.error(f"TLS Handshake failed due to missing attribute: {e}")
            import traceback
            traceback.print_exc()
            self.state.handshake_completed = False
            return False
        except Exception as e:
            logging.error(f"Unexpected error during TLS Handshake: {e}")
            import traceback
            traceback.print_exc()
            self.state.handshake_completed = False
            return False

    def handle_network_packet(self, packet: Packet) -> None:
        """Handle incoming network packet and process TLS data if applicable"""
        if Raw in packet and self.state.handshake_completed:
            try:
                # is_client = self.determine_packet_direction(packet)  # Unused variable removed
                if self.state.key_block is not None:
                    decrypted_data = self.state.process_received_tls_packet(
                        packet,
                        key_block=self.state.key_block
                    )
                    self.process_decrypted_payload(decrypted_data)
            except ValueError as e:
                logging.error(f"TLS packet processing failed: {e}")
        else:
            pass

    def determine_packet_direction(self, packet: Packet) -> bool:
        """Determine if the packet is from client or server"""
        src_ip: str = packet[IP].src
        return src_ip == self.client_ip

    def process_decrypted_payload(self, decrypted_data: bytes) -> None:
        """Process the decrypted payload"""
        logging.info(f"Decrypted data: {decrypted_data}")

    def run_session(
        self,
        request_data: bytes,
        response_data: bytes,
        file_to_send: Optional[str] = None
    ) -> None:
        try:
            if self.use_tls:
                logging.info("Starting TLS session")
                self.server_port = NetworkPorts.HTTPS
                if not self.perform_handshake():
                    raise TLSSessionError("Handshake failed")
                if file_to_send:
                    if not Path(file_to_send).exists():
                        logging.error(f"File not found: {file_to_send}")
                    else:
                        logging.info(f"Found file to send: {file_to_send}")
                self._handle_data_exchange(request_data, response_data, file_to_send)
            else:
                logging.info("Starting unencrypted session")
                self.server_port = NetworkPorts.HTTP
                self._handle_data_exchange(request_data, response_data, None)
        except Exception as e:
            raise TLSSessionError(f"Session failed: {e}")

    def _handle_data_exchange(
        self,
        request_data: bytes,
        response_data: bytes,
        file_to_send: Optional[str]
    ) -> None:
        logging.info(f"Handshake completed: {self.state.handshake_completed}")
        logging.info(f"Use client cert: {self.use_client_cert}")
        logging.info(f"File to send: {file_to_send}")
        if self.state.handshake_completed and self.use_client_cert:
            logging.info("Using encrypted exchange")
            self._handle_encrypted_exchange(request_data, response_data, file_to_send)
        else:
            logging.info("Using unencrypted exchange")
            self._handle_unencrypted_exchange(request_data, response_data)

    def _handle_encrypted_exchange(
        self,
        request_data: bytes,
        response_data: bytes,
        file_to_send: Optional[str]
    ) -> None:
        # Ensure state has up-to-date randoms before encryption
        self.state.server_random = self.server_random
        self.state.client_random = self.client_random
        try:
            if self.master_secret is None or self.server_random is None or self.client_random is None:
                raise TLSSessionError("Missing master_secret, server_random, or client_random for encryption.")
            logging.info("Sending encrypted request data")
            encrypt_and_send_application_data(
                self.state, request_data, is_request=True,
                prf=self.prf, master_secret=self.master_secret,
                server_random=self.server_random, client_random=self.client_random,
                client_ip=self.client_ip, server_ip=self.server_ip,
                client_port=self.client_port, server_port=self.server_port,
                tls_context=self.tls_context, state=self.state
            )
            logging.info("Sending encrypted response data")
            encrypt_and_send_application_data(
                self.state, response_data, is_request=False,
                prf=self.prf, master_secret=self.master_secret,
                server_random=self.server_random, client_random=self.client_random,
                client_ip=self.client_ip, server_ip=self.server_ip,
                client_port=self.client_port, server_port=self.server_port,
                tls_context=self.tls_context, state=self.state
            )
            if file_to_send:
                logging.info(f"Attempting to send file: {file_to_send}")
                self._send_file(file_to_send)
                logging.info("File sent successfully")
        except Exception as e:
            logging.error(f"Encrypted exchange failed: {e}")
            raise TLSSessionError(f"Encrypted exchange failed: {e}")

    def _send_file(self, file_path: str) -> None:
        """Send file over encrypted connection"""
        # Ensure state has up-to-date randoms before encryption
        self.state.server_random = self.server_random
        self.state.client_random = self.client_random
        try:
            if self.master_secret is None or self.server_random is None or self.client_random is None:
                raise TLSSessionError("Missing master_secret, server_random, or client_random for encryption.")
            logging.info(f"Opening file: {file_path}")
            if not Path(file_path).exists():
                logging.error(f"File not found: {file_path}")
                raise FileNotFoundError(f"File not found: {file_path}")
            with open(file_path, 'rb') as file:
                file_data = file.read()
                logging.info(f"Read {len(file_data)} bytes from file")
                encrypt_and_send_application_data(
                    self.state, file_data, is_request=False,
                    prf=self.prf, master_secret=self.master_secret,
                    server_random=self.server_random, client_random=self.client_random,
                    client_ip=self.client_ip, server_ip=self.server_ip,
                    client_port=self.client_port, server_port=self.server_port,
                    tls_context=self.tls_context, state=self.state
                )
                logging.info("File sent successfully")
        except Exception as e:
            logging.error(f"File send failed: {e}")
            raise TLSSessionError(f"File send failed: {e}")

    def _handle_unencrypted_exchange(
        self,
        request_data: bytes,
        response_data: bytes
    ) -> None:
        try:
            self._send_unencrypted_data(request_data, is_request=True)
            self._send_unencrypted_data(response_data, is_request=False)
            logging.warning("Using unencrypted communication")
        except Exception as e:
            raise TLSSessionError(f"Unencrypted exchange failed: {e}")

    def _send_unencrypted_data(self, data: bytes, is_request: bool) -> None:
        try:
            src_ip = self.client_ip if is_request else self.server_ip
            dst_ip = self.server_ip if is_request else self.client_ip
            sport = self.client_port if is_request else NetworkPorts.HTTP
            dport = NetworkPorts.HTTP if is_request else self.client_port
            packet = self.state.create_tcp_packet(
                src_ip=src_ip,
                dst_ip=dst_ip,
                sport=sport,
                dport=dport,
                payload=data,
                flags="PA"
            )
            self.pcap_writer.packets.append(packet)
            logging.info(f"Added {'request' if is_request else 'response'} packet")
        except Exception as e:
            logging.error(f"Failed to send unencrypted data: {e}")

    def _process_http_data(self, data: bytes, is_request: bool) -> bytes:
        """Process HTTP data, ensuring correct headers and content length"""
        data_str = data.decode('utf-8', errors='ignore')
        if not is_request:
            if data_str.startswith('HTTP/'):
                return data
            body_length = len(data_str.encode('utf-8'))
            processed_data = f"HTTP/1.1 400 Bad Request\r\nContent-Length: {body_length}\r\n\r\n{data_str}"
            return processed_data.encode('utf-8')
        return data

    def _get_connection_params(self, is_request: bool) -> Tuple[str, str, int, int]:
        """Get connection parameters based on request/response"""
        src_ip = self.client_ip if is_request else self.server_ip
        dst_ip = self.server_ip if is_request else self.client_ip
        sport = self.client_port if is_request else self.server_port
        dport = self.server_port if is_request else self.client_port
        return src_ip, dst_ip, sport, dport

    def send_tls_packet(
        self,
        src_ip: str,
        dst_ip: str,
        sport: int,
        dport: int,
        is_handshake: bool = False
    ) -> IP:
        """Send TLS packet with sequence tracking"""
        try:
            tls_data = raw(self.tls_context)
            is_client = (src_ip == self.client_ip)
            packet, tls_seq = self.state.create_tls_packet(
                src_ip=src_ip,
                dst_ip=dst_ip,
                sport=sport,
                dport=dport,
                tls_data=tls_data,
                client_ip=self.client_ip,
                is_handshake=is_handshake
            )
            if is_client:
                self.tls_context.seq_num = tls_seq.to_bytes(8, 'big')
            else:
                self.tls_context.seq_num = tls_seq.to_bytes(8, 'big')
            self.pcap_writer.packets.append(packet)
            return packet
        except Exception as e:
            raise TLSSessionError(f"Failed to send TLS packet: {e}")

    def send_to_client(self, message: Any) -> None:
        """Send a message to the client during handshake"""
        if not hasattr(self.tls_context, 'msg') or self.tls_context.msg is None:
            self.tls_context.msg = []
        self.tls_context.msg.append(message)
        if hasattr(message, 'type') and getattr(message, 'type', None) in [22]:
            self.handshake_messages.append(raw(message))

    def send_to_server(self, message: Any) -> None:
        """Send a message to the server during handshake"""
        if not hasattr(self.tls_context, 'msg') or self.tls_context.msg is None:
            self.tls_context.msg = []
        self.tls_context.msg.append(message)
        if hasattr(message, 'type') and getattr(message, 'type', None) in [22]:
            self.handshake_messages.append(raw(message))

    def add_handshake_message(self, message: Any) -> None:
        """Add a raw message to handshake messages"""
        if not hasattr(self, 'handshake_messages'):
            self.handshake_messages = []
        self.handshake_messages.append(message)

    def cleanup(self) -> None:
        """Clean up session resources"""
        try:
            self.state.handshake_messages.clear()
        except Exception as e:
            logging.error(f"Session cleanup failed: {e}")