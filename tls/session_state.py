# pyright: reportUnknownVariableType=false, reportUnknownMemberType=false, reportUnknownArgumentType=false, reportUnknownParameterType=false, reportMissingParameterType=false, reportMissingTypeArgument=false, reportReturnType=false, reportAttributeAccessIssue=false
"""State information for TLS session"""
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from dataclasses import dataclass, field
from typing import Optional, Tuple, List, Dict, Any, Protocol, runtime_checkable
from scapy.layers.inet import TCP, IP
from scapy.packet import Raw, Packet
from hmac import HMAC
import hashlib
import logging
import random

from .verification import verify_tls_mac
from .exceptions import PcapWriteError
from .constants import TCPFlags
from .utils.packet import flags_to_int

@runtime_checkable
class KeyBlock(Protocol):
    client_mac_key: bytes
    server_mac_key: bytes
    client_key: bytes
    server_key: bytes
    client_iv: bytes
    server_iv: bytes

@dataclass
class ConnectionState:
    """State information for a TCP connection"""
    seq: int = field(default_factory=lambda: random.randint(1000000, 9999999))
    ack: int = 0
    isn: int = 0
    fin_sent: bool = False

@dataclass
class SessionState:
    """State information for TLS session"""
    tcp_seq_num: int = 0
    client_seq_num: int = field(default=0)
    server_seq_num: int = field(default=0)
    master_secret: Optional[bytes] = None
    handshake_completed: bool = False
    handshake_messages: List[Any] = field(default_factory=list)
    connections: Dict[Tuple[str, str, int, int], Dict[str, Any]] = field(default_factory=dict)
    key_block: Optional[KeyBlock] = None
    sni: str = ""
    cert_chain: list = field(default_factory=list)

    def update_tcp_seq_ack(self, src_ip: str, dst_ip: str, sport: int, dport: int, 
                       payload_size: int, flags: int, is_handshake: bool = False) -> Tuple[int, int]:
        """Update sequence and acknowledgment numbers based on connection state"""
        connection_id = (src_ip, dst_ip, sport, dport)
        reverse_id = (dst_ip, src_ip, dport, sport)

        # Initialize connection state if needed
        if connection_id not in self.connections:
            self.connections[connection_id] = {
                'seq': random.randint(1000000, 9999999),
                'ack': 0,
                'isn': 0,
                'fin_sent': False
            }

        conn: Dict[str, Any] = self.connections[connection_id]
        rev_conn: Dict[str, Any] = self.connections.get(reverse_id, {'seq': 0, 'ack': 0, 'isn': 0})

        seq: int = conn['seq']
        ack: int = conn['ack']

        # Calculate sequence increment
        if is_handshake:
            seq_increment = payload_size
        else:
            if flags & 0x02:  # SYN
                conn['isn'] = seq
                seq_increment = 1
            elif flags & 0x01:  # FIN
                seq_increment = 1
            elif flags & 0x04:  # RST
                seq_increment = 0
            else:
                seq_increment = payload_size

        # Update sequence number
        conn['seq'] = seq + seq_increment

        # Handle ACK flag
        if flags & 0x10:  # ACK
            if rev_conn['seq'] > 0:
                ack = rev_conn['seq']
                if rev_conn.get('fin_sent', False):
                    ack += 1
                    rev_conn['fin_sent'] = False
            conn['ack'] = ack

        # Track FIN flag
        if flags & 0x01:
            conn['fin_sent'] = True

        return seq, ack

    def create_tls_packet(self, src_ip: str, dst_ip: str, sport: int, dport: int, 
                      tls_data: bytes, client_ip: str, is_handshake: bool = False) -> Tuple[IP, int]:
        tcp_payload = tls_data  # Already bytes
        flags = "PA"
        flags_int = flags_to_int(flags)
        
        seq, ack = self.update_tcp_seq_ack(
            src_ip, dst_ip, sport, dport,
            len(tcp_payload), flags_int, is_handshake
        )

        is_client = (src_ip == client_ip)
        if is_client:
            tls_seq = self.client_seq_num
            mac_key = self.key_block.client_mac_key if self.key_block else None
            iv = self.key_block.client_iv if self.key_block else None
            encryption_key = self.key_block.client_key if self.key_block else None
            logging.debug(f"Client seq num: {self.client_seq_num}")
            self.client_seq_num += 1
        else:
            tls_seq = self.server_seq_num 
            mac_key = self.key_block.server_mac_key if self.key_block else None
            iv = self.key_block.server_iv if self.key_block else None
            encryption_key = self.key_block.server_key if self.key_block else None
            logging.debug(f"Server seq num: {self.server_seq_num}")
            self.server_seq_num += 1

        if mac_key and encryption_key and iv:
            # Calculate MAC
            mac = calculate_mac(mac_key, tls_seq, 0x17, 0x0303, tcp_payload)
            plaintext = tcp_payload + mac

            # Add padding
            block_size = 16
            plaintext_padded = add_padding(plaintext, block_size)

            # Perform encryption
            cipher = Cipher(algorithms.AES(encryption_key), modes.CBC(iv))
            encryptor = cipher.encryptor()
            final_payload = encryptor.update(plaintext_padded) + encryptor.finalize()
        else:
            final_payload = tcp_payload

        packet = IP(src=src_ip, dst=dst_ip) / \
                TCP(sport=sport, dport=dport, seq=seq, ack=ack, flags=flags, window=65535) / \
                Raw(load=final_payload)
        
        return packet, tls_seq
            
    def create_tcp_packet(
        self,
        src_ip: str,
        dst_ip: str,
        sport: int,
        dport: int,
        payload: bytes,
        flags: str
    ) -> IP:
        """Create a TCP packet with the specified parameters."""
        try:
            payload_size = len(payload)
            flags_int = flags_to_int(flags)
            seq, ack = self.update_tcp_seq_ack(src_ip, dst_ip, sport, dport, payload_size, flags_int)

            ip_layer = IP(src=src_ip, dst=dst_ip)
            tcp_layer = TCP(sport=sport, dport=dport, seq=seq, ack=ack, flags=flags)
            packet = ip_layer / tcp_layer / Raw(load=payload)
            
            logging.debug(f"Created TCP packet: {packet.summary()}")
            logging.debug(f"SEQ: {seq}, ACK: {ack}, Flags: {flags}")
            
            return packet
        
        except Exception as e:
            raise PcapWriteError(f"Failed to create TCP packet: {e}")
        
    def _calculate_seq_increment(
        self, 
        flags: int, 
        payload_size: int, 
        is_handshake: bool = False
    ) -> int:
        """
        Calculate sequence number increment based on TCP flags and payload.
        
        Args:
            flags: TCP flags
            payload_size: Size of the payload
            is_handshake: Whether this is a handshake packet
        
        Returns:
            int: Sequence number increment
        """
        # For SYN and FIN flags, increment is 1
        if flags & (TCPFlags.SYN | TCPFlags.FIN):
            return 1
        
        # For handshake packets or packets with payload, increment by payload size
        if is_handshake or payload_size > 0:
            return payload_size
        
        # For other packets (like ACK without payload), no increment
        return 0
    
    def _handle_ack_flag(self, conn: ConnectionState) -> int:
        """
        Handle ACK flag and determine acknowledgment number.
        
        Args:
            conn: Connection state for the reverse direction
        
        Returns:
            int: Acknowledgment number
        """
        try:
            # If no initial sequence number is set, use the connection's current sequence
            if conn.isn == 0:
                conn.isn = conn.seq
            
            # Simple acknowledgment: use the current sequence number of the reverse connection
            return conn.seq
        
        except Exception as e:
            raise PcapWriteError(f"Failed to handle ACK flag: {e}")
        
    def create_syn_packet(self, src_ip: str, dst_ip: str, sport: int, dport: int) -> IP:
        seq, _ = self.update_tcp_seq_ack(src_ip, dst_ip, sport, dport, 0, TCPFlags.SYN)
        return IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=dport, seq=seq, flags="S", window=65535)

    def create_synack_packet(self, src_ip: str, dst_ip: str, sport: int, dport: int) -> IP:
        seq, ack = self.update_tcp_seq_ack(src_ip, dst_ip, sport, dport, 0, TCPFlags.SYN | TCPFlags.ACK)
        return IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=dport, seq=seq, ack=ack, flags="SA", window=65535)

    def create_fin_packet(self, src_ip: str, dst_ip: str, sport: int, dport: int) -> IP:
        seq, ack = self.update_tcp_seq_ack(src_ip, dst_ip, sport, dport, 0, TCPFlags.FIN | TCPFlags.ACK)
        return IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=dport, seq=seq, ack=ack, flags="FA", window=65535)

    def process_received_tls_packet(self, packet: Packet, key_block: KeyBlock) -> bytes:
        payload: bytes = packet[Raw].load
        
        # Decrypt payload
        cipher = Cipher(algorithms.AES(key_block.client_key), modes.CBC(key_block.client_iv))
        decryptor = cipher.decryptor()
        decrypted_payload = decryptor.update(payload) + decryptor.finalize()
        
        # Verify and remove padding
        data_with_mac = verify_padding(decrypted_payload)
        
        # Split data and MAC
        digest_size = 32  # SHA256
        data = data_with_mac[:-digest_size]
        received_mac = data_with_mac[-digest_size:]
        
        # Verify MAC
        computed_mac = verify_tls_mac(
            key_block.client_mac_key, 
            self.client_seq_num,
            0x17,  # Application data
            0x0303,  # TLS 1.2
            data
        )
        
        if computed_mac != received_mac:
            raise ValueError("MAC verification failed")
        
        return data

    def process_received_server_tls_packet(self, packet: Packet, key_block: KeyBlock) -> bytes:
        payload: bytes = packet[Raw].load
        
        # Decrypt payload
        cipher = Cipher(algorithms.AES(key_block.server_key), modes.CBC(key_block.server_iv))
        decryptor = cipher.decryptor()
        decrypted_payload = decryptor.update(payload) + decryptor.finalize()
        
        # Verify and remove padding
        data_with_mac = verify_padding(decrypted_payload)
        
        # Split data and MAC
        digest_size = 32  # SHA256
        data = data_with_mac[:-digest_size]
        received_mac = data_with_mac[-digest_size:]
        
        # Verify MAC
        computed_mac = verify_tls_mac(
            key_block.server_mac_key, 
            self.server_seq_num,
            0x17,  # Application data
            0x0303,  # TLS 1.2
            data
        )
        
        if computed_mac != received_mac:
            raise ValueError("Server MAC verification failed")
        
        return data

def add_padding(plaintext: bytes, block_size: int) -> bytes:
    pad_length = block_size - (len(plaintext) % block_size)
    if pad_length == 0:
        pad_length = block_size
    padding = bytes([pad_length - 1] * pad_length)
    return plaintext + padding

def verify_padding(plaintext: bytes) -> bytes:
    pad_length = plaintext[-1]
    
    # Check if padding is valid
    if pad_length > len(plaintext) - 1:
        raise ValueError(f"Invalid padding: {pad_length} too large")
    
    # Verify padding bytes
    padding = plaintext[-pad_length-1:-1]
    if not all(b == pad_length for b in padding):
        raise ValueError("Invalid padding content")
    
    # Return data without padding
    return plaintext[:-pad_length-1]

def verify_tls_mac(mac_key: bytes, seq_num: int, content_type: int, version: int, data: bytes) -> bytes:
    mac_data = (
        seq_num.to_bytes(8, 'big') +  
        content_type.to_bytes(1, 'big') +                     
        version.to_bytes(2, 'big') +                 
        len(data).to_bytes(2, 'big') +  
        data
    )
    return HMAC(mac_key, mac_data, hashlib.sha256).digest()

def calculate_mac(mac_key: bytes, seq_num: int, content_type: int, version: int, data: bytes) -> bytes:
    """Calculate TLS MAC"""
    mac_data = (
        seq_num.to_bytes(8, 'big') +  # Sequence number
        content_type.to_bytes(1, 'big') +  # Content type
        version.to_bytes(2, 'big') +  # Version
        len(data).to_bytes(2, 'big') +  # Length
        data  # Data
    )
    return HMAC(mac_key, mac_data, hashlib.sha256).digest()

def remove_padding(decrypted_payload: bytes) -> bytes:
    pad_length = decrypted_payload[-1]
    
    # Validate padding
    for i in range(1, pad_length + 1):
        if decrypted_payload[-i] != pad_length:
            raise ValueError("Invalid padding")
    
    return decrypted_payload[:-pad_length-1]
