"""
PCAP Writer module for TLS/TCP packet capture.
Handles packet creation, validation and storage for network traffic simulation.
"""

from dataclasses import dataclass, field
from scapy.layers.inet import TCP, IP
from scapy.utils import wrpcap
from scapy.compat import raw
from scapy.packet import Raw, Packet
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any
import random
import logging

from .constants import TLSVersion, TLSRecord, TCPFlags
from .utils import flags_to_int

# Exceptions
class PcapWriterError(Exception):
    """Base exception for PCAP Writer errors"""
    pass

class TLSValidationError(PcapWriterError):
    """TLS record validation error"""
    pass

class PacketCreationError(PcapWriterError):
    """Error during packet creation"""
    pass

# Data Classes
@dataclass
class PcapWriterConfig:
    """Configuration for PCAP Writer"""
    log_path: Path
    log_level: int = logging.INFO

@dataclass
class ConnectionState:
    """State information for a TCP connection"""
    seq: int = field(default_factory=lambda: random.randint(1000000, 9999999))
    ack: int = 0
    isn: int = 0
    fin_sent: bool = False

@dataclass
class PacketStats:
    """Statistics for packet processing"""
    total_packets: int = 0
    valid_packets: int = 0
    invalid_packets: int = 0
    tls_records: int = 0
    
    def add_valid_packet(self) -> None:
        self.total_packets += 1
        self.valid_packets += 1
        
    def add_invalid_packet(self) -> None:
        self.total_packets += 1
        self.invalid_packets += 1

class ValidationResult:
    """TLS Record Validation Result"""
    def __init__(self, valid: bool, message: str):
        self.valid = valid
        self.message = message

class PacketValidator:
    """TLS Packet Validation Logic"""
    
    @staticmethod
    def validate_tls_record(payload: bytes, idx: Optional[int] = None) -> ValidationResult:
        """Validate TLS record format"""
        try:
            if len(payload) < 5:
                return ValidationResult(False, "Record too short")
                
            record_type = payload[0]
            version = (payload[1] << 8) | payload[2]
            length = (payload[3] << 8) | payload[4]
            
            # Update valid record types to include ChangeCipherSpec
            valid_record_types = [
                TLSRecord.HANDSHAKE, 
                TLSRecord.APPLICATION_DATA, 
                TLSRecord.CHANGE_CIPHER_SPEC  # Add this line
            ]
            
            if record_type not in valid_record_types:
                return ValidationResult(
                    False, 
                    f"Invalid record type: {hex(record_type)}"
                )
                
            if version != TLSVersion.TLS_1_2:
                return ValidationResult(
                    False,
                    f"Invalid version: {hex(version)}"
                )
                
            if length + 5 != len(payload):
                return ValidationResult(
                    False,
                    f"Length mismatch: {length + 5} != {len(payload)}"
                )
                
            return ValidationResult(True, "Valid TLS record")
            
        except Exception as e:
            return ValidationResult(False, f"Validation error: {str(e)}")

    @staticmethod
    def get_record_info(payload: bytes) -> Optional[str]:
        """Extract TLS record information"""
        if len(payload) < 5:
            return None
            
        # Check if it's HTTP first
        if payload.startswith(b'GET') or payload.startswith(b'HTTP'):
            return "HTTP message"
            
        # Otherwise try to parse as TLS
        record_type = payload[0]
        version = (payload[1] << 8) | payload[2]
        length = (payload[3] << 8) | payload[4]
        
        return (f"Record Type: {hex(record_type)}, "
                f"Version: {hex(version)}, "
                f"Length: {length}")
    
class CustomPcapWriter:
    """Handles creation and storage of network packets for PCAP generation."""

    def __init__(self, config: PcapWriterConfig) -> None:
        """Initialize the PCAP writer."""
        self.config = config
        self.packets: List[Packet] = []
        self.connections: Dict[Tuple[str, str, int, int], ConnectionState] = {}
        self.stats = PacketStats()
        self._setup_logging()

    def __enter__(self) -> 'CustomPcapWriter':
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.cleanup()

    def cleanup(self) -> None:
        """Cleanup resources"""
        self.packets.clear()
        self.connections.clear()

    def _setup_logging(self) -> None:
        """Configure logging settings."""
        try:
            log_path = self.config.log_path
            log_path.parent.mkdir(parents=True, exist_ok=True)
            
            logging.basicConfig(
                filename=str(log_path),
                level=self.config.log_level,
                format='%(asctime)s - %(levelname)s - [%(name)s] - %(message)s'
            )
        except Exception as e:
            raise PcapWriterError(f"Failed to setup logging: {e}")

    def _get_connection_state(
        self,
        connection_id: Tuple[str, str, int, int]
    ) -> ConnectionState:
        """Get or create connection state for a connection ID."""
        if connection_id not in self.connections:
            self.connections[connection_id] = ConnectionState()
        return self.connections[connection_id]

    def _validate_ip_layer(self, packet: Packet) -> bool:
        """Validate IP layer of packet"""
        try:
            if IP not in packet:
                logging.warning("Missing IP layer")
                return False
                
            ip = packet[IP]
            if not ip.src or not ip.dst:
                logging.warning("Invalid IP addresses")
                return False
                
            return True
            
        except Exception as e:
            logging.error(f"IP validation error: {e}")
            return False

    def _validate_tcp_layer(self, packet: Packet) -> bool:
        """Validate TCP layer of packet"""
        try:
            if TCP not in packet:
                logging.warning("Missing TCP layer")
                return False
                
            tcp = packet[TCP]
            if not (0 < tcp.sport < 65536) or not (0 < tcp.dport < 65536):
                logging.warning("Invalid TCP ports")
                return False
                
            return True
            
        except Exception as e:
            logging.error(f"TCP validation error: {e}")
            return False

    def validate_packet(self, packet: Packet, idx: int) -> bool:
        """Validate all layers of a packet."""
        try:
            if not self._validate_ip_layer(packet):
                return False
                
            if not self._validate_tcp_layer(packet):
                return False
                
            if Raw in packet:
                payload = packet[Raw].load
                # Check if it's a TLS record
                if len(payload) >= 5 and payload[0] in [0x14, 0x15, 0x16, 0x17]:
                    result = PacketValidator.validate_tls_record(payload, idx)
                    if not result.valid:
                        logging.warning(f"Packet {idx}: {result.message}")
                        return False
                # If not TLS, check if it's valid HTTP
                elif payload.startswith(b'GET') or payload.startswith(b'HTTP'):
                    logging.info(f"Packet {idx}: Valid HTTP message")
                    return True
                else:
                    logging.warning(f"Packet {idx}: Unknown protocol")
                    return False
                    
            return True
            
        except Exception as e:
            logging.error(f"Packet validation error: {e}")
            return False

    def update_seq_ack(self, src_ip, dst_ip, sport, dport, payload_size, flags, is_handshake=False):
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

        conn = self.connections[connection_id]
        rev_conn = self.connections.get(reverse_id, {'seq': 0, 'ack': 0, 'isn': 0})

        seq = conn['seq']
        ack = conn['ack']

        # Calculate sequence increment based on packet type
        if is_handshake:
            # For handshake packets, use entire payload size
            seq_increment = payload_size
        else:
            if flags & 0x02:  # SYN
                conn['isn'] = seq  # Store Initial Sequence Number
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
        if flags & 0x01:  # FIN
            conn['fin_sent'] = True

        return seq, ack

    def _calculate_seq_increment(self, flags, payload_size):
        if flags & (TCPFlags.SYN | TCPFlags.FIN):
            return 1
        return payload_size

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
            seq, ack = self.update_seq_ack(src_ip, dst_ip, sport, dport, payload_size, flags_int)

            ip_layer = IP(src=src_ip, dst=dst_ip)
            tcp_layer = TCP(sport=sport, dport=dport, seq=seq, ack=ack, flags=flags)
            packet = ip_layer / tcp_layer / Raw(load=payload)
            
            logging.debug(f"Created TCP packet: {packet.summary()}")
            logging.debug(f"SEQ: {seq}, ACK: {ack}, Flags: {flags}")
            
            return packet
        
        except Exception as e:
            raise PacketCreationError(f"Failed to create TCP packet: {e}")

    def create_syn_packet(self, src_ip, dst_ip, sport, dport):
        seq, _ = self.update_seq_ack(src_ip, dst_ip, sport, dport, 0, TCPFlags.SYN)
        return IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=dport, seq=seq, flags="S", window=65535)

    def create_synack_packet(self, src_ip, dst_ip, sport, dport):
        seq, ack = self.update_seq_ack(src_ip, dst_ip, sport, dport, 0, TCPFlags.SYN | TCPFlags.ACK)
        return IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=dport, seq=seq, ack=ack, flags="SA", window=65535)

    def create_fin_packet(self, src_ip, dst_ip, sport, dport):
        seq, ack = self.update_seq_ack(src_ip, dst_ip, sport, dport, 0, TCPFlags.FIN | TCPFlags.ACK)
        return IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=dport, seq=seq, ack=ack, flags="FA", window=65535)

    def create_tls_packet(self, src_ip, dst_ip, sport, dport, tls_data, is_handshake=False):
        """Create a TCP packet with TLS data"""
        tcp_payload = raw(tls_data)
        flags = "PA"  # PSH+ACK for all TLS packets
        flags_int = flags_to_int(flags)
        
        seq, ack = self.update_seq_ack(
            src_ip, 
            dst_ip, 
            sport, 
            dport, 
            len(tcp_payload), 
            flags_int,
            is_handshake
        )

        packet = IP(src=src_ip, dst=dst_ip) / \
                TCP(sport=sport, dport=dport, seq=seq, ack=ack, flags=flags, window=65535) / \
                Raw(load=tcp_payload)
        
        logging.debug(f"Created TLS packet: {packet.summary()}")
        logging.debug(f"SEQ: {seq}, ACK: {ack}, Flags: {flags}, Length: {len(tcp_payload)}")
        
        return packet

    def save_pcap(self, filename: str) -> None:
        """Save packets to PCAP file with validation."""
        try:
            valid_packets = []

            for idx, pkt in enumerate(self.packets):
                try:
                    if self.validate_packet(pkt, idx):
                        valid_packets.append(pkt)
                        self.stats.add_valid_packet()
                    else:
                        self.stats.add_invalid_packet()
                    
                except Exception as e:
                    self.stats.add_invalid_packet()
                    logging.error(f"Error processing packet {idx}: {e}")
            
            if valid_packets:
                output_path = Path(filename)
                output_path.parent.mkdir(parents=True, exist_ok=True)
                wrpcap(str(output_path), valid_packets)
                logging.info(f"Saved {len(valid_packets)} valid packets to {filename}")
                if self.stats.invalid_packets:
                    logging.warning(f"Skipped {self.stats.invalid_packets} invalid packets")
            else:
                logging.error("No valid packets to save")

        except Exception as e:
            logging.error(f"Failed to save PCAP file: {e}")
            raise PcapWriterError(f"Failed to save PCAP file: {e}")

    def get_statistics(self) -> dict:
        """Get packet processing statistics"""
        return {
            "total_packets": self.stats.total_packets,
            "valid_packets": self.stats.valid_packets,
            "invalid_packets": self.stats.invalid_packets,
            "tls_records": self.stats.tls_records,
            "connections": len(self.connections)
        }

    def verify_and_log_packets(self) -> None:
        """Verify and log details of all packets."""
        logging.info(f"Verifying {len(self.packets)} packets...")
        
        for idx, packet in enumerate(self.packets, 1):
            try:
                logging.info(f"Packet {idx}: {packet.summary()}")
                
                if Raw in packet:
                    payload = packet[Raw].load
                    if payload and len(payload) >= 5:
                        tls_info = PacketValidator.get_record_info(payload)
                        if tls_info:
                            logging.info(f"TLS Record: {tls_info}")
                            self.stats.tls_records += 1
                        
            except Exception as e:
                logging.error(f"Error verifying packet {idx}: {e}")
                
        stats = self.get_statistics()
        logging.info("Verification complete: " + 
                    f"{stats['valid_packets']} valid packets, " +
                    f"{stats['tls_records']} TLS records")
    
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
            raise PacketCreationError(f"Failed to handle ACK flag: {e}")