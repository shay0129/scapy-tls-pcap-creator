"""
Packet validation module for TLS/TCP packets.
Handles validation, statistics, and record type checking.
"""
from dataclasses import dataclass
from typing import Optional
from scapy.layers.inet import TCP, IP
from scapy.packet import Raw, Packet
import logging

from .constants import TLSVersion, TLSRecord


# Data Classes
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
   """TLS/TCP Packet Validation Logic"""

   @staticmethod
   def validate_packet(packet: Packet, idx: int) -> bool:
       """Validate all layers of a packet."""
       try:
           if not PacketValidator._validate_ip_layer(packet):
               return False
               
           if not PacketValidator._validate_tcp_layer(packet):
               return False
               
           if Raw in packet:
               payload = packet[Raw].load
               return PacketValidator._validate_payload(payload, idx)
                   
           return True
           
       except Exception as e:
           logging.error(f"Packet validation error: {e}")
           return False
   
   @staticmethod
   def _validate_ip_layer(packet: Packet) -> bool:
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

   @staticmethod 
   def _validate_tcp_layer(packet: Packet) -> bool:
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

   @staticmethod
   def _validate_payload(payload: bytes, idx: Optional[int] = None) -> bool:
       """Validate packet payload (TLS/HTTP)"""
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

   @staticmethod
   def validate_tls_record(payload: bytes, idx: Optional[int] = None) -> ValidationResult:
       """Validate TLS record format"""
       try:
           if len(payload) < 5:
               return ValidationResult(False, "Record too short")
               
           record_type = payload[0]
           version = (payload[1] << 8) | payload[2]
           length = (payload[3] << 8) | payload[4]
           
           valid_record_types = [
               TLSRecord.HANDSHAKE, 
               TLSRecord.APPLICATION_DATA, 
               TLSRecord.CHANGE_CIPHER_SPEC
           ]
           
           if record_type not in valid_record_types:
               return ValidationResult(False, f"Invalid record type: {hex(record_type)}")
               
           if version != TLSVersion.TLS_1_2:
               return ValidationResult(False, f"Invalid version: {hex(version)}")
               
           if length + 5 != len(payload):
               return ValidationResult(False, f"Length mismatch: {length + 5} != {len(payload)}")
               
           return ValidationResult(True, "Valid TLS record")
           
       except Exception as e:
           return ValidationResult(False, f"Validation error: {str(e)}")

   @staticmethod
   def get_record_info(payload: bytes) -> Optional[str]:
       """Extract TLS record information"""
       if len(payload) < 5:
           return None
           
       if payload.startswith(b'GET') or payload.startswith(b'HTTP'):
           return "HTTP message"
           
       record_type = payload[0]
       version = (payload[1] << 8) | payload[2]
       length = (payload[3] << 8) | payload[4]
       
       return (f"Record Type: {hex(record_type)}, "
               f"Version: {hex(version)}, "
               f"Length: {length}")

   @staticmethod
   def count_tls_records(packet: Packet) -> int:
       """Count the number of TLS records in a packet"""
       if Raw not in packet:
           return 0
       
       payload = packet[Raw].load
       count = 0
       offset = 0
       
       while offset + 5 <= len(payload):
           record_type = payload[offset]
           version = (payload[offset + 1] << 8) | payload[offset + 2]
           length = (payload[offset + 3] << 8) | payload[offset + 4]
           
           if record_type in [0x14, 0x15, 0x16, 0x17] and version == TLSVersion.TLS_1_2:
               count += 1
               offset += 5 + length
           else:
               break
       
       return count