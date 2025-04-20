"""
PCAP Writer module for network packet storage and management.
Handles packet storage, saving to PCAP files, and basic packet statistics.
"""
from dataclasses import dataclass
from scapy.utils import wrpcap
from scapy.packet import Packet
from pathlib import Path
from typing import List, Dict
import logging

from .packet_validator import PacketValidator, PacketStats
from .exceptions import StorageError, PcapWriteError

# Configuration
@dataclass
class PcapWriterConfig:
   """Configuration for PCAP Writer"""
   log_path: Path
   log_level: int = logging.INFO

class PcapWriter:
   """Handles storage and management of network packets for PCAP generation."""

   def __init__(self, config: PcapWriterConfig) -> None:
       """Initialize the PCAP writer."""
       self.config = config
       self.packets: List[Packet] = []
       self.stats = PacketStats()
       self._setup_logging()

   def __enter__(self) -> 'PcapWriter':
       return self
       
   def __exit__(self, exc_type, exc_val, exc_tb) -> None:
       self.cleanup()

   def cleanup(self) -> None:
       """Cleanup resources"""
       self.packets.clear()

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
           raise StorageError(f"Failed to setup logging: {e}")

   def save_pcap(self, filename: str) -> None:
       """Save packets to PCAP file with validation."""
       try:
           valid_packets = []
           validator = PacketValidator()

           for idx, pkt in enumerate(self.packets):
               try:
                   if validator.validate_packet(pkt, idx):
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
           raise PcapWriteError(f"Failed to save PCAP file: {e}")

   def get_statistics(self) -> dict:
       """Get packet processing statistics"""
       return {
           "total_packets": self.stats.total_packets,
           "valid_packets": self.stats.valid_packets,
           "invalid_packets": self.stats.invalid_packets,
           "tls_records": self.stats.tls_records
       }

   def verify_and_log_packets(self) -> None:
       """Verify and log details of all packets."""
       logging.info(f"Verifying {len(self.packets)} packets...")
       
       for idx, packet in enumerate(self.packets, 1):
           try:
               logging.info(f"Packet {idx}: {packet.summary()}")
               self.stats.tls_records += PacketValidator.count_tls_records(packet)
                       
           except Exception as e:
               logging.error(f"Error verifying packet {idx}: {e}")
               
       stats = self.get_statistics()
       logging.info("Verification complete: " + 
                   f"{stats['valid_packets']} valid packets, " +
                   f"{stats['tls_records']} TLS records")

   def add_packet(self, packet: Packet) -> None:
       """Add a packet to storage"""
       self.packets.append(packet)
       logging.debug(f"Added packet: {packet.summary()}")