# pcap_writer.py
from scapy.layers.tls.record import TLS
from scapy.layers.inet import TCP, IP
from scapy.packet import Raw
from scapy.utils import wrpcap
from scapy.compat import raw
import random
import logging

from crypto import *
from utils import flags_to_int
from tls_utils import *

class CustomPcapWriter:
    def __init__(self, config):
        self.config = config
        self.packets = []
        self.connections = {}
        self.setup_logging()

    def setup_logging(self):
        logging.basicConfig(filename='../api/pcap_generator.log', level=logging.INFO,
                          format='%(asctime)s - %(levelname)s - %(message)s')

    def update_seq_ack(self, src_ip, dst_ip, sport, dport, payload_size, flags, is_handshake=False):
        """Update the sequence and acknowledgment numbers"""
        connection_id = (src_ip, dst_ip, sport, dport)
        reverse_id = (dst_ip, src_ip, dport, sport)

        if connection_id not in self.connections:
            self.connections[connection_id] = {
                'seq': random.randint(1000000, 9999999),
                'ack': 0,
                'isn': 0
            }

        conn = self.connections[connection_id]
        rev_conn = self.connections.get(reverse_id, {'seq': 0, 'ack': 0, 'isn': 0})

        seq = conn['seq']
        ack = conn['ack']

        # Special handling for handshake packets
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

        conn['seq'] = seq + seq_increment

        if flags & 0x10:  # ACK
            if rev_conn['seq'] > 0:
                ack = rev_conn['seq']
                if rev_conn.get('fin_sent', False):
                    ack += 1
                    rev_conn['fin_sent'] = False
            conn['ack'] = ack

        if flags & 0x01:  # FIN
            conn['fin_sent'] = True

        return seq, ack

    def create_tcp_packet(self, src_ip, dst_ip, sport, dport, payload, flags):
        """Create a TCP packet"""
        payload_size = len(payload)
        flags_int = flags_to_int(flags)
        seq, ack = self.update_seq_ack(src_ip, dst_ip, sport, dport, payload_size, flags_int)

        ip_layer = IP(src=src_ip, dst=dst_ip)
        tcp_layer = TCP(sport=sport, dport=dport, seq=seq, ack=ack, flags=flags)
        
        packet = ip_layer / tcp_layer / Raw(load=payload)
        
        # Log packet creation for debugging
        logging.debug(f"Created TCP packet: {packet.summary()}")
        logging.debug(f"SEQ: {seq}, ACK: {ack}, Flags: {flags}")
        
        return packet

    def create_tls_packet(self, src_ip, dst_ip, sport, dport, tls_data, seq_num=None, is_handshake=False):
        """Create a TCP packet with TLS data"""
        tcp_payload = raw(tls_data)
        flags = "PA"  # PSH+ACK for all TLS packets
        
        payload_size = len(tcp_payload)
        flags_int = flags_to_int(flags)
        seq, ack = self.update_seq_ack(src_ip, dst_ip, sport, dport, payload_size, flags_int, is_handshake)

        # Create packet
        ip_layer = IP(src=src_ip, dst=dst_ip)
        tcp_layer = TCP(sport=sport, dport=dport, seq=seq, ack=ack, flags=flags)
        packet = ip_layer / tcp_layer / Raw(load=tcp_payload)

        # Verify TLS record format
        if len(tcp_payload) > 0:
            record_type = tcp_payload[0]
            version = (tcp_payload[1] << 8) | tcp_payload[2]
            if record_type in [0x16, 0x17]:  # Handshake or Application Data
                if version != 0x0303:  # TLS 1.2
                    logging.warning(f"Unexpected TLS version: {hex(version)}")
                else:
                    logging.debug(f"Valid TLS 1.2 record: type={hex(record_type)}")

        return packet

    def save_pcap(self, filename):
        """Save the packets to a PCAP file with enhanced verification"""
        valid_packets = []
        invalid_packets = []

        for idx, pkt in enumerate(self.packets):
            try:
                # Basic packet validation
                raw_pkt = bytes(pkt)
                
                # Additional TLS validation
                if Raw in pkt and len(pkt[Raw].load) > 0:
                    payload = pkt[Raw].load
                    if payload[0] in [0x16, 0x17]:  # Handshake or Application Data
                        version = (payload[1] << 8) | payload[2]
                        length = (payload[3] << 8) | payload[4]
                        if version != 0x0303:  # TLS 1.2
                            logging.warning(f"Packet {idx}: Invalid TLS version {hex(version)}")
                        if length + 5 != len(payload):
                            logging.warning(f"Packet {idx}: TLS length mismatch")
                
                valid_packets.append(pkt)
                
            except Exception as e:
                error_message = f"Packet {idx} skipped due to error: {e}"
                invalid_packets.append((pkt, error_message))
                logging.error(error_message)
        
        if valid_packets:
            wrpcap(filename, valid_packets)
            logging.info(f"PCAP file '{filename}' saved successfully with {len(valid_packets)} packets.")
        else:
            logging.warning("No valid packets to save.")

    def verify_and_log_packets(self):
        """Enhanced packet verification and logging"""
        logging.info("Starting packet verification and logging...")
        
        for idx, packet in enumerate(self.packets):
            logging.info(f"Packet {idx + 1}: {packet.summary()}")
            
            # Check for TLS content
            if Raw in packet:
                payload = packet[Raw].load
                if len(payload) > 0 and payload[0] in [0x16, 0x17]:
                    record_type = payload[0]
                    version = (payload[1] << 8) | payload[2]
                    length = (payload[3] << 8) | payload[4]
                    
                    logging.info(f"TLS Record: type={hex(record_type)}, "
                               f"version={hex(version)}, length={length}")
        
        logging.info("Packet verification and logging completed.")