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

    def update_seq_ack(self, src_ip, dst_ip, sport, dport, payload_size, flags):
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
        
        return ip_layer / tcp_layer / Raw(load=payload)

 

    
    def create_tls_packet(self, src_ip, dst_ip, sport, dport, tls_payload):
        """Create a TCP packet with a TLS payload"""

        tcp_payload = raw(tls_payload)
        return self.create_tcp_packet(src_ip, dst_ip, sport, dport, tcp_payload, "PA")
    

    def save_pcap(self, filename):
        """Save the packets to a PCAP file"""

        valid_packets = []
        invalid_packets = []

        for idx, pkt in enumerate(self.packets):
            try:
                raw_pkt = bytes(pkt)
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
        
        if invalid_packets:
            logging.warning(f"{len(invalid_packets)} packets were invalid and not saved.")
            for pkt, error in invalid_packets:
                logging.error(f"Invalid packet info: {error}")

    def verify_and_log_packets(self):
        logging.info("Starting packet verification and logging...")
        for idx, packet in enumerate(self.packets):
            logging.info(f"Packet {idx + 1}: {packet.summary()}")
            if TLS in packet:
                logging.info(f"TLS packet detected: {packet[TLS].summary()}")
        logging.info("Packet verification and logging completed.")


    def verify_master_secret(self):
        """Verify the master secret on the log file"""

        return verify_master_secret(self.client_random, self.master_secret, self.config.SSL_KEYLOG_FILE)

