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

    def create_tcp_ack(self, src_ip, dst_ip, sport, dport):
        """Create a TCP ACK packet"""

        seq, ack = self.update_seq_ack(src_ip, dst_ip, sport, dport, 0, 0x10)  # 0x10 is the ACK flag
        ip_layer = IP(src=src_ip, dst=dst_ip)
        tcp_layer = TCP(sport=sport, dport=dport, seq=seq, ack=ack, flags="A")
        return ip_layer / tcp_layer

    
    def create_tls_packet(self, src_ip, dst_ip, sport, dport, tls_payload):
        """Create a TCP packet with a TLS payload"""

        tcp_payload = raw(tls_payload)
        return self.create_tcp_packet(src_ip, dst_ip, sport, dport, tcp_payload, "PA")
    
    def create_tcp_handshake(self, client_ip, server_ip, client_port, server_port):
        """Create a TCP handshake"""
        # SYN
        syn = IP(src=client_ip, dst=server_ip) / TCP(sport=client_port, dport=server_port, flags='S', seq=random.randint(1000, 9999))
        self.pcap_writer.packets.append(syn)

        # SYN-ACK
        syn_ack = IP(src=server_ip, dst=client_ip) / TCP(sport=server_port, dport=client_port, flags='SA', seq=random.randint(1000, 9999), ack=syn.seq + 1)
        self.pcap_writer.packets.append(syn_ack)

        # ACK
        ack = IP(src=client_ip, dst=server_ip) / TCP(sport=client_port, dport=server_port, flags='A', seq=syn_ack.ack, ack=syn_ack.seq + 1)
        self.pcap_writer.packets.append(ack)

        logging.info("TCP Handshake completed")
        return syn.seq + 1, syn_ack.seq + 1  # Return next sequence numbers for client and server
    
    def add_ack(self, src_ip, dst_ip, src_port, dst_port, ack_num, seq_num):
        """Add an ACK packet to the packets list"""

        ack = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags='A', seq=seq_num, ack=ack_num)
        self.pcap_writer.packets.append(ack)
        logging.info(f"ACK sent from {src_ip} to {dst_ip}")
        return seq_num  # The sequence number doesn't change for ACK packets

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

    def log_crypto_values(self):
        """Log the crypto values to a file"""

        logging.info(f"Client Random: {self.client_random.hex() if hasattr(self, 'client_random') else 'N/A'}")
        logging.info(f"Server Random: {self.server_random.hex() if hasattr(self, 'server_random') else 'N/A'}")
        logging.info(f"Pre-Master Secret: {self.pre_master_secret.hex() if hasattr(self, 'pre_master_secret') else 'N/A'}")
        logging.info(f"Master Secret: {self.master_secret.hex() if hasattr(self, 'master_secret') else 'N/A'}")
        logging.info(f"Encryption Key: {self.master_secret[:16].hex() if hasattr(self, 'master_secret') else 'N/A'}")

    def verify_master_secret(self):
        """Verify the master secret on the log file"""

        return verify_master_secret(self.client_random, self.master_secret, self.config.SSL_KEYLOG_FILE)

    def decrypt_application_data_packet(self, packet):
        """Decrypt the application data packet"""

        return self.decrypt_data_tls12(packet)