# utils.py
import logging
import hmac
from cryptography.hazmat.primitives import constant_time
from cryptography.hazmat.primitives import hashes
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import os

def encode_length(length, num_bytes) -> bytes:
    """Encode the length of a field"""

    return length.to_bytes(num_bytes, byteorder='big')

def generate_session_id():
    """Generate a random session ID"""
    # in this case, we generate a 32-byte random session ID
    # Session Resumption, which is not implemented here, would use a different session ID
    return os.urandom(32)

def flags_to_int(flags):
    """Convert a string of flags to an integer"""
    flag_map = {
        'F': 0x01,  # FIN
        'S': 0x02,  # SYN
        'R': 0x04,  # RST
        'P': 0x08,  # PSH
        'A': 0x10,  # ACK
        'U': 0x20   # URG
    }
    return sum(flag_map[f] for f in flags.upper() if f in flag_map)

# Setup logging to a file
logging.basicConfig(filename='../api/pcap_generator.log', 
                    level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    filemode='w')


def log_ssl_key(client_random: str, master_secret: str) -> None:
    with open("../api/SSLKEYLOG.LOG", "w") as f:
        f.write(f"CLIENT_RANDOM {client_random} {master_secret}\n")
    logging.info(f"Logged SSL key: CLIENT_RANDOM {client_random} {master_secret}")

def compare_to_original(post_value: bytes, original_value: bytes) -> bool:
    if not post_value:
        logging.info("Failed: Post message is empty")
        return False

    if constant_time.bytes_eq(post_value, original_value):
        logging.info("Comparison successful")
        return True
    
    logging.info("Comparison failed")
    return False

def compute_mac(key: bytes, message: bytes) -> bytes:
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(message)
    return h.finalize()


def int_to_bytes_length(n):
    """Helper function to calculate the byte length of an integer"""
    return (n.bit_length() + 7) // 8


def get_key_for_packet(packet_keys:list, packet_index:int):
    if 0 <= packet_index < len(packet_keys):
        return packet_keys[packet_index]
    else:
        raise ValueError(f"No key found for packet index {packet_index}")
    
"""def get_base_iv_for_packet(packet_ivs: list, packet_index: int)-> bytes:
        # for GCM mode
        if 0 <= packet_index < len(packet_ivs):
            return packet_ivs[packet_index]
        else:
            raise ValueError(f"No base IV found for packet index {packet_index}")"""
        
def get_mac_key_for_packet(packet_mac_keys:list,packet_index:int)-> bytes:
        # for CBC mode
        if 0 <= packet_index < len(packet_mac_keys):
            return packet_mac_keys[packet_index]
        else:
            raise ValueError(f"No MAC key found for packet index {packet_index}")
        

def print_message_content(message):
        try:
            decoded = message.decode('utf-8')
            lines = decoded.split('\n')
            for line in lines[:10]:
                logging.info(line)
            if len(lines) > 10:
                logging.info("...")
        except UnicodeDecodeError:
            logging.info(f"Binary data (first 100 bytes): {message[:100].hex()}")
            if len(message) > 100:
                logging.info("...")


def load_cert(cert_path):
    with open(cert_path, "rb") as f:
            cert_data = f.read()
            if cert_path.endswith('.der'):
                certificate = x509.load_der_x509_certificate(cert_data, default_backend())
            else:
                certificate = x509.load_pem_x509_certificate(cert_data, default_backend())
    return certificate