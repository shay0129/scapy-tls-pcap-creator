# tls_session.py
from scapy.layers.tls.record import TLS, TLSApplicationData
from scapy.layers.tls.handshake import TLSClientHello, TLSServerHello, TLSCertificate, TLSCertificateRequest, TLSServerHelloDone, TLSClientKeyExchange, TLSFinished
from scapy.layers.tls.extensions import TLS_Ext_ServerName, TLS_Ext_EncryptThenMAC, ServerName, TLS_Ext_SupportedGroups, TLS_Ext_SignatureAlgorithms
from scapy.layers.tls.crypto.suites import TLS_RSA_WITH_AES_128_CBC_SHA256
from scapy.layers.tls.crypto.prf import PRF
from scapy.layers.tls.record import TLSChangeCipherSpec
from scapy.layers.tls.extensions import (
    TLS_Ext_ServerName, TLS_Ext_ExtendedMasterSecret, TLS_Ext_EncryptThenMAC, ServerName,
    TLS_Ext_SupportedGroups, TLS_Ext_SignatureAlgorithms
)
from cryptography import x509
from scapy.all import Raw
from scapy.all import raw
import logging
import os

from cryptography.hazmat.primitives import serialization

from pcap_writer import CustomPcapWriter
from config import Config
from crypto import *
from utils import *
from tls_utils import *

class UnifiedTLSSession:
    def __init__(self, pcap_writer, client_ip, server_ip, client_port, server_port, use_tls=True, use_client_cert=False):
        # Initialize the TLS session
        self.pcap_writer = pcap_writer
        # IP addresses and ports
        self.client_ip = client_ip
        self.server_ip = server_ip
        self.client_port = client_port
        self.server_port = server_port
        self.server_name = "server"
        self.client_name_1 = "client1"
    
        # TLS parameters
        self.use_tls = use_tls
        self.use_client_cert = use_client_cert
        self.tls_context = TLS()

        # Generate client and server key pairs
        self.server_cert, self.server_private_key, self.server_public_key = load_server_cert_keys(cert_path="../certificates/server.der", key_path="../certificates/server.key")
        self.seq_num = 0
        self.master_secret = None

        # TLS handshake parameters
        self.handshake_completed = False
        self.handshake_messages = []  # Initialize the list to store handshake messages
        self.prf = PRF(hash_name='SHA256', tls_version=0x0303)  # TLS 1.2

        self.encrypted_packets = []
        self.original_messages = []
        self.packet_keys = []
        self.packet_ivs = []
        self.packet_mac_keys = []

        self.client_write_mac_key = None
        self.server_write_mac_key = None

    

    def perform_handshake(self)-> None:
        # According to RFC 5246, the TLS handshake process is as follows:
        try:
            # Step 1: Client Hello
            self.send_client_hello()
            
            # Step 2: Server Hello, Certificate, ServerKeyExchange (if needed), ServerHelloDone
            self.send_server_hello()
            
            # Step 3: Client (RSA) Key Exchange (and Client Certificate if required)
            self.send_client_key_exchange()
            
            # Step 4: Generate Master Secret
            self.handle_master_secret()
            
            # Step 5: Client ChangeCipherSpec and Finished
            self.send_client_change_cipher_spec()
            
            # Step 6: Server ChangeCipherSpec and Finished
            self.send_server_change_cipher_spec()
            
            # Step 7: Log SSL keys for Wireshark
            self.handle_ssl_key_log()
            
            logging.info("TLS Handshake completed successfully")
        except Exception as e:
            logging.error(f"TLS Handshake failed: {str(e)}")
            raise e
    
    def run_session(self, request_data, response_data, file_to_send=None):
        if self.use_tls:
            self.perform_handshake()
            self.handshake_completed = True
        
        if self.handshake_completed and self.use_client_cert:
            # תקשורת מוצפנת עבור client1
            self.send_application_data(request_data, is_request=True)
            self.send_application_data(response_data, is_request=False)
            if file_to_send:
                with open(file_to_send, 'rb') as file:
                    file_data = file.read()
                    self.send_application_data(file_data, is_request=False)
        else:
            # תקשורת HTTP לא מוצפנת עבור client2 (אחרי TLS handshake)
            self.send_unencrypted_data(request_data, is_request=True)
            self.send_unencrypted_data(response_data, is_request=False)

    def send_client_hello(self)-> None:
    #----------------------------------
    # Client Hello
    #----------------------------------
        self.client_GMT_unix_time, self.client_random_bytes = generate_random()
        self.client_random = self.client_GMT_unix_time.to_bytes(4, 'big') + self.client_random_bytes
        logging.info(f"Generated client_random: {self.client_random.hex()}")
        
        client_hello = TLSClientHello(
            version=0x0303,  # TLS 1.2
            ciphers=[TLS_RSA_WITH_AES_128_CBC_SHA256],
            ext=[
                TLS_Ext_ServerName(servernames=[ServerName(servername=f"{self.server_name}.local".encode())]),
                TLS_Ext_EncryptThenMAC(),
                TLS_Ext_SupportedGroups(groups=["x25519"]),
                TLS_Ext_SignatureAlgorithms(sig_algs=["sha256+rsa"]),
            ],
            gmt_unix_time=self.client_GMT_unix_time,
            random_bytes=self.client_random_bytes
        )
        self.tls_context.msg = [client_hello]
        self.send_tls_packet(self.client_ip, self.server_ip, self.client_port, self.server_port)

        logging.info(f"Client Hello sent from {self.client_ip}")
    
    def send_server_hello(self)-> None:
    #----------------------------------
    # Server Hello
    #----------------------------------
        
        self.server_GMT_unix_time, self.server_random_bytes = generate_random()
        self.server_random = self.server_GMT_unix_time.to_bytes(4, 'big') + self.server_random_bytes
        logging.info(f"Generated server_random: {self.server_random.hex()}")

        self.session_id = os.urandom(32)
        logging.info(f"Generated session_id: {self.session_id.hex()}")
        try:
            
            cert = load_cert("../certificates/"+self.server_name+".der")
            cert_der = cert.public_bytes(serialization.Encoding.DER)
            # Extract the public key from the certificate
            self.server_public_key = cert.public_key()

            logging.info(f"Server certificate loaded. Subject: {cert.subject}")
            logging.info(f"Server certificate public key: {self.server_public_key.public_numbers().n}")

        except Exception as e:
            logging.error(f"Error loading server certificate: {str(e)}")
            raise

        # recheck the server certificate
        logging.info(f"Server certificate loaded. Subject: {cert.subject}")
        logging.info(f"Server certificate public key: {cert.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()}")

        server_hello = TLSServerHello(
            version=0x0303,  # TLS 1.2
            gmt_unix_time=self.server_GMT_unix_time,
            random_bytes=self.server_random_bytes,
            sid = self.session_id,
            cipher=TLS_RSA_WITH_AES_128_CBC_SHA256.val,
            ext=[
                #TLS_Ext_ServerName(servernames=[ServerName(servername="Pasdaran.local")]), # need fix this extantion
                #TLS_Ext_SupportedGroups(groups=['secp256r1', 'x25519']), # relevant for ECDHE key exchange
                TLS_Ext_SignatureAlgorithms(sig_algs=['sha256+rsaepss']),
                TLS_Ext_ExtendedMasterSecret(),
                TLS_Ext_EncryptThenMAC()
                ]
            )
        
        # Server Certificate
        certificate = TLSCertificate(certs=[(len(cert_der), cert_der)])
        logging.info(f"Sending server certificate. Size: {len(cert_der)} bytes")

        # Log some information for debugging
        logging.info(f"Server Hello cipher: {server_hello.cipher}")
        logging.info(f"Server Hello version: {hex(server_hello.version)}")
        logging.info(f"Server Hello extensions: {server_hello.ext}")
        logging.info(f"Server selected cipher suite: {server_hello.cipher}")
        # Make sure the SSL keylog file is being used correctly
        ssl_keylog_file = self.pcap_writer.config.SSL_KEYLOG_FILE
        logging.info(f"Using SSL keylog file: {ssl_keylog_file}")
        if not os.path.exists(ssl_keylog_file):
            logging.warning(f"SSL keylog file does not exist: {ssl_keylog_file}")

        # Add this line to explicitly set the TLS version for the session
        self.tls_context.tls_version = 0x0303  # TLS 1.2

        # ECDH key exchange
        """server_key_exchange = TLSServerKeyExchange(
            params=ServerDHParams( #public server key, for play with it ECDH key exchange
                dh_p=self.server_public_key.public_numbers().n.to_bytes((self.server_public_key.public_numbers().n.bit_length() + 7) // 8, byteorder='big'),
                dh_g=self.server_public_key.public_numbers().e.to_bytes((self.server_public_key.public_numbers().e.bit_length() + 7) // 8, byteorder='big'),
                dh_Ys=self.server_public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo),
            ),
        )"""     
        
        self.tls_context.msg = [server_hello, certificate, TLSCertificateRequest(), TLSServerHelloDone()]
        self.send_tls_packet(self.server_ip, self.client_ip, self.server_port, self.client_port)
        logging.info(f"Server Hello and Certificate sent to {self.client_ip}")

    def send_client_key_exchange(self)-> None:
    #----------------------------------
    # Client Certificate (if required)
    #----------------------------------
        client_certificate = None
        if self.use_client_cert:
            try:
                cert = load_cert("../certificates/Pasdaran.local.crt")
                cert_der = cert.public_bytes(serialization.Encoding.DER)
                client_certificate = TLSCertificate(certs=[(len(cert_der), cert_der)])

                logging.info(f"Client Certificate sent from {self.client_ip}. Certificate size: {len(cert_der)} bytes")
            except Exception as e:
                logging.error(f"Error handling client certificate: {str(e)}")
                raise e

        #----------------------------------
        # Client (RSA) Key Exchange
        #----------------------------------
        try:
            self.pre_master_secret = generate_pre_master_secret()
            logging.info(f"Client generated pre_master_secret: {self.pre_master_secret.hex()}")

            # Encrypt pre-master secret with server's public key who extracted from server certificate
            self.encrypted_pre_master_secret = encrypt_pre_master_secret(self.pre_master_secret, self.server_public_key)
            
            if not isinstance(self.encrypted_pre_master_secret, bytes):
                self.encrypted_pre_master_secret = bytes(self.encrypted_pre_master_secret)

            logging.info(f"Encrypted pre_master_secret length: {len(self.encrypted_pre_master_secret)}")

            # validate the length of the encrypted pre-master secret
            length_bytes = len(self.encrypted_pre_master_secret).to_bytes(2, 'big')

            # יצירת המבנה המלא של ClientKeyExchange
            client_key_exchange_data = length_bytes + self.encrypted_pre_master_secret

            client_key_exchange = TLSClientKeyExchange(
                exchkeys=client_key_exchange_data
            )
            self.tls_context.msg = [client_certificate, client_key_exchange] if client_certificate else [client_key_exchange]
            self.send_tls_packet(self.client_ip, self.server_ip, self.client_port, self.server_port)
            logging.info(f"Client Key Exchange sent from {self.client_ip}")

        except Exception as e:
            logging.error(f"Error in client key exchange: {str(e)}")
            raise e

    def handle_master_secret(self)-> None:
    #----------------------------------
    # Extracted Master Secret
    #----------------------------------
        # Before generating the master secret,
        # try to decrypt the pre-master secret with server's private key
        try:
            decrypted_pre_master_secret = decrypt_pre_master_secret(self.encrypted_pre_master_secret, self.server_private_key)
            logging.info(f"Server decrypted pre_master_secret: {decrypted_pre_master_secret.hex()}")
            if compare_to_original(decrypted_pre_master_secret, self.pre_master_secret):
                logging.info("Pre master secret encrypted matches.")
        except Exception as e:
            logging.error(f"Pre-master secret decryption failed: {e}")
            raise ValueError("Pre-master secret does not match") from e
        # Compute master secret
        self.master_secret = self.prf.compute_master_secret(
            self.pre_master_secret,
            self.client_random,
            self.server_random
        )
        print(f"Master secret: {self.master_secret.hex()}")
        # Derive key material
        key_block = self.prf.derive_key_block(
            self.master_secret,
            self.server_random,
            self.client_random,
            2 * (16 + 32 + 16)  # 2 * (key_length + mac_key_length + iv_length)
        )
        self.client_write_key = key_block[:16]
        self.server_write_key = key_block[16:32]
        self.client_write_mac_key = key_block[32:64]
        self.server_write_mac_key = key_block[64:96]
        self.client_write_IV = key_block[96:112]
        self.server_write_IV = key_block[112:128]

        

    def send_client_change_cipher_spec(self)-> None:
    #----------------------------------
    # Client ChangeCipherSpec
    #----------------------------------
        client_verify_data = self.prf.compute_verify_data(
            'client',
            'write',
            b''.join(self.handshake_messages),
            self.master_secret
        )
        client_finished = TLSFinished(vdata=client_verify_data)
        """sent by both the client and the
            server to notify the receiving party that subsequent records will be
            protected under the newly negotiated CipherSpec and keys."""
        self.tls_context.msg = [TLSChangeCipherSpec()]
        self.tls_context.msg = [client_finished]
        self.send_tls_packet(self.client_ip, self.server_ip, self.client_port, self.server_port)
        logging.info(f"Client ChangeCipherSpec and Finished sent from {self.client_ip}")

    def send_server_change_cipher_spec(self):
    #----------------------------------
    # Server ChangeCipherSpec
    #----------------------------------
        # Server Finished
        server_verify_data = self.prf.compute_verify_data(
            'server',
            'write',
            b''.join(self.handshake_messages),
            self.master_secret
        )

        decrypted_pre_master_secret = decrypt_pre_master_secret(self.encrypted_pre_master_secret, self.server_private_key)
        
        logging.info(f"Server decrypted pre_master_secret: {decrypted_pre_master_secret.hex()}")

        finished = TLSFinished(vdata=server_verify_data)
        
        self.tls_context.msg = [TLSChangeCipherSpec()]
        self.tls_context.msg = [finished]
        self.send_tls_packet(self.server_ip, self.client_ip, self.server_port, self.client_port)
        logging.info(f"Server Finished sent to {self.client_ip}")
    def handle_ssl_key_log(self):
    #----------------------------------
    # SSL Key Log
    #----------------------------------
        try:
            # Log SSL key for Wireshark decryption
            log_line = f"CLIENT_RANDOM {self.client_random.hex()} {self.master_secret.hex()}"
            with open(self.pcap_writer.config.SSL_KEYLOG_FILE, "a") as f:
                f.write(log_line + "\n")
            logging.info(f"Logged master secret to {self.pcap_writer.config.SSL_KEYLOG_FILE}: {log_line}")
        except Exception as e:
            logging.error(f"Failed to derive master secret for decryption: {str(e)}")
            raise e
            
        # check if the SSLKEYLOG's master secret is correct
        if verify_master_secret(self.client_random, self.master_secret, self.pcap_writer.config.SSL_KEYLOG_FILE):
            logging.info(f"Derived master_secret: {self.master_secret.hex()}")
        else:
            raise Exception("Master secret verification failed")
            
        
    
    def send_application_data(self, data, is_request):
        is_client = is_request
        key = self.client_write_key if is_client else self.server_write_key
        mac_key = self.client_write_mac_key if is_client else self.server_write_mac_key
        
        iv = os.urandom(16)  # Generate a new IV for each message
        
        # Encrypt the data using CBC mode with HMAC-SHA256 for integrity
        encrypted_data = encrypt_tls12_record_cbc(data, key, iv, mac_key)
        self.encrypted_packets.append(encrypted_data)
        self.original_messages.append(data)
        
        # שמור את המפתח וה-IV
        self.packet_keys.append(key)
        self.packet_ivs.append(iv)
        self.packet_mac_keys.append(mac_key)
        
        # Create a TLS Application Data record
        tls_data = TLSApplicationData(data=encrypted_data)
        self.tls_context.msg = [tls_data]
        
        src_ip = self.client_ip if is_request else self.server_ip
        dst_ip = self.server_ip if is_request else self.client_ip
        sport = self.client_port if is_request else self.server_port
        dport = self.server_port if is_request else self.client_port
        
        # Send the encrypted TLS packet
        self.send_tls_packet(src_ip, dst_ip, sport, dport)

    
    
    def send_unencrypted_data(self, data, is_request):
        src_ip = self.client_ip if is_request else self.server_ip
        dst_ip = self.server_ip if is_request else self.client_ip
        sport = self.client_port if is_request else self.server_port
        dport = self.server_port if is_request else self.client_port
        
        packet = self.pcap_writer.create_tcp_packet(src_ip, dst_ip, sport, dport, data, "PA")
        self.pcap_writer.packets.append(packet)

    def send_tls_packet(self, src_ip, dst_ip, sport, dport):
        packet = self.pcap_writer.create_tls_packet(src_ip, dst_ip, sport, dport, raw(self.tls_context))
        self.pcap_writer.packets.append(packet)
        self.seq_num += len(packet.payload)
        return packet


    def verify_tls_session(self):
        """Verify the TLS session by decrypting each packet and comparing it with the original message."""
        logging.info(f"\nStarting TLS session verification for {self.client_ip}")
        
        for i, (packet, original_message) in enumerate(zip(self.encrypted_packets, self.original_messages)):
            logging.info(f"\nVerifying encrypted packet {i+1}")
            logging.info(f"Original message length: {len(original_message)}")
            logging.info(f"Encrypted packet length: {len(packet)}")
            
            logging.info("Original message:")
            print_message_content(original_message)
            
            try:
                # Get the key and MAC key for the current packet
                key = get_key_for_packet(self.packet_keys, i)
                mac_key = get_mac_key_for_packet(self.packet_mac_keys, i)

                # Decrypt the packet using TLS 1.2 CBC mode
                decrypted = decrypt_tls12_record_cbc(packet, key, mac_key)
                
                # Compare the decrypted message with the original message
                if compare_to_original(decrypted, original_message):
                    logging.info("Decrypted message matches original message")
                    logging.info(f"Decrypted message: {decrypted}")
                else:
                    raise("Decrypted message does not match original message.")
                    
            except ValueError as e:
                logging.error(f"Error processing packet {i+1}: {str(e)}")
        
        logging.info(f"\nTLS session verification complete for {self.client_ip}")
        logging.info(f"Total packets verified: {len(self.encrypted_packets)}")



def main():
#----------------------------------
    config = Config()
    writer = CustomPcapWriter(config)
    # clear the SSL_KEYLOG_FILE
    with open(config.SSL_KEYLOG_FILE, "w") as f:
        pass
    
    #----------
    # Client 1
    #----------
    logging.info("\n--- Client 1 Session ---")
    client1_session = UnifiedTLSSession(writer, config.CLIENT1_IP, config.SERVER_IP, 12345, 443, use_tls=True, use_client_cert=True)
    client1_session.run_session(config.GET_REQUEST, config.OK_RESPONSE, 'ctf_challenge.gif')
    client1_session.verify_tls_session()  # Verify TLS session for Client 1

    #----------
    # Client 2
    #----------
    logging.info("\n--- Client 2 Session ---")
    client2_session = UnifiedTLSSession(writer, config.CLIENT2_IP, config.SERVER_IP, 12346, 443, use_tls=True, use_client_cert=False)
    client2_session.run_session(config.GET_REQUEST, config.BAD_REQUEST)
    #client2_session.verify_tls_session()  # Verify TLS session for Client 2

    writer.save_pcap(config.OUTPUT_PCAP)
    writer.verify_and_log_packets()

    # Optional: Print a summary of the TLS session verifications
    logging.info("\nTLS Session Verification Summary:")
    logging.info(f"Client 1: {len(client1_session.encrypted_packets)} packets verified")
    #logging.info(f"Client 2: {len(client2_session.encrypted_packets)} packets verified")
#----------------------------------
    
if __name__ == "__main__":
    main()