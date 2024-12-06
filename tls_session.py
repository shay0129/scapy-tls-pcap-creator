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
    """
    Simulates a TLS session between a client and server, including the
    handshake and application data exchange.
    """
    def __init__(self, pcap_writer, client_ip, server_ip, client_port, server_port, use_tls=True, use_client_cert=False):
        
        # Packet capture writer (PCAP) for saving packets
        self.pcap_writer = pcap_writer

        # Network configuration
        self.client_ip = client_ip
        self.server_ip = server_ip
        self.client_port = client_port
        self.server_port = server_port

        # Default server name for TLS Server Name Indication (SNI)
        self.server_name = "server"
        
        # Ports for secure and non-secure communication
        self.https_port = 443
        self.http_port = 80

        # TLS configuration
        self.use_tls = use_tls
        self.use_client_cert = use_client_cert

        # Create a TLS context for the session (TLS 1.2 in this case)
        self.tls_context = TLS(version=0x0303)

        # Load certificates and set up the Certificate Authority (CA) chain
        self.setup_certificates()
        
        # Sequence numbers for TLS session (general, client, server)
        self.seq_num = 0
        self.client_seq_num = 0
        self.server_seq_num = 0 
        
        # Master secret used in key generation (to be derived during handshake)
        self.master_secret = None

        # TLS handshake parameters
        self.handshake_completed = False
        self.handshake_messages = []

        # Pseudo-Random Function (PRF) configuration for TLS key generation
        self.prf = PRF(hash_name='SHA256', tls_version=0x0303)

    
    def verify_certificate_chain(self, chain):
        """Verify a simple certificate chain"""
        if len(chain) != 2:  # Server cert and root CA
            return False
        
        server_cert = chain[0]
        root_ca = chain[1]
        
        try:
            # Check if root CA is the issuer of server cert
            if server_cert.issuer != root_ca.subject:
                logging.warning("Server certificate not issued by provided CA")
                logging.warning(f"Server cert issuer: {server_cert.issuer}")
                logging.warning(f"Root CA subject: {root_ca.subject}")
                return False
                
            # Verify server cert signature
            root_public_key = root_ca.public_key()
            root_public_key.verify(
                server_cert.signature,
                server_cert.tbs_certificate_bytes,
                asymmetric_padding.PKCS1v15(),
                server_cert.signature_hash_algorithm
            )
            logging.info("Certificate chain verification successful")
            return True
            
        except Exception as e:
            logging.error(f"Certificate signature verification failed: {e}")
            return False

    def verify_server_public_key(self):
        """Verify the server's public key matches the one in the certificate"""
        try:
            # Extract public key from certificate
            cert_public_key = self.server_cert.public_key()
            cert_numbers = cert_public_key.public_numbers()
            
            # Get numbers from loaded public key
            loaded_numbers = self.server_public_key.public_numbers()
            
            # Compare modulus (n) and public exponent (e)
            keys_match = (
                cert_numbers.n == loaded_numbers.n and 
                cert_numbers.e == loaded_numbers.e
            )
            
            if keys_match:
                logging.info("Server public key matches certificate")
                logging.info(f"Modulus (n): {hex(cert_numbers.n)}")
                logging.info(f"Public exponent (e): {hex(cert_numbers.e)}")
            else:
                raise ValueError("Server public key does not match certificate")
                
            return keys_match
            
        except Exception as e:
            logging.error(f"Public key verification failed: {e}")
            raise

    def setup_certificates(self):
        """Setup certificate chain and server credentials"""
        try:
            # Load the root CA
            self.ca_cert = load_cert("../certificates/guards-ca.crt")
            
            # Load server certificate and keys (only once!)
            self.server_cert, self.server_private_key, self.server_public_key = load_server_cert_keys(
                cert_path="../certificates/server.der", 
                key_path="../certificates/server.key"
            )
            """
            -----BEGIN PUBLIC KEY-----
            MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAr+2v5nIDcUdr9GCOGfZO
            Sx2NHKsj24prLap2jZWjo0dOc6UhIRLKnJ/KxUuPpJFagez54ASwE2mzLbmGlWvS
            ICgaoZbc5RlqILK9cS/jhrmn2CwdT3cVImOQPOQZb29sAstWIMuyZ5i9rqXbegDA
            Ggxh6iyfHnlGOSka/4HF4JPKhhxaxfeSWtW1aQiphiiktDRZeH2JPujA2J3r1n9/
            If5sddB9pelJywF+UXQqHmY3icuSDAyy6gG59Xj/LbOgzEq58Canrsp5sWMDLLaw
            ug0zvcq50+bMt49gQSPsTc5c+X86YzLPCertrbepLjaIkNgtsWeVlWWq6WPBj6MO
            jQIDAQAB
            -----END PUBLIC KEY-----
            """
            # Build chain with just root CA and server cert
            self.cert_chain = [
                self.server_cert,
                self.ca_cert
            ]
            
            self.verify_server_public_key()

            # Verify the chain
            if not self.verify_certificate_chain(self.cert_chain):
                logging.warning("Certificate chain verification failed")
                logging.warning(f"Server cert issuer: {self.server_cert.issuer}")
                logging.warning(f"CA cert subject: {self.ca_cert.subject}")
            else:
                logging.info("Certificate chain verification passed")
                
            logging.info("Certificate chain loaded successfully")
            logging.info(f"Server cert subject: {self.server_cert.subject}")
            logging.info(f"Server public key: {self.server_public_key.public_numbers().n}")
            logging.info(f"CA cert subject: {self.ca_cert.subject}")
            
        except Exception as e:
            logging.error(f"Failed to setup certificates: {e}")
            raise


    def perform_handshake(self)-> None:
        """
        Executes the TLS handshake process according to RFC 5246.
        """
        try:
            # Step 1: Client Hello
            self.send_client_hello()
            
            # Step 2: Server Hello, Certificate, Certificate Request, (ServerKeyExchange if needed), ServerHelloDone
            self.send_server_hello()
            
            # Step 3: (Client Certificate if needed), Client (RSA) Key Exchange
            self.send_client_key_exchange()
            
            # Step 4: Generate Master Secret
            self.handle_master_secret()
            
            # Step 5: Client ChangeCipherSpec and Finished
            self.send_client_change_cipher_spec()
            
            # Step 6: Server ChangeCipherSpec and Finished
            self.send_server_change_cipher_spec()
            
            # Log SSL keys for Wireshark
            self.handle_ssl_key_log()
            
            logging.info("TLS Handshake completed successfully")

            return True
        except Exception as e:
            logging.error(f"TLS Handshake failed: {str(e)}")
            raise e
    
    def run_session(self, request_data, response_data, file_to_send=None):
        """
        Runs a complete client-server session.

        Args:
            request_data: The data to be sent in the client's request.
            response_data: The data to be sent in the server's response.
            file_to_send: Optional; the path to a file that the server
                          should send to the client.
        """
        if self.use_tls:
            # use port 443
            self.server_port = self.https_port
            
            self.handshake_completed = self.perform_handshake()
            if not self.handshake_completed:
                logging.error("TLS Handshake failed. Closing session.")
                return
        
        else:
            # use port 80
            self.server_port = self.http_port
        
        if self.handshake_completed and self.use_client_cert:
            # Encrypted HTTP communication for client1 (after TLS handshake)
            # Client1 sends a GET request and receives a GIF file
            self.encrypt_and_send_application_data(request_data, is_request=True)
            # Server sends a GIF file in response
            self.encrypt_and_send_application_data(response_data, is_request=False)
            if file_to_send:
                try:
                    with open(file_to_send, 'rb') as file:
                        file_data = file.read()
                        self.encrypt_and_send_application_data(file_data, is_request=False)
                except FileNotFoundError:
                    logging.error(f"File {file_to_send} not found.")
                except IOError as e:
                    logging.error(f"Error reading file {file_to_send}: {e}")

            logging.info("TLS Handshake completed. Encrypted communication initiated.")

        else:
            # Unencrypted HTTP communication for client2
            self.send_unencrypted_data(request_data, is_request=True)
            self.send_unencrypted_data(response_data, is_request=False)
            logging.warning("TLS Handshake failed or client certificate missing. Proceeding with unencrypted communication.")

    def send_to_client(self, packet) -> None:
        """
        Simulates sending a packet to the client.
        Adds logging for tracking packet flows.
        """
        try:
            # Add packet transmission logic here (e.g., send over a socket)
            logging.info(f"Sending packet to client: {type(packet).__name__}")
        except Exception as e:
            logging.error(f"Failed to send packet to client: {str(e)}")
            raise

    def send_to_server(self, packet) -> None:
        """
        Simulates sending a packet to the server.
        Adds logging for tracking packet flows.
        """
        try:
            # Add packet transmission logic here (e.g., send over a socket)
            logging.info(f"Sending packet to server: {type(packet).__name__}")
        except Exception as e:
            logging.error(f"Failed to send packet to server: {str(e)}")
            raise

    def send_client_hello(self) -> bytes:
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

        # Send ClientHello to the server
        self.send_to_server(client_hello)

        # Track handshake message
        raw_hello = raw(client_hello)
        self.handshake_messages.append(raw_hello)
        
        self.tls_context.msg = [client_hello]
        logging.info(f"Client Hello sent from {self.client_ip}")
        return self.send_tls_packet(
            self.client_ip, self.server_ip, self.client_port, self.server_port, is_handshake=True
        )
    
    def send_server_hello(self) -> bytes:
    #----------------------------------
    # Server Hello
    #----------------------------------
        
        # Generate a Server Random
        self.server_GMT_unix_time, self.server_random_bytes = generate_random()
        self.server_random = self.server_GMT_unix_time.to_bytes(4, 'big') + self.server_random_bytes
        logging.info(f"Generated server_random: {self.server_random.hex()}")

        server_hello = TLSServerHello(
            version=0x0303,  # TLS 1.2
            gmt_unix_time=self.server_GMT_unix_time,
            random_bytes=self.server_random_bytes,
            sid = os.urandom(32),
            cipher=TLS_RSA_WITH_AES_128_CBC_SHA256.val,
            ext=[
                #TLS_Ext_ServerName(servernames=[ServerName(servername="Pasdaran.local")]), # need fix this extantion
                #TLS_Ext_SupportedGroups(groups=['secp256r1', 'x25519']), # relevant for ECDHE key exchange
                TLS_Ext_SignatureAlgorithms(sig_algs=['sha256+rsaepss']),
                TLS_Ext_ExtendedMasterSecret(),
                TLS_Ext_EncryptThenMAC()
                ]
            )
        
         # ECDH key exchange
        """server_key_exchange = TLSServerKeyExchange(
            params=ServerDHParams( #public server key, for play with it ECDH key exchange
                dh_p=self.server_public_key.public_numbers().n.to_bytes((self.server_public_key.public_numbers().n.bit_length() + 7) // 8, byteorder='big'),
                dh_g=self.server_public_key.public_numbers().e.to_bytes((self.server_public_key.public_numbers().e.bit_length() + 7) // 8, byteorder='big'),
                dh_Ys=self.server_public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo),
            ),
        )"""     
        
        # Build certificate chain
        cert_entries = []
        for cert in self.cert_chain:
            cert_der = cert.public_bytes(serialization.Encoding.DER)
            cert_entries.append((len(cert_der), cert_der))
        
        certificate = TLSCertificate(certs=cert_entries)

        # Check if the server public key matches the certificate
        server_cert = x509.load_der_x509_certificate(cert_entries[0][1])  # Load server cert
        cert_public_key = server_cert.public_key()
        if cert_public_key.public_numbers() != self.server_public_key.public_numbers():
            raise ValueError("Server public key mismatch!")
        
        # Get Distinguished Name (DN) from the CA certificate
        ca_dn = self.ca_cert.subject.public_bytes()
        
        cert_request = TLSCertificateRequest(
            ctypes=[1],  # RSA certificate type
            sig_algs=[0x0401],  # SHA256 + RSA
            certauth=[
                (len(ca_dn), ca_dn)  # Use only the Distinguished Name
            ]
        )
        # Send messages to the client
        self.send_to_client(server_hello)
        self.send_to_client(certificate)
        self.send_to_client(cert_request)
        self.send_to_client(TLSServerHelloDone())

        # Track handshake messages
        self.handshake_messages.extend([
            raw(server_hello),
            raw(certificate),
            raw(cert_request)
        ])
        
        self.tls_context.msg = [server_hello, certificate, cert_request ,TLSServerHelloDone()]
        return self.send_tls_packet(
            self.server_ip, self.client_ip, self.server_port, self.client_port, is_handshake=True
        )


    def send_client_key_exchange(self) -> bytes:
        """
        Handles the client key exchange during the TLS handshake.
        """
        try:
            # Initialize client_certificate to None to handle cases where it's not required
            client_certificate = None

            #----------------------------------
            # Client Certificate (if required)
            #----------------------------------
            if self.use_client_cert:
                cert = load_cert("../certificates/client.crt")
                cert_der = cert.public_bytes(serialization.Encoding.DER)
                client_certificate = TLSCertificate(certs=[(len(cert_der), cert_der)])
                # Track the certificate message
                self.handshake_messages.append(raw(client_certificate))
                logging.info("Client certificate prepared.")

            #----------------------------------
            # Client (RSA) Key Exchange
            #----------------------------------
            self.pre_master_secret = generate_pre_master_secret()
            self.encrypted_pre_master_secret = encrypt_pre_master_secret(
                self.pre_master_secret,
                self.server_public_key
            )

            if not isinstance(self.encrypted_pre_master_secret, bytes):
                self.encrypted_pre_master_secret = bytes(self.encrypted_pre_master_secret)

            logging.info(f"Encrypted pre_master_secret length: {len(self.encrypted_pre_master_secret)}")

            # Prepare key exchange message
            length_bytes = len(self.encrypted_pre_master_secret).to_bytes(2, 'big')
            client_key_exchange = TLSClientKeyExchange(
                exchkeys=length_bytes + self.encrypted_pre_master_secret
            )

            # Send the client certificate (if required) and the key exchange
            if client_certificate:
                self.send_to_server(client_certificate)
                logging.info("Client certificate sent to server.")

            self.send_to_server(client_key_exchange)
            logging.info("Client Key Exchange sent to server.")

            # Track the key exchange message
            self.handshake_messages.append(raw(client_key_exchange))

            # Update TLS context
            if client_certificate:
                self.tls_context.msg = [client_certificate, client_key_exchange]
            else:
                self.tls_context.msg = [client_key_exchange]

            # Send packet
            return self.send_tls_packet(
                self.client_ip,
                self.server_ip,
                self.client_port,
                self.server_port,
                is_handshake=True
            )

        except Exception as e:
            logging.error(f"Error in client key exchange: {e}")
            raise


    def handle_master_secret(self)-> None:
    #----------------------------------
    # Extracted Master Secret
    #----------------------------------

        try:
            # Step 1: Decrypt Pre-Master Secret
            decrypted_pre_master_secret = decrypt_pre_master_secret(self.encrypted_pre_master_secret, self.server_private_key)
            logging.info(f"Server decrypted pre_master_secret: {decrypted_pre_master_secret.hex()}")
            
            # Step 2: Validate Pre-Master Secret
            if compare_to_original(decrypted_pre_master_secret, self.pre_master_secret):
                logging.info("Pre master secret encrypted matches.")

        except Exception as e:
            logging.error(f"Pre-master secret decryption failed: {e}")
            raise ValueError("Pre-master secret does not match") from e
        
        # Step 3: Compute Master Secret using PRF
        self.master_secret = self.prf.compute_master_secret(
            self.pre_master_secret,
            self.client_random,
            self.server_random
        )
        print(f"Master secret: {self.master_secret.hex()}")
        logging.info(f"Master secret: {self.master_secret.hex()}")
        

    def send_client_change_cipher_spec(self)-> bytes:
    #----------------------------------
    # Client ChangeCipherSpec
    #----------------------------------
        """
        Sends the Client ChangeCipherSpec and Finished messages to the server.
        Returns the raw packets sent.
        """
        try:
            # Compute the client verify data for the Finished message
            client_verify_data = self.prf.compute_verify_data(
                'client',
                'write',
                b''.join(self.handshake_messages),
                self.master_secret
            )

            # Create TLSFinished and ChangeCipherSpec messages
            client_finished = TLSFinished(vdata=client_verify_data)
            change_cipher_spec = TLSChangeCipherSpec()
            self.send_to_server(client_finished)
            self.send_to_server(change_cipher_spec)

            # Add messages to context and handshake history
            self.handshake_messages.append(raw(client_finished))
            self.handshake_messages.append(raw(change_cipher_spec))
            self.tls_context.msg = [change_cipher_spec, client_finished]

            # Send packets and return raw TLS packet
            logging.info("Client ChangeCipherSpec and Finished messages sent.")
            return self.send_tls_packet(
                self.client_ip,
                self.server_ip,
                self.client_port,
                self.server_port,
                is_handshake=True
            )
        except Exception as e:
            logging.error(f"Error in Client ChangeCipherSpec: {e}")
            raise


    def send_server_change_cipher_spec(self) -> bytes:
    #----------------------------------
    # Server ChangeCipherSpec
    #----------------------------------
        """
        Sends the Server ChangeCipherSpec and Finished messages to the client.
        Returns the raw packets sent.
        """
        try:
            # Compute the server verify data for the Finished message
            server_verify_data = self.prf.compute_verify_data(
                'server',
                'write',
                b''.join(self.handshake_messages),
                self.master_secret
            )

            # Decrypt pre-master secret for validation (optional)
            decrypted_pre_master_secret = decrypt_pre_master_secret(
                self.encrypted_pre_master_secret,
                self.server_private_key
            )
            logging.debug(f"Decrypted pre-master secret: {decrypted_pre_master_secret.hex()}")

            # Create TLSFinished and ChangeCipherSpec messages
            server_finished = TLSFinished(vdata=server_verify_data)
            change_cipher_spec = TLSChangeCipherSpec()

            self.send_to_client(server_finished)
            self.send_to_client(change_cipher_spec)

            # Add messages to context and handshake history
            self.handshake_messages.append(raw(server_finished))
            self.handshake_messages.append(raw(change_cipher_spec))
            self.tls_context.msg = [change_cipher_spec, server_finished]

            # Send packets and return raw TLS packet
            logging.info("Server ChangeCipherSpec and Finished messages sent.")
            return self.send_tls_packet(
                self.server_ip,
                self.client_ip,
                self.server_port,
                self.client_port,
                is_handshake=True
            )
        except Exception as e:
            logging.error(f"Error in Server ChangeCipherSpec: {e}")
            raise

    def handle_ssl_key_log(self) -> None:
    #----------------------------------
    # SSL Key Log
    #----------------------------------
        """Write keys in correct format for Wireshark"""
        try:
            with open(self.pcap_writer.config.SSL_KEYLOG_FILE, "a") as f:
                # Log master secret with client random
                f.write(f"CLIENT_RANDOM {self.client_random.hex()} {self.master_secret.hex()}\n")
                
            logging.info(f"SSL keys logged successfully to {self.pcap_writer.config.SSL_KEYLOG_FILE}")
                
        except Exception as e:
            logging.error(f"Failed to log SSL keys: {e}")
            raise

            
    def encrypt_and_send_application_data(self, data, is_request) -> bytes:
        """
        Encrypts and sends TLS application data by RFC 5246.
        """
        try:
            # Determine client or server context
            is_client = is_request
            key_block = self.prf.derive_key_block(
                self.master_secret,
                self.server_random,
                self.client_random,
                2 * (16 + 32)  # 2 * (key_length + mac_key_length)
            )
            
            # Extract keys and IV
            client_mac_key = key_block[0:32]
            server_mac_key = key_block[32:64]
            client_key = key_block[64:80]
            server_key = key_block[80:96]
            
            key = client_key if is_client else server_key
            mac_key = client_mac_key if is_client else server_mac_key
            explicit_iv = os.urandom(16)
            
            # Generate sequence number
            seq_num = self.client_seq_num if is_client else self.server_seq_num
            seq_num_bytes = seq_num.to_bytes(8, byteorder='big')
            
            # Encrypt data
            encrypted_data = encrypt_tls12_record_cbc(data, key, explicit_iv, mac_key, seq_num_bytes)
            tls_record = explicit_iv + encrypted_data
            
            # Construct the TLS Application Data message
            tls_data = TLSApplicationData(data=tls_record)
            self.tls_context.msg = [tls_data]
            
            # Update sequence numbers
            if is_client:
                self.client_seq_num += 1
            else:
                self.server_seq_num += 1
            
            # Determine source and destination
            src_ip = self.client_ip if is_request else self.server_ip
            dst_ip = self.server_ip if is_request else self.client_ip
            sport = self.client_port if is_request else self.server_port
            dport = self.server_port if is_request else self.client_port
            
            # Send the packet
            raw_packet = self.send_tls_packet(src_ip, dst_ip, sport, dport)
            
            # Log and return raw packet
            logging.info(f"TLS Application Data sent from {src_ip}:{sport} to {dst_ip}:{dport}")
            return raw(tls_data)
        except Exception as e:
            logging.error(f"Error in encrypt_and_send_application_data: {e}")
            raise

    
    
    def send_unencrypted_data(self, data, is_request):
        """Send unencrypted HTTP data with proper Content-Length handling"""
        # Convert data to string if it's bytes
        data_str = data.decode('utf-8') if isinstance(data, bytes) else data
        
        # If this is a response, ensure Content-Length header is correct
        if not is_request:
            try:
                # Split headers and body
                if '\r\n\r\n' in data_str:
                    headers, body = data_str.split('\r\n\r\n', 1)
                    header_lines = headers.split('\r\n')
                    
                    # Calculate actual content length
                    body_length = len(body.encode('utf-8'))
                    
                    # Update or add Content-Length header
                    content_length_found = False
                    new_headers = []
                    
                    for line in header_lines:
                        if line.lower().startswith('content-length:'):
                            new_headers.append(f'Content-Length: {body_length}')
                            content_length_found = True
                        else:
                            new_headers.append(line)
                    
                    if not content_length_found:
                        new_headers.append(f'Content-Length: {body_length}')
                    
                    # Reconstruct the response with correct Content-Length
                    data_str = '\r\n'.join(new_headers) + '\r\n\r\n' + body
                    
                    # Convert back to bytes
                    data = data_str.encode('utf-8')
                else:
                    # If no body separator found, treat entire content as body
                    body_length = len(data_str.encode('utf-8'))
                    data = f"HTTP/1.1 200 OK\r\nContent-Length: {body_length}\r\n\r\n{data_str}".encode('utf-8')
                    
            except Exception as e:
                logging.error(f"Error processing HTTP response: {e}")
                # If any error occurs, ensure we have valid HTTP format
                data = f"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 21\r\n\r\nInternal Server Error".encode('utf-8')
        
        src_ip = self.client_ip if is_request else self.server_ip
        dst_ip = self.server_ip if is_request else self.client_ip
        # http port
        sport = self.client_port if is_request else self.http_port
        dport = self.http_port if is_request else self.client_port
        
        packet = self.pcap_writer.create_tcp_packet(src_ip, dst_ip, sport, dport, data, "PA")
        self.pcap_writer.packets.append(packet)

    def send_tls_packet(self, src_ip, dst_ip, sport, dport, is_handshake=False):
        """Send TLS packet with proper sequence tracking"""
        tls_data = raw(self.tls_context)
        
        # Update sequence number based on direction
        if src_ip == self.client_ip:
            seq_num = self.client_seq_num
            self.client_seq_num += len(tls_data)
        else:
            seq_num = self.server_seq_num
            self.server_seq_num += len(tls_data)
        
        packet = self.pcap_writer.create_tls_packet(
            src_ip=src_ip,
            dst_ip=dst_ip,
            sport=sport,
            dport=dport,
            tls_data=tls_data,
            seq_num=seq_num,
            is_handshake=is_handshake
        )
        
        self.pcap_writer.packets.append(packet)
        return packet



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

    #----------
    # Client 2
    #----------
    logging.info("\n--- Client 2 Session ---")
    client2_session = UnifiedTLSSession(writer, config.CLIENT2_IP, config.SERVER_IP, 12346, 443, use_tls=True, use_client_cert=False)
    client2_session.run_session(config.GET_REQUEST, config.BAD_REQUEST)

    writer.save_pcap(config.OUTPUT_PCAP)
    writer.verify_and_log_packets()

    # Optional: Print a summary of the TLS session verifications
    logging.info("\nTLS Session Verification Summary:")
    logging.info(f"Client 1: {len(client1_session.encrypted_packets)} packets verified")
    #logging.info(f"Client 2: {len(client2_session.encrypted_packets)} packets verified")
#----------------------------------
    
if __name__ == "__main__":
    main()