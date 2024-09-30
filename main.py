# main.py
import logging
from tls_session import UnifiedTLSSession
from pcap_writer import CustomPcapWriter
from config import Config
from crypto import *
from utils import *
from tls_utils import *

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