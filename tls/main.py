"""
Main script for running TLS sessions simulation.
Creates two client sessions - one with certificate and one without.
Captures traffic to PCAP file.

Usage:
python -m tls.main
"""
import logging
import sys
from pathlib import Path
from typing import NoReturn, Generator, Optional
from contextlib import contextmanager

from .packet_storage import PcapWriter, PcapWriterConfig
from .config import NetworkConfig
from .exceptions import TLSSessionError, ConfigurationError
from .session import UnifiedTLSSession
from .constants import (
    NetworkPorts,
    NetworkAddresses,
    CHALLENGE_FILE,
    LoggingPaths
)
from .utils.logging import setup_logging

def exit_with_error(message: str, code: int) -> NoReturn:
    """Exit program with error message and code"""
    logging.error(message)
    sys.exit(code)

@contextmanager
def session_context(
    writer: PcapWriter,
    client_ip: str,
    server_ip: str,
    client_port: int,
    use_client_cert: bool
) -> Generator[UnifiedTLSSession, None, None]:
    """Context manager for TLS session"""
    session = None
    try:
        session = UnifiedTLSSession(
            pcap_writer=writer,
            client_ip=client_ip,
            server_ip=server_ip,
            client_port=client_port,
            server_port=NetworkPorts.HTTPS,
            use_tls=True,
            use_client_cert=use_client_cert
        )
        yield session
    finally:
        if session:
            try:
                session.cleanup()
            except Exception as e:
                logging.error(f"Session cleanup failed: {e}")


def setup_environment(config: NetworkConfig) -> PcapWriter:
    """Setup environment for TLS sessions"""
    try:
        # Construct PcapWriterConfig from config (only valid parameters: log_path, log_level)
        writer_config = PcapWriterConfig(
            log_path=Path(config.log_path) if hasattr(config, 'log_path') else Path("tls_session.log"),
            log_level=getattr(config, 'log_level', logging.INFO)
        )
        writer = PcapWriter(writer_config)
        # Clear SSL keylog file
        if hasattr(config, 'SSL_KEYLOG_FILE'):
            Path(LoggingPaths.SSL_KEYLOG).write_text('')
            logging.info(f"Cleared SSL keylog file: {LoggingPaths.SSL_KEYLOG}")
        return writer
    except Exception as e:
        raise ConfigurationError(f"Environment setup failed: {e}")


def run_client_session(
    writer: PcapWriter,
    client_ip: str,
    server_ip: str,
    client_port: int,
    use_client_cert: bool,
    request: bytes,
    response: bytes,
    challenge_file: Optional[Path] = None
) -> None:
    """Run a single client TLS session"""
    session_type = "certificate" if use_client_cert else "no certificate"
    logging.info(f"\n--- Client Session ({session_type}) ---")
    try:
        with session_context(writer, client_ip, server_ip, client_port, use_client_cert) as session:
            file_to_send = str(challenge_file) if challenge_file and challenge_file.exists() else None
            session.run_session(request, response, file_to_send)
            logging.info(f"Session completed successfully for {client_ip}")
    except Exception as e:
        raise TLSSessionError(f"Session failed for {client_ip}: {e}")


def save_results(writer: PcapWriter, config: NetworkConfig) -> None:
    """Save and verify PCAP results"""
    try:
        writer.save_pcap(str(config.OUTPUT_PCAP))
        writer.verify_and_log_packets()
        logging.info(f"Results saved to {config.OUTPUT_PCAP}")
        
    except Exception as e:
        raise ConfigurationError(f"Failed to save results: {e}")

def main() -> None:
    """Main function to run TLS sessions"""
    try:
        # Load configuration first
        config = NetworkConfig.load()

        # Setup logging using the log_path and log_level from config
        setup_logging(
            log_path=config.log_path, 
            level=config.log_level
        )
        logging.info("Starting TLS session simulation")

        # Setup environment and continue with rest of the code
        writer = setup_environment(config)
        
        # Run Client 1 session (with certificate)
        run_client_session(
            writer=writer,
            client_ip=NetworkAddresses.CLIENT_1_IP,
            server_ip=NetworkAddresses.SERVER_IP,
            client_port=NetworkPorts.CLIENT_DEFAULT,
            use_client_cert=True,
            request=NetworkConfig.GET_REQUEST,
            response=NetworkConfig.OK_RESPONSE,
            challenge_file=CHALLENGE_FILE
        )
        
        # Run Client 2 session (without certificate)
        run_client_session(
            writer=writer,
            client_ip=NetworkAddresses.CLIENT_2_IP,
            server_ip=NetworkAddresses.SERVER_IP,
            client_port=NetworkPorts.CLIENT_DEFAULT + 1,
            use_client_cert=False,
            request=NetworkConfig.GET_REQUEST,
            response=NetworkConfig.BAD_REQUEST
        )
        
        # Save and verify results
        save_results(writer, config)
        
    except ConfigurationError as e:
        exit_with_error(f"Configuration error: {e}", 1)
    except TLSSessionError as e:
        exit_with_error(f"Session error: {e}", 2)
    except Exception as e:
        exit_with_error(f"Unexpected error: {e}", 3)
    else:
        logging.info("TLS session simulation completed successfully")
    finally:
        logging.shutdown()

if __name__ == "__main__":
    main()