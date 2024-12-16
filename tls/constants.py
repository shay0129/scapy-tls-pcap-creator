"""
Constants for TLS session simulation.
Contains protocol versions, ports, file paths and other configuration values.
"""

from pathlib import Path
from typing import Final
import logging

# Base Directory Configuration
BASE_DIR: Final[Path] = Path(__file__).parent

CERTS_DIR: Final[Path] = BASE_DIR / "certificates" / "certs"
LOGS_DIR: Final[Path] = BASE_DIR / "logs"
OUTPUT_DIR: Final[Path] = BASE_DIR / "output"
DOCUMENTS_DIR: Final[Path] = BASE_DIR / "documents"

# Output file paths
OUTPUT_PCAP: Final[Path] = OUTPUT_DIR / "capture.pcap"
CHALLENGE_FILE: Final[Path] = DOCUMENTS_DIR / "ctf_challenge.gif"

LOG_FILE: Final[str] = "tls_session.log"

# Create required directories
for directory in [CERTS_DIR, LOGS_DIR, OUTPUT_DIR, DOCUMENTS_DIR]:
    directory.mkdir(parents=True, exist_ok=True)

class TLSVersion:
    """TLS protocol versions"""
    TLS_1_2: Final[int] = 0x0303
    TLS_1_1: Final[int] = 0x0302
    TLS_1_0: Final[int] = 0x0301

class TLSRecord:
    """TLS record types and sizes"""
    CHANGE_CIPHER_SPEC: Final[int] = 0x14
    ALERT: Final[int] = 0x15
    HANDSHAKE: Final[int] = 0x16
    APPLICATION_DATA: Final[int] = 0x17
    SESSION_ID_SIZE = 32  # Standard TLS session ID size

    # Record type bytes
    CHANGE_CIPHER_SPEC_BYTES: Final[bytes] = b'\x14'
    ALERT_BYTES: Final[bytes] = b'\x15'
    HANDSHAKE_BYTES: Final[bytes] = b'\x16'
    APPLICATION_DATA_BYTES: Final[bytes] = b'\x17'
    
    # Size limits
    MAX_RECORD_SIZE: Final[int] = 16384  # 16 KB
    MAX_HANDSHAKE_SIZE: Final[int] = 16384
    RECORD_TYPE_APP_DATA = 0x17
class NetworkPorts:
    """Network port configurations"""
    HTTPS: Final[int] = 443
    HTTP: Final[int] = 80
    CLIENT_DEFAULT: Final[int] = 12345
    CLIENT_1: Final[int] = 12345
    CLIENT_2: Final[int] = 54321
    

class NetworkAddresses:
    """Network address configurations"""
    SERVER_IP: Final[str] = "10.0.0.1"
    CLIENT_1_IP: Final[str] = "192.168.1.1"
    CLIENT_2_IP: Final[str] = "192.168.1.2"

class CertificatePaths:
    """Certificate file paths"""
    CA_CERT: Final[Path] = CERTS_DIR / "ca.crt"
    CA_KEY: Final[Path] = CERTS_DIR / "ca.key"
    SERVER_CERT: Final[Path] = CERTS_DIR / "server.crt"
    SERVER_KEY: Final[Path] = CERTS_DIR / "server.key"
    CLIENT_CERT: Final[Path] = CERTS_DIR / "client.crt"
    CLIENT_KEY: Final[Path] = CERTS_DIR / "client.key"

class LoggingPaths:
    """Logging file paths"""
    TLS_LOG: Final[Path] = LOGS_DIR / "tls.log"
    PCAP_LOG: Final[Path] = LOGS_DIR / "pcap.log"
    ERROR_LOG: Final[Path] = LOGS_DIR / "error.log"
    SSL_KEYLOG: Final[Path] = LOGS_DIR / "ssl-keys.log"

class LoggingConfig:
    """Logging configuration"""
    LEVEL: Final[int] = logging.INFO
    FORMAT: Final[str] = '%(asctime)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s'
    MAX_SIZE: Final[int] = 10 * 1024 * 1024  # 10MB
    BACKUP_COUNT: Final[int] = 5
    MAX_BINARY_DISPLAY: Final[int] = 100
    MAX_LINES_DISPLAY: Final[int] = 10

class TCPFlags:
    """TCP flag values"""
    ACK: Final[int] = 0x10
    SYN: Final[int] = 0x02
    FIN: Final[int] = 0x01
    RST: Final[int] = 0x04

class CryptoConstants:
    """Cryptographic constants"""
    AES_128_KEY_LENGTH: Final[int] = 16
    SHA256_MAC_LENGTH: Final[int] = 32
    IV_LENGTH: Final[int] = 16
    MIN_MAC_KEY_SIZE: Final[int] = 32
    SEQ_NUM_SIZE: Final[int] = 8
    SESSION_ID_SIZE: Final[int] = 32
    RSA_KEY_SIZE: Final[int] = 2048
    PRE_MASTER_SECRET_SIZE: Final[int] = 48

class HTTPStatus:
    """HTTP status codes"""
    OK: Final[int] = 200
    BAD_REQUEST: Final[int] = 400

class GeneralConfig:
    """General configuration settings"""
    DEFAULT_SNI: Final[str] = "Pasdaran.local"
    DEFAULT_TIMEOUT: Final[int] = 30
    DEFAULT_MTU: Final[int] = 1500
    MAX_PACKET_SIZE: Final[int] = 65535
    MAX_PACKET_INDEX: Final[int] = 65535


class keys:
    SHA256_MAC_LENGTH, AES_128_KEY_LENGTH, IV_LENGTH = 32, 16, 16

