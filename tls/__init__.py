"""
TLS protocol implementation package.
Provides TLS session handling, protocol simulation, and packet capture capabilities.
"""

from dataclasses import dataclass, field
from typing import Optional
from pathlib import Path
from tls.cipher_suite import CipherSuite, CipherMode, CipherType

from .session import UnifiedTLSSession
from .constants import (
    TLSVersion,
    TLSRecord,
    NetworkPorts,
    NetworkAddresses,
    CertificatePaths,
    LoggingPaths,
    CryptoConstants,
    HTTPStatus
)
from .exceptions import (
    TLSError,
    TLSSessionError,
    ConfigurationError,
    HandshakeError,
    CertificateError,
    CryptoError
)
from .pcap_writer import CustomPcapWriter, PcapWriterConfig
from .config import NetworkConfig
# SessionState dataclass
@dataclass
class SessionState:
    """State information for TLS session"""
    seq_num: int = 0
    client_seq_num: int = 0
    server_seq_num: int = 0
    master_secret: Optional[bytes] = None
    handshake_completed: bool = False
    handshake_messages: list = field(default_factory=list)

__version__ = '1.0.0'
__author__ = 'Your Name'

# Constants
DEFAULT_SNI = "www.ctf-example.org"
DEFAULT_TLS_VERSION = TLSVersion.TLS_1_2

# Export all public classes, functions and constants
__all__ = [
    # Main Classes
    'UnifiedTLSSession',
    'CustomPcapWriter',
    'NetworkConfig',
    'PcapWriterConfig',
    'SessionState',
    'CipherSuite',
    'CipherMode',
    'CipherType',
    
    # Constants Classes
    'TLSVersion',
    'TLSRecord',
    'NetworkPorts',
    'NetworkAddresses',
    'CertificatePaths',
    'LoggingPaths',
    'CryptoConstants',
    'HTTPStatus',

    # Exception Classes
    'TLSError',
    'TLSSessionError',
    'ConfigurationError',
    'HandshakeError',
    'CertificateError',
    'CryptoError',

    # Package Constants
    'DEFAULT_SNI',
    'DEFAULT_TLS_VERSION',
    '__version__',
    '__author__'
]

# Package-level logging configuration
import logging
logging.getLogger(__name__).addHandler(logging.NullHandler())