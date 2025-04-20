"""
TLS protocol implementation package.
Provides TLS session handling, protocol simulation, and packet capture capabilities.
"""
from .session_state import SessionState
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
    CryptoError,
    StorageError,
    PcapWriteError,
    ValidationError,
    TLSValidationError,
    MasterSecretError
)
from .packet_storage import PcapWriter, PcapWriterConfig
from .config import NetworkConfig
from .packet_validator import PacketValidator, PacketStats

__version__ = '1.0.0'
__author__ = 'Shay Mordechai'

# Constants
DEFAULT_SNI = "www.ctf-example.org"
DEFAULT_TLS_VERSION = TLSVersion.TLS_1_2

# Export all public classes, functions and constants
__all__ = [
    # Session State Classes
    'SessionState',

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
    'StorageError',
    'PcapWriteError',
    'ValidationError',
    'TLSValidationError',
    'MasterSecretError'

    # Main Classes
    'PcapWriter',
    'NetworkConfig',
    'PcapWriterConfig',
    'PacketValidator',
    'PacketStats',    

    # Package Constants
    'DEFAULT_SNI',
    'DEFAULT_TLS_VERSION',
    '__version__',
    '__author__'
]

# Package-level logging configuration
import logging
logging.getLogger(__name__).addHandler(logging.NullHandler())