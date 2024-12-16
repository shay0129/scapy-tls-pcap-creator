"""
Network Configuration Constants
Contains all network-related configuration including IP addresses,
HTTP requests/responses and file paths.
"""

from dataclasses import dataclass, field
from typing import Final, ClassVar
from pathlib import Path
import ipaddress
import logging
from enum import Enum
from tls.constants import LoggingPaths

from tls.constants import LoggingConfig

class HttpContentType(str, Enum):
    """HTTP Content Types"""
    TEXT_PLAIN = "text/plain"
    APPLICATION_JSON = "application/json"
    IMAGE_GIF = "image/gif"

class ConfigError(Exception):
    """Base exception for configuration errors"""
    pass

class PathValidationError(ConfigError):
    """Raised when path validation fails"""
    pass

class IpValidationError(ConfigError):
    """Raised when IP validation fails"""
    pass

@dataclass(frozen=True)
class NetworkConfig:
    # Network addresses as class variables
    SERVER_IP: ClassVar[str] = '10.0.0.1'
    CLIENT1_IP: ClassVar[str] = '192.168.1.1'
    CLIENT2_IP: ClassVar[str] = '192.168.1.2'
    
    # File paths with validation on initialization
    output_pcap: Path = field(default=Path("path/to/output.pcap"))
    ssl_keylog_file: Path = field(default=LoggingPaths.SSL_KEYLOG)
    log_path: Path = field(default=Path("../logs/tls_session.log"))
    log_level: int = field(default=LoggingConfig.LEVEL)

    output_pcap: Path = field(default=Path("path/to/output.pcap"))
    OUTPUT_PCAP: str = field(default="path/to/output.pcap")

    # HTTP Messages
    GET_REQUEST: ClassVar[bytes] = (
        b"GET /resource HTTP/1.1\r\n"
        b"Host: server.local\r\n"
        b"User-Agent: Custom-Client/1.0\r\n"
        b"Connection: close\r\n"
        b"\r\n"
    )
    
    OK_RESPONSE: ClassVar[bytes] = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: text/plain\r\n"
        b"Content-Length: 13\r\n"
        b"\r\n"
        b"Hello, world!"
    )
    
    BAD_REQUEST: ClassVar[bytes] = (
        b"HTTP/1.1 400 Bad Request\r\n"
        b"Content-Type: text/plain\r\n"
        b"Content-Length: 11\r\n"
        b"\r\n"
        b"Bad Request"
    )

    def __post_init__(self) -> None:
        """Validate configuration after initialization"""
        self._validate_ip_addresses()
        self._validate_and_create_paths()
        self._validate_http_messages()

    @classmethod
    def create_with_paths(cls, output_pcap: Path, ssl_keylog_file: Path) -> 'NetworkConfig':
        """Create configuration with custom file paths"""
        return cls(
            output_pcap=output_pcap,
            ssl_keylog_file=ssl_keylog_file
        )

    @classmethod
    def load(cls) -> 'NetworkConfig':
        """
        Load default network configuration.
        
        Returns:
            NetworkConfig: Configured network settings with default paths
        """
        base_dir = Path(__file__).parent.parent
        default_output_pcap = base_dir / "output" / "capture.pcap"
        default_ssl_keylog = LoggingPaths.SSL_KEYLOG
        default_log_path = base_dir / "logs" / "tls_session.log"
        
        # Ensure directories exist
        default_output_pcap.parent.mkdir(parents=True, exist_ok=True)
        default_ssl_keylog.parent.mkdir(parents=True, exist_ok=True)
        default_log_path.parent.mkdir(parents=True, exist_ok=True)
        
        return cls(
            output_pcap=default_output_pcap,
            ssl_keylog_file=default_ssl_keylog,
            log_path=default_log_path
        )
    
    def _validate_ip_addresses(self) -> None:
        """Validate IP address format"""
        try:
            for ip in [self.SERVER_IP, self.CLIENT1_IP, self.CLIENT2_IP]:
                ipaddress.ip_address(ip)
        except ValueError as e:
            raise IpValidationError(f"Invalid IP address: {e}")

    def _validate_and_create_paths(self) -> None:
        """Validate and create necessary directories"""
        try:
            for path in [self.output_pcap, self.ssl_keylog_file]:
                path.parent.mkdir(parents=True, exist_ok=True)
                if not path.parent.exists():
                    raise PathValidationError(f"Failed to create directory for {path}")
        except Exception as e:
            raise PathValidationError(f"Path validation failed: {e}")

    def _validate_http_messages(self) -> None:
        """Validate HTTP message format and content lengths"""
        try:
            self._validate_http_message(self.OK_RESPONSE, 200)
            self._validate_http_message(self.BAD_REQUEST, 400)
            self._validate_request_format(self.GET_REQUEST)
        except ValueError as e:
            logging.warning(f"HTTP message validation warning: {e}")

    @staticmethod
    def _validate_http_message(message: bytes, expected_status: int) -> None:
        """Validate a single HTTP message"""
        try:
            # Decode and split headers from body
            headers, body = message.split(b"\r\n\r\n", 1)
            headers = headers.decode('utf-8')
            
            # Validate status line
            status_line = headers.split('\r\n')[0]
            if str(expected_status) not in status_line:
                raise ValueError(f"Invalid status code in {status_line}")
            
            # Validate Content-Length
            for header in headers.split('\r\n'):
                if header.lower().startswith('content-length:'):
                    declared_length = int(header.split(':')[1].strip())
                    actual_length = len(body)
                    if declared_length != actual_length:
                        raise ValueError(
                            f"Content-Length mismatch: declared {declared_length}, "
                            f"actual {actual_length}"
                        )
                    break
            
        except Exception as e:
            raise ValueError(f"HTTP message validation failed: {e}")

    @staticmethod
    def _validate_request_format(request: bytes) -> None:
        """Validate HTTP request format"""
        try:
            # Decode and validate request line
            request_line = request.split(b"\r\n")[0].decode('utf-8')
            method, path, protocol = request_line.split()
            
            if method != "GET":
                raise ValueError(f"Invalid HTTP method: {method}")
            if not protocol.startswith("HTTP/"):
                raise ValueError(f"Invalid protocol: {protocol}")
            
            # Validate required headers
            headers = request.split(b"\r\n\r\n")[0].decode('utf-8')
            if "Host:" not in headers:
                raise ValueError("Missing Host header")
            
        except Exception as e:
            raise ValueError(f"Request validation failed: {e}")

    def get_paths_dict(self) -> dict:
        """Get a dictionary of all file paths"""
        return {
            'output_pcap': self.output_pcap,
            'ssl_keylog_file': self.ssl_keylog_file
        }

    def validate_all(self) -> bool:
        """
        Validate entire configuration.
        Returns True if valid, False otherwise.
        """
        try:
            self._validate_ip_addresses()
            self._validate_and_create_paths()
            self._validate_http_messages()
            return True
        except Exception as e:
            logging.error(f"Configuration validation failed: {e}")
            return False