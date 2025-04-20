"""
Network Configuration Constants
Contains all network-related configuration including IP addresses,
HTTP requests/responses and file paths.
"""
from dataclasses import dataclass
from typing import ClassVar
from pathlib import Path
import ipaddress

from .constants import LoggingPaths, LoggingConfig

@dataclass
class NetworkConfig:
    # IP Addresses (Constants)
    SERVER_IP: ClassVar[str] = '10.0.0.1'
    CLIENT1_IP: ClassVar[str] = '192.168.1.1'
    CLIENT2_IP: ClassVar[str] = '192.168.1.2'
    
    # File paths (Variables)
    output_pcap: Path
    ssl_keylog_file: Path
    log_path: Path
    log_level: int = LoggingConfig.LEVEL
    
    # HTTP Messages (CONSTANTS)
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

    @classmethod
    def load(cls) -> 'NetworkConfig':
        """Load default network configuration"""
        base_dir = Path(__file__).parent
        return cls(
            output_pcap=base_dir / "output" / "capture.pcap",
            ssl_keylog_file=LoggingPaths.SSL_KEYLOG,
            log_path=base_dir / "logs" / "tls_session.log"
        )

    def __post_init__(self) -> None:
        """Validate and create paths after initialization"""
        # Create directories
        for path in [self.output_pcap, self.ssl_keylog_file, self.log_path]:
            path.parent.mkdir(parents=True, exist_ok=True)
            
        # Validate IP addresses
        for ip in [self.SERVER_IP, self.CLIENT1_IP, self.CLIENT2_IP]:
            try:
                ipaddress.ip_address(ip)
            except ValueError as e:
                raise ValueError(f"Invalid IP address {ip}: {e}")
            
    @property
    def OUTPUT_PCAP(self) -> Path:
        """For backward compatibility"""
        return self.output_pcap